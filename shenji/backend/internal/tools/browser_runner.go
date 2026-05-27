package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"shenji/backend/internal/runner"
	"shenji/backend/internal/safety"
)

// BrowserRunnerTool provides browser automation capabilities via Playwright in a Docker container.
// Supports: open page, login, save session, capture XHR/fetch, extract frontend routes,
// screenshot, read-only DOM inspection, record cookie/localStorage/sessionStorage.
type BrowserRunnerTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type browserRunnerInput struct {
	TaskID  uint   `json:"taskId"`
	Target  string `json:"target"`
	Action  string `json:"action"` // visit / login / capture_xhr / extract_js / screenshot / dom_inspect
	URL     string `json:"url"`
	Script  string `json:"script"` // optional playwright script snippet
	Credentials map[string]string `json:"credentials"` // username/password for login action
}

type BrowserResult struct {
	Action       string   `json:"action"`
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	Cookies      []string `json:"cookies"`
	LocalStorage []string `json:"local_storage"`
	XHRRequests  []string `json:"xhr_requests"`
	JSFiles      []string `json:"js_files"`
	FrontendRoutes []string `json:"frontend_routes"`
	Screenshots  []string `json:"screenshots"`
	DOMSummary   string   `json:"dom_summary"`
	Secrets      []string `json:"secrets"`
}

func NewBrowserRunnerTool(manager *runner.RunnerManager, timeout time.Duration) *BrowserRunnerTool {
	return &BrowserRunnerTool{manager: manager, timeout: timeout}
}

func (t *BrowserRunnerTool) Name() string { return "browser_runner" }
func (t *BrowserRunnerTool) Kind() string { return "pentest" }
func (t *BrowserRunnerTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Browser automation via headless Chromium: visit pages, login, capture XHR/fetch requests, extract JS resources, take screenshots, inspect DOM, record cookies/localStorage.",
		Properties: map[string]string{
			"target": "base URL",
			"action": "visit|login|capture_xhr|extract_js|screenshot|dom_inspect",
			"url":    "specific URL to visit",
			"script": "optional custom playwright script",
		},
		Required: []string{"target", "action"},
	}
}

func (t *BrowserRunnerTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	var parsed browserRunnerInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.Target) == "" {
		return fmt.Errorf("target is required")
	}
	return policy.ValidateTarget(ctx, parsed.Target)
}

func (t *BrowserRunnerTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed browserRunnerInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}

	action := strings.TrimSpace(parsed.Action)
	if action == "" {
		action = "visit"
	}
	targetURL := parsed.URL
	if targetURL == "" {
		targetURL = parsed.Target
	}

	script := buildBrowserScript(action, targetURL, parsed.Credentials)
	started := time.Now().UTC()

	runResult := t.manager.Run(ctx, runner.RunRequest{
		TaskID:        parsed.TaskID,
		RunnerType:    "browser",
		ToolName:      t.Name(),
		ImageName:     "runner-browser",
		Command:       []string{"sh", "-lc", script},
		Timeout:       t.timeout,
		NetworkPolicy: "bridge",
	})

	result := parseBrowserResult(action, targetURL, runResult.Stdout)
	raw, _ := json.MarshalIndent(result, "", "  ")

	summary := fmt.Sprintf("Browser %s on %s: title=%s, %d XHR, %d JS files, %d cookies, %d secrets",
		action, targetURL, result.Title, len(result.XHRRequests), len(result.JSFiles), len(result.Cookies), len(result.Secrets))

	return &ToolResult{
		StartedAt:  started,
		FinishedAt: runResult.FinishedAt,
		Status:     runResult.Status,
		Summary:    summary,
		Stdout:     string(raw),
		Stderr:     runResult.Stderr,
		Metadata: map[string]any{
			"action":     action,
			"url":        targetURL,
			"result":     result,
			"image":      runResult.ImageName,
			"xhrCount":   len(result.XHRRequests),
			"secretCount": len(result.Secrets),
		},
		CommandHint: runResult.CommandPreview,
	}, nil
}

func (t *BrowserRunnerTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	action, _ := result.Metadata["action"].(string)
	evidence := []EvidenceDraft{{
		Type:         "tool_output",
		Title:        fmt.Sprintf("Browser %s result", action),
		Summary:      result.Summary,
		Raw:          result.Stdout,
		RelationType: "baseline",
		Redacted:     false,
	}}
	return evidence, nil
}

func buildBrowserScript(action, targetURL string, credentials map[string]string) string {
	escapedURL := strings.ReplaceAll(targetURL, "'", "'\"'\"'")

	// Use node + playwright for browser automation
	switch action {
	case "login":
		username := credentials["username"]
		password := credentials["password"]
		return fmt.Sprintf(`
if command -v node >/dev/null 2>&1 && [ -d /node_modules/playwright ]; then
  node -e "
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({headless: true});
  const page = await browser.newPage();
  await page.goto('%s');
  // Try common login form patterns
  const inputs = await page.$$('input');
  for (const input of inputs) {
    const type = await input.getAttribute('type');
    const name = await input.getAttribute('name');
    if (type === 'text' || type === 'email' || (name && name.match(/user|email|account|login/i))) {
      await input.fill('%s');
    }
    if (type === 'password') {
      await input.fill('%s');
    }
  }
  const submit = await page.$('button[type=submit], input[type=submit], button:has-text(\"login\"), button:has-text(\"登录\")');
  if (submit) await submit.click();
  await page.waitForTimeout(2000);
  console.log('## title');
  console.log(await page.title());
  console.log('## cookies');
  const cookies = await page.context().cookies();
  cookies.forEach(c => console.log(c.name + '=' + c.value.substring(0,20) + '...'));
  console.log('## url_after_login');
  console.log(page.url());
  await browser.close();
})();
" 2>/dev/null
else
  echo '## fallback_curl'
  curl -ksSI --max-time 10 '%s' 2>/dev/null || true
fi
`, escapedURL, username, password, escapedURL)

	case "capture_xhr":
		return fmt.Sprintf(`
if command -v node >/dev/null 2>&1 && [ -d /node_modules/playwright ]; then
  node -e "
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({headless: true});
  const page = await browser.newPage();
  const requests = [];
  page.on('request', req => {
    if (req.resourceType() === 'xhr' || req.resourceType() === 'fetch') {
      requests.push(req.method() + ' ' + req.url());
    }
  });
  await page.goto('%s', {waitUntil: 'networkidle'});
  await page.waitForTimeout(3000);
  console.log('## title');
  console.log(await page.title());
  console.log('## xhr_requests');
  requests.forEach(r => console.log(r));
  console.log('## cookies');
  const cookies = await page.context().cookies();
  cookies.forEach(c => console.log(c.name + '=' + c.value.substring(0,20)));
  await browser.close();
})();
" 2>/dev/null
else
  echo '## fallback'
  curl -ksSL --max-time 10 '%s' 2>/dev/null | grep -oE '(fetch|axios|XMLHttpRequest|\\$\\.ajax)\\s*\\(' | head -20 || true
fi
`, escapedURL, escapedURL)

	case "extract_js":
		return fmt.Sprintf(`
echo '## js_files'
curl -ksSL --max-time 12 '%s' 2>/dev/null | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | head -20 || true
echo '## js_secrets'
for js in $(curl -ksSL --max-time 10 '%s' 2>/dev/null | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | head -5); do
  full="$js"
  echo "$js" | grep -q "^http" || full="%s/$js"
  curl -ksSL --max-time 8 "$full" 2>/dev/null | grep -oiE "(api[_-]?key|secret|token|password|private[_-]?key|auth)['\"]?\s*[:=]\s*['\"][^'\"]{6,}['\"]" | head -5 || true
done
echo '## frontend_routes'
curl -ksSL --max-time 10 '%s' 2>/dev/null | grep -oE '(path|route)\s*:\s*["\x27]/[^"\x27]+' | head -20 || true
`, escapedURL, escapedURL, strings.TrimRight(targetURL, "/"), escapedURL)

	default: // visit
		return fmt.Sprintf(`
echo '## headers'
curl -ksSI --max-time 10 '%s' 2>/dev/null || true
echo '## body_preview'
curl -ksSL --max-time 12 '%s' 2>/dev/null | head -c 8000 || true
echo '## title'
curl -ksSL --max-time 10 '%s' 2>/dev/null | grep -oP '<title>[^<]+</title>' | head -1 || true
echo '## cookies'
curl -ksSI --max-time 10 '%s' 2>/dev/null | grep -i 'set-cookie' || true
echo '## links'
curl -ksSL --max-time 10 '%s' 2>/dev/null | grep -oP 'href="[^"]*"' | sed 's/href="//;s/"//' | sort -u | head -30 || true
`, escapedURL, escapedURL, escapedURL, escapedURL, escapedURL)
	}
}

func parseBrowserResult(action, url, stdout string) BrowserResult {
	result := BrowserResult{Action: action, URL: url}
	lines := strings.Split(stdout, "\n")
	section := ""

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimPrefix(line, "## ")
			continue
		}
		if line == "" {
			continue
		}

		switch section {
		case "title":
			if result.Title == "" {
				result.Title = strings.TrimPrefix(strings.TrimSuffix(line, "</title>"), "<title>")
			}
		case "cookies":
			result.Cookies = append(result.Cookies, line)
		case "xhr_requests":
			result.XHRRequests = append(result.XHRRequests, line)
		case "js_files":
			result.JSFiles = append(result.JSFiles, line)
		case "js_secrets":
			if line != "" {
				result.Secrets = append(result.Secrets, line)
			}
		case "frontend_routes":
			result.FrontendRoutes = append(result.FrontendRoutes, line)
		case "links":
			result.FrontendRoutes = append(result.FrontendRoutes, line)
		}
	}

	return result
}
