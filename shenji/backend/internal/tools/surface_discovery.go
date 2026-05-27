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

// SurfaceDiscoveryTool performs comprehensive attack surface discovery.
// It collects: homepage, login/register, robots.txt, sitemap.xml, JS/CSS resources,
// API paths, forms, upload/download points, admin interfaces, error pages,
// cookies, response headers, authentication methods, and frontend routes.
// All results are written as Surface Facts to the blackboard.
type SurfaceDiscoveryTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type surfaceDiscoveryInput struct {
	TaskID uint   `json:"taskId"`
	Target string `json:"target"`
}

type SurfaceResult struct {
	Target          string   `json:"target"`
	StatusCode      int      `json:"status_code"`
	ServerHeader    string   `json:"server_header"`
	PoweredBy       string   `json:"powered_by"`
	Cookies         []string `json:"cookies"`
	ResponseHeaders []string `json:"response_headers"`
	Forms           []string `json:"forms"`
	Links           []string `json:"links"`
	JSFiles         []string `json:"js_files"`
	APIEndpoints    []string `json:"api_endpoints"`
	UploadPoints    []string `json:"upload_points"`
	DownloadPoints  []string `json:"download_points"`
	AdminPaths      []string `json:"admin_paths"`
	LoginPaths      []string `json:"login_paths"`
	RobotsTxt       string   `json:"robots_txt"`
	SitemapPaths    []string `json:"sitemap_paths"`
	ErrorPages      []string `json:"error_pages"`
	JSSecrets       []string `json:"js_secrets"`
	AuthMethod      string   `json:"auth_method"`
}

func NewSurfaceDiscoveryTool(manager *runner.RunnerManager, timeout time.Duration) *SurfaceDiscoveryTool {
	return &SurfaceDiscoveryTool{manager: manager, timeout: timeout}
}

func (t *SurfaceDiscoveryTool) Name() string { return "surface_discovery" }
func (t *SurfaceDiscoveryTool) Kind() string { return "pentest" }
func (t *SurfaceDiscoveryTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Comprehensive attack surface discovery: homepage, robots.txt, JS analysis, forms, upload/download points, admin paths, API endpoints, cookies, auth method detection.",
		Properties:  map[string]string{"target": "authorized URL"},
		Required:    []string{"target"},
	}
}

func (t *SurfaceDiscoveryTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	var parsed surfaceDiscoveryInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.Target) == "" {
		return fmt.Errorf("target is required")
	}
	return policy.ValidateTarget(ctx, parsed.Target)
}

func (t *SurfaceDiscoveryTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed surfaceDiscoveryInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}

	target := strings.TrimRight(strings.TrimSpace(parsed.Target), "/")
	escaped := shellSingleQuote(target)
	started := time.Now().UTC()

	// Comprehensive surface discovery script
	command := []string{"sh", "-lc", fmt.Sprintf(`set -eu
echo '## homepage'
curl -ksSI --max-time 10 %s 2>/dev/null || true
echo '---BODY---'
curl -ksSL --max-time 12 %s 2>/dev/null | head -c 15000 || true

echo '## robots'
curl -ksSL --max-time 8 %s/robots.txt 2>/dev/null | head -50 || true

echo '## sitemap'
curl -ksSL --max-time 8 %s/sitemap.xml 2>/dev/null | grep -oP 'loc>[^<]+' | head -30 || true

echo '## common_paths'
for path in /admin /login /register /api /swagger /graphql /upload /download /export /.env /backup /debug /test /health /status /api/v1 /api/docs; do
  code=$(curl -ksSo /dev/null -w '%%{http_code}' --max-time 5 %s$path 2>/dev/null || echo "000")
  if [ "$code" != "000" ] && [ "$code" != "404" ]; then
    echo "$path $code"
  fi
done

echo '## js_files'
curl -ksSL --max-time 12 %s 2>/dev/null | grep -oP '(src|href)="[^"]*\.(js|css)"' | head -30 || true

echo '## js_secrets'
for jsurl in $(curl -ksSL --max-time 10 %s 2>/dev/null | grep -oP 'src="[^"]*\.js"' | grep -oP '"[^"]*"' | tr -d '"' | head -5); do
  full_url="%s"
  if echo "$jsurl" | grep -q "^http"; then
    full_url="$jsurl"
  elif echo "$jsurl" | grep -q "^/"; then
    full_url="%s$jsurl"
  fi
  curl -ksSL --max-time 8 "$full_url" 2>/dev/null | grep -oiE "(api[_-]?key|secret|token|password|credential|private[_-]?key|auth)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]" | head -10 || true
done
`, escaped, escaped, escaped, escaped, escaped, escaped, escaped, target, target)}

	runResult := t.manager.Run(ctx, runner.RunRequest{
		TaskID:        parsed.TaskID,
		RunnerType:    "pentest",
		ToolName:      t.Name(),
		ImageName:     "runner-pentest",
		Command:       command,
		Timeout:       t.timeout,
		NetworkPolicy: "bridge",
	})

	result := parseSurfaceResult(target, runResult.Stdout)
	raw, _ := json.MarshalIndent(result, "", "  ")

	factCount := len(result.APIEndpoints) + len(result.Forms) + len(result.UploadPoints) + len(result.AdminPaths) + len(result.JSSecrets)
	summary := fmt.Sprintf("Surface discovery: %d API endpoints, %d forms, %d upload points, %d admin paths, %d JS secrets found",
		len(result.APIEndpoints), len(result.Forms), len(result.UploadPoints), len(result.AdminPaths), len(result.JSSecrets))

	return &ToolResult{
		StartedAt:  started,
		FinishedAt: runResult.FinishedAt,
		Status:     runResult.Status,
		Summary:    summary,
		Stdout:     string(raw),
		Stderr:     runResult.Stderr,
		Metadata: map[string]any{
			"target":    target,
			"result":    result,
			"factCount": factCount,
			"image":     runResult.ImageName,
		},
		CommandHint: runResult.CommandPreview,
	}, nil
}

func (t *SurfaceDiscoveryTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	target, _ := result.Metadata["target"].(string)
	evidence := []EvidenceDraft{{
		Type:         "tool_output",
		Title:        "Attack Surface Discovery",
		Summary:      result.Summary,
		Raw:          result.Stdout,
		Target:       target,
		RelationType: "baseline",
		Redacted:     false,
	}}
	return evidence, nil
}

func parseSurfaceResult(target string, stdout string) SurfaceResult {
	result := SurfaceResult{Target: target}
	lines := strings.Split(stdout, "\n")
	section := ""

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimPrefix(line, "## ")
			continue
		}
		if line == "" || line == "---BODY---" {
			continue
		}

		switch section {
		case "homepage":
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "server:") {
				result.ServerHeader = strings.TrimSpace(line[7:])
			}
			if strings.HasPrefix(lower, "x-powered-by:") {
				result.PoweredBy = strings.TrimSpace(line[13:])
			}
			if strings.HasPrefix(lower, "set-cookie:") {
				result.Cookies = append(result.Cookies, strings.TrimSpace(line[11:]))
			}
			if strings.Contains(lower, "authorization") || strings.Contains(lower, "www-authenticate") {
				result.AuthMethod = "header-based"
			}
			// Extract forms and links from body
			if strings.Contains(lower, "<form") {
				result.Forms = append(result.Forms, extractFormAction(line))
			}
			if strings.Contains(lower, "href=") {
				for _, link := range extractLinks(line) {
					if isInterestingLink(link) {
						result.Links = append(result.Links, link)
					}
				}
			}

		case "robots":
			if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
				path := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				if path != "" {
					result.RobotsTxt += line + "\n"
					if isAdminPath(path) {
						result.AdminPaths = append(result.AdminPaths, path)
					}
				}
			}

		case "common_paths":
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				path := parts[0]
				code := parts[1]
				if isAdminPath(path) {
					result.AdminPaths = append(result.AdminPaths, fmt.Sprintf("%s [%s]", path, code))
				} else if strings.Contains(path, "login") || strings.Contains(path, "register") {
					result.LoginPaths = append(result.LoginPaths, fmt.Sprintf("%s [%s]", path, code))
				} else if strings.Contains(path, "upload") {
					result.UploadPoints = append(result.UploadPoints, fmt.Sprintf("%s [%s]", path, code))
				} else if strings.Contains(path, "download") || strings.Contains(path, "export") {
					result.DownloadPoints = append(result.DownloadPoints, fmt.Sprintf("%s [%s]", path, code))
				} else if strings.Contains(path, "api") || strings.Contains(path, "swagger") || strings.Contains(path, "graphql") {
					result.APIEndpoints = append(result.APIEndpoints, fmt.Sprintf("%s [%s]", path, code))
				}
			}

		case "js_files":
			if strings.Contains(line, ".js") {
				result.JSFiles = append(result.JSFiles, line)
			}

		case "js_secrets":
			if line != "" {
				result.JSSecrets = append(result.JSSecrets, line)
			}
		}
	}

	// Detect auth method from cookies
	if result.AuthMethod == "" {
		for _, cookie := range result.Cookies {
			lower := strings.ToLower(cookie)
			if strings.Contains(lower, "session") || strings.Contains(lower, "phpsessid") {
				result.AuthMethod = "session-cookie"
			} else if strings.Contains(lower, "token") || strings.Contains(lower, "jwt") {
				result.AuthMethod = "token-cookie"
			}
		}
	}

	return result
}

func extractFormAction(line string) string {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "action=")
	if idx < 0 {
		return "form-detected"
	}
	rest := line[idx+7:]
	rest = strings.Trim(rest, "\"' ")
	if end := strings.IndexAny(rest, "\"' >"); end > 0 {
		return rest[:end]
	}
	return "form-detected"
}

func extractLinks(line string) []string {
	var links []string
	for _, sep := range []string{`href="`, `href='`} {
		parts := strings.Split(line, sep)
		for i := 1; i < len(parts); i++ {
			end := strings.IndexAny(parts[i], "\"'")
			if end > 0 {
				links = append(links, parts[i][:end])
			}
		}
	}
	return links
}

func isInterestingLink(link string) bool {
	lower := strings.ToLower(link)
	return strings.Contains(lower, "api") || strings.Contains(lower, "admin") ||
		strings.Contains(lower, "upload") || strings.Contains(lower, "download") ||
		strings.Contains(lower, "login") || strings.Contains(lower, "register") ||
		strings.Contains(lower, "graphql") || strings.Contains(lower, "swagger")
}

func isAdminPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "admin") || strings.Contains(lower, "manage") ||
		strings.Contains(lower, "dashboard") || strings.Contains(lower, "console") ||
		strings.Contains(lower, "debug")
}
