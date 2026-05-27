package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"shenji/backend/internal/safety"
)

type HTTPSurfaceTool struct{}

type httpSurfaceInput struct {
	TaskID  uint              `json:"taskId"`
	BaseURL string            `json:"baseUrl"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers"`
}

type httpSurfaceLink struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

type httpSurfaceForm struct {
	Method string   `json:"method"`
	Action string   `json:"action"`
	Inputs []string `json:"inputs"`
}

type httpSurfaceParam struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	URL      string `json:"url"`
	Method   string `json:"method"`
}

type httpSurfaceResult struct {
	BaseURL    string             `json:"baseUrl"`
	Links      []httpSurfaceLink  `json:"links"`
	Forms      []httpSurfaceForm  `json:"forms"`
	Parameters []httpSurfaceParam `json:"parameters"`
}

func (t HTTPSurfaceTool) Name() string { return "http_surface" }
func (t HTTPSurfaceTool) Kind() string { return "http" }
func (t HTTPSurfaceTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Parse an authorized HTTP baseline response into links, forms, and parameter input surfaces.",
		Properties: map[string]string{
			"baseUrl": "authorized baseline URL",
			"body":    "redacted HTTP response body",
			"headers": "optional response headers",
		},
		Required: []string{"baseUrl"},
	}
}

func (t HTTPSurfaceTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	var parsed httpSurfaceInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	return policy.ValidateTarget(ctx, parsed.BaseURL)
}

func (t HTTPSurfaceTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	_ = ctx
	started := time.Now().UTC()
	var parsed httpSurfaceInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}
	result := discoverHTTPSurface(parsed.BaseURL, parsed.Body)
	raw, _ := json.MarshalIndent(result, "", "  ")
	summary := fmt.Sprintf("Discovered %d links, %d forms, and %d input parameters from %s", len(result.Links), len(result.Forms), len(result.Parameters), parsed.BaseURL)
	now := time.Now().UTC()
	return &ToolResult{
		StartedAt:  started,
		FinishedAt: now,
		Status:     "success",
		Summary:    summary,
		Stdout:     string(raw),
		Metadata: map[string]any{
			"baseUrl":    parsed.BaseURL,
			"linkCount":  len(result.Links),
			"formCount":  len(result.Forms),
			"paramCount": len(result.Parameters),
		},
		CommandHint: "http_surface " + parsed.BaseURL,
	}, nil
}

func (t HTTPSurfaceTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	_ = ctx
	target, _ := result.Metadata["baseUrl"].(string)
	return []EvidenceDraft{{
		Type:             "tool_output",
		Title:            "HTTP input surface discovery",
		Summary:          result.Summary,
		Raw:              result.Stdout,
		Target:           target,
		ResponseSnapshot: json.RawMessage(result.Stdout),
		RelationType:     "baseline",
		Redacted:         true,
	}}, nil
}

func discoverHTTPSurface(baseURL string, body string) httpSurfaceResult {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return httpSurfaceResult{BaseURL: baseURL}
	}
	if len(body) > 512000 {
		body = body[:512000]
	}
	links := extractSurfaceLinks(parsedBase, body)
	forms := extractSurfaceForms(parsedBase, body)
	params := extractSurfaceParams(parsedBase, links, forms)
	return httpSurfaceResult{
		BaseURL:    baseURL,
		Links:      links,
		Forms:      forms,
		Parameters: params,
	}
}

func extractSurfaceLinks(base *url.URL, body string) []httpSurfaceLink {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']?([^"'\s>#]+)`),
		regexp.MustCompile(`(?is)<area[^>]+href\s*=\s*["']?([^"'\s>#]+)`),
		regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']?([^"'\s>#]+)`),
		regexp.MustCompile(`(?is)<link[^>]+href\s*=\s*["']?([^"'\s>#]+)`),
	}
	seen := map[string]struct{}{}
	links := []httpSurfaceLink{}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(body, 80) {
			if len(match) < 2 {
				continue
			}
			resolved := resolveSurfaceURL(base, htmlUnescapeLite(match[1]))
			if resolved == "" {
				continue
			}
			if _, exists := seen[resolved]; exists {
				continue
			}
			seen[resolved] = struct{}{}
			links = append(links, httpSurfaceLink{URL: resolved, Source: "html"})
			if len(links) >= 60 {
				return links
			}
		}
	}
	return links
}

func extractSurfaceForms(base *url.URL, body string) []httpSurfaceForm {
	formRe := regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRe := regexp.MustCompile(`(?is)<(?:input|textarea|select)\b([^>]*)>`)
	forms := []httpSurfaceForm{}
	for _, match := range formRe.FindAllStringSubmatch(body, 40) {
		if len(match) < 3 {
			continue
		}
		attrs := match[1]
		inner := match[2]
		method := strings.ToUpper(firstNonBlank(attrValue(attrs, "method"), "GET"))
		action := attrValue(attrs, "action")
		if action == "" {
			action = base.String()
		} else {
			action = resolveSurfaceURL(base, htmlUnescapeLite(action))
		}
		inputs := []string{}
		seenInputs := map[string]struct{}{}
		for _, inputMatch := range inputRe.FindAllStringSubmatch(inner, 80) {
			if len(inputMatch) < 2 {
				continue
			}
			name := strings.TrimSpace(attrValue(inputMatch[1], "name"))
			if name == "" {
				continue
			}
			if _, exists := seenInputs[name]; exists {
				continue
			}
			seenInputs[name] = struct{}{}
			inputs = append(inputs, name)
		}
		sort.Strings(inputs)
		forms = append(forms, httpSurfaceForm{Method: method, Action: action, Inputs: inputs})
		if len(forms) >= 24 {
			break
		}
	}
	return forms
}

func extractSurfaceParams(base *url.URL, links []httpSurfaceLink, forms []httpSurfaceForm) []httpSurfaceParam {
	seen := map[string]struct{}{}
	params := []httpSurfaceParam{}
	addQueryParams := func(rawURL string, method string) {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return
		}
		for name := range parsed.Query() {
			key := method + "|query|" + rawURL + "|" + name
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			params = append(params, httpSurfaceParam{Name: name, Location: "query", URL: rawURL, Method: method})
		}
	}
	addQueryParams(base.String(), "GET")
	for _, link := range links {
		addQueryParams(link.URL, "GET")
		if len(params) >= 80 {
			return params
		}
	}
	for _, form := range forms {
		for _, input := range form.Inputs {
			key := form.Method + "|form|" + form.Action + "|" + input
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			params = append(params, httpSurfaceParam{Name: input, Location: "form", URL: form.Action, Method: form.Method})
			if len(params) >= 80 {
				return params
			}
		}
	}
	return params
}

func resolveSurfaceURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	resolved.Fragment = ""
	return resolved.String()
}

func attrValue(attrs string, name string) string {
	pattern := regexp.MustCompile(`(?is)\b` + regexp.QuoteMeta(name) + `\s*=\s*["']?([^"'\s>]+)`)
	match := pattern.FindStringSubmatch(attrs)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func htmlUnescapeLite(value string) string {
	replacements := map[string]string{
		"&amp;":  "&",
		"&#38;":  "&",
		"&lt;":   "<",
		"&gt;":   ">",
		"&quot;": `"`,
		"&#39;":  "'",
	}
	for old, next := range replacements {
		value = strings.ReplaceAll(value, old, next)
	}
	return value
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
