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

// FingerprintTool identifies components, frameworks, versions from HTTP responses,
// dependency files, and service banners. Results are written as Blackboard Facts
// for environment modeling and ordinary hypothesis formation.
type FingerprintTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type fingerprintInput struct {
	TaskID uint   `json:"taskId"`
	Target string `json:"target"`
	Mode   string `json:"mode"` // http_headers | dependency_scan | full
}

type fingerprintResult struct {
	Target     string                 `json:"target"`
	Mode       string                 `json:"mode"`
	Components []componentFingerprint `json:"components"`
	RawOutput  string                 `json:"raw_output"`
}

type componentFingerprint struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Category   string `json:"category"`   // framework / server / language / library / cms / plugin
	Confidence string `json:"confidence"` // definite / probable / possible
	Source     string `json:"source"`     // http_header / html_meta / url_pattern / dependency_file / banner
}

func NewFingerprintTool(manager *runner.RunnerManager, timeout time.Duration) *FingerprintTool {
	return &FingerprintTool{manager: manager, timeout: timeout}
}

func (t *FingerprintTool) Name() string { return "fingerprint" }
func (t *FingerprintTool) Kind() string { return "pentest" }
func (t *FingerprintTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Identify target components, frameworks, and versions through HTTP fingerprinting, dependency analysis, and service banners.",
		Properties: map[string]string{
			"target": "authorized URL, domain, or IP",
			"mode":   "http_headers | dependency_scan | full (default: full)",
		},
		Required: []string{"target"},
	}
}

func (t *FingerprintTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	var parsed fingerprintInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.Target) == "" {
		return fmt.Errorf("target is required")
	}
	return policy.ValidateTarget(ctx, parsed.Target)
}

func (t *FingerprintTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed fingerprintInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}
	mode := strings.TrimSpace(parsed.Mode)
	if mode == "" {
		mode = "full"
	}

	command := fingerprintCommand(parsed.Target, mode)
	started := time.Now().UTC()

	runResult := t.manager.Run(ctx, runner.RunRequest{
		TaskID:        parsed.TaskID,
		RunnerType:    "pentest",
		ToolName:      t.Name(),
		ImageName:     "runner-pentest",
		Command:       command,
		Timeout:       t.timeout,
		NetworkPolicy: "bridge",
	})

	result := parseFingerprints(parsed.Target, mode, runResult.Stdout)
	raw, _ := json.MarshalIndent(result, "", "  ")

	summary := fmt.Sprintf("Fingerprint scan identified %d components for %s", len(result.Components), parsed.Target)

	return &ToolResult{
		StartedAt:  started,
		FinishedAt: runResult.FinishedAt,
		Status:     runResult.Status,
		Summary:    summary,
		Stdout:     string(raw),
		Stderr:     runResult.Stderr,
		Metadata: map[string]any{
			"target":         parsed.Target,
			"mode":           mode,
			"image":          runResult.ImageName,
			"containerId":    runResult.ContainerID,
			"componentCount": len(result.Components),
			"components":     result.Components,
		},
		CommandHint: runResult.CommandPreview,
	}, nil
}

func (t *FingerprintTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	_ = ctx
	target, _ := result.Metadata["target"].(string)
	components, _ := result.Metadata["components"].([]componentFingerprint)

	evidence := []EvidenceDraft{}

	// One evidence per identified component
	for _, comp := range components {
		title := fmt.Sprintf("Component: %s %s", comp.Name, comp.Version)
		summary := fmt.Sprintf("Identified %s %s (%s) via %s [%s]", comp.Name, comp.Version, comp.Category, comp.Source, comp.Confidence)
		evidence = append(evidence, EvidenceDraft{
			Type:         "tool_output",
			Title:        title,
			Summary:      summary,
			Raw:          result.Stdout,
			Target:       target,
			RelationType: "fingerprint",
			Redacted:     false,
		})
	}

	// If no components found, still record the attempt
	if len(evidence) == 0 {
		evidence = append(evidence, EvidenceDraft{
			Type:         "tool_output",
			Title:        "Fingerprint scan completed",
			Summary:      result.Summary,
			Raw:          result.Stdout,
			Target:       target,
			RelationType: "baseline",
			Redacted:     false,
		})
	}

	return evidence, nil
}

func fingerprintCommand(target string, mode string) []string {
	escaped := shellSingleQuote(target)

	switch mode {
	case "http_headers":
		return []string{"sh", "-lc", fmt.Sprintf(`set -eu
echo '## http_headers'
curl -ksSI --max-time 10 %s 2>/dev/null || true
echo '## http_body_meta'
curl -ksSL --max-time 12 %s 2>/dev/null | head -c 8000 || true`, escaped, escaped)}

	case "dependency_scan":
		return []string{"sh", "-lc", fmt.Sprintf(`set -eu
echo '## whatweb'
if command -v whatweb >/dev/null 2>&1; then whatweb --no-errors --color=never --log-brief=- %s 2>/dev/null || true; fi
echo '## httpx_tech'
if command -v httpx >/dev/null 2>&1; then printf '%%s\n' %s | httpx -silent -tech-detect -status-code -title -follow-redirects -timeout 10 2>/dev/null || true; fi`, escaped, escaped)}

	default: // full
		return []string{"sh", "-lc", fmt.Sprintf(`set -eu
echo '## http_headers'
curl -ksSI --max-time 10 %s 2>/dev/null || true
echo '## http_body_meta'
curl -ksSL --max-time 12 %s 2>/dev/null | head -c 8000 || true
echo '## whatweb'
if command -v whatweb >/dev/null 2>&1; then whatweb --no-errors --color=never --log-brief=- %s 2>/dev/null || true; fi
echo '## httpx_tech'
if command -v httpx >/dev/null 2>&1; then printf '%%s\n' %s | httpx -silent -tech-detect -status-code -title -follow-redirects -timeout 10 2>/dev/null || true; fi
echo '## nmap_version'
if command -v nmap >/dev/null 2>&1; then nmap -Pn -sV --top-ports 20 --host-timeout 30s %s 2>/dev/null || true; fi`, escaped, escaped, escaped, escaped, shellSingleQuote(hostForProbe(target)))}
	}
}

func parseFingerprints(target string, mode string, stdout string) fingerprintResult {
	result := fingerprintResult{
		Target:    target,
		Mode:      mode,
		RawOutput: truncateProbeText(stdout, 15000),
	}

	lines := strings.Split(stdout, "\n")
	seen := map[string]struct{}{}

	addComponent := func(name, version, category, confidence, source string) {
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if name == "" {
			return
		}
		key := strings.ToLower(name + "|" + version)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		result.Components = append(result.Components, componentFingerprint{
			Name:       name,
			Version:    version,
			Category:   category,
			Confidence: confidence,
			Source:     source,
		})
	}

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)

		// Server header: "Server: Apache/2.4.49"
		if strings.HasPrefix(lower, "server:") {
			value := strings.TrimSpace(line[7:])
			parts := strings.SplitN(value, "/", 2)
			name := parts[0]
			version := ""
			if len(parts) > 1 {
				version = strings.Split(parts[1], " ")[0]
			}
			addComponent(name, version, "server", "definite", "http_header")
		}

		// X-Powered-By: PHP/7.4.3
		if strings.HasPrefix(lower, "x-powered-by:") {
			value := strings.TrimSpace(line[13:])
			parts := strings.SplitN(value, "/", 2)
			name := parts[0]
			version := ""
			if len(parts) > 1 {
				version = strings.Split(parts[1], " ")[0]
			}
			addComponent(name, version, "language", "definite", "http_header")
		}

		// WhatWeb output: "http://target [200 OK] Apache[2.4.49], PHP[7.4.3], ThinkPHP"
		if strings.Contains(lower, "[") && (strings.Contains(lower, "http://") || strings.Contains(lower, "https://")) {
			// Extract bracketed components
			parts := strings.Split(line, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if idx := strings.Index(part, "["); idx > 0 {
					name := strings.TrimSpace(part[:idx])
					// Remove URL prefix if present
					if lastSpace := strings.LastIndex(name, " "); lastSpace >= 0 {
						name = name[lastSpace+1:]
					}
					version := strings.Trim(part[idx:], "[]")
					if name != "" && !strings.HasPrefix(strings.ToLower(name), "http") && len(name) < 40 {
						addComponent(name, version, "framework", "probable", "whatweb")
					}
				}
			}
		}

		// httpx tech detect: "http://target [200] [Title] [nginx,php,jquery]"
		if strings.Contains(lower, "httpx") || (strings.Count(line, "[") >= 3 && strings.Contains(lower, "http")) {
			// Extract tech from last bracket group
			lastOpen := strings.LastIndex(line, "[")
			lastClose := strings.LastIndex(line, "]")
			if lastOpen >= 0 && lastClose > lastOpen {
				techs := line[lastOpen+1 : lastClose]
				for _, tech := range strings.Split(techs, ",") {
					tech = strings.TrimSpace(tech)
					if tech != "" && len(tech) < 40 {
						addComponent(tech, "", "framework", "probable", "httpx")
					}
				}
			}
		}

		// Nmap service version: "80/tcp open http Apache httpd 2.4.49"
		if strings.Contains(lower, "/tcp") && strings.Contains(lower, "open") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				// Try to extract service name and version
				serviceName := ""
				serviceVersion := ""
				for i := 3; i < len(fields); i++ {
					if isVersionLike(fields[i]) {
						serviceVersion = fields[i]
						break
					}
					if serviceName == "" {
						serviceName = fields[i]
					} else {
						serviceName += " " + fields[i]
					}
				}
				if serviceName != "" {
					addComponent(serviceName, serviceVersion, "service", "definite", "banner")
				}
			}
		}
	}

	return result
}

func isVersionLike(s string) bool {
	if len(s) == 0 {
		return false
	}
	dotCount := strings.Count(s, ".")
	if dotCount == 0 {
		return false
	}
	// Check if starts with digit
	if s[0] >= '0' && s[0] <= '9' {
		return true
	}
	return false
}
