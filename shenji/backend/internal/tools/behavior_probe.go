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

// BehaviorProbeTool is a pure sensor: it sends a baseline request and a variant request,
// then compares the responses. It does NOT decide what to test or what payloads to use.
// The Reasoner generates structured Intents that specify:
// - baseline_url / variant_url (or baseline_body / variant_body)
// - success_criteria (what to look for in the diff)
// - marker (optional string to search in variant response)
// This tool only executes and reports observations.
type BehaviorProbeTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type behaviorProbeInput struct {
	TaskID      uint              `json:"taskId"`
	BaselineURL string            `json:"baselineUrl"`
	VariantURL  string            `json:"variantUrl"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	BaselineBody string           `json:"baselineBody"`
	VariantBody  string           `json:"variantBody"`
	Marker      string            `json:"marker"`
	Hypothesis  string            `json:"hypothesis"`
}

type ProbeObservation struct {
	Hypothesis       string `json:"hypothesis"`
	BaselineStatus   int    `json:"baseline_status"`
	BaselineLength   int    `json:"baseline_length"`
	VariantStatus    int    `json:"variant_status"`
	VariantLength    int    `json:"variant_length"`
	StatusDiff       bool   `json:"status_diff"`
	LengthDiff       bool   `json:"length_diff"`
	MarkerFound      bool   `json:"marker_found"`
	BaselinePreview  string `json:"baseline_preview"`
	VariantPreview   string `json:"variant_preview"`
}

func NewBehaviorProbeTool(manager *runner.RunnerManager, timeout time.Duration) *BehaviorProbeTool {
	return &BehaviorProbeTool{manager: manager, timeout: timeout}
}

func (t *BehaviorProbeTool) Name() string { return "behavior_probe" }
func (t *BehaviorProbeTool) Kind() string { return "pentest" }
func (t *BehaviorProbeTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Pure sensor: sends baseline and variant HTTP requests, compares responses. Does NOT generate payloads — the Reasoner specifies everything via Intent.",
		Properties: map[string]string{
			"baselineUrl":  "full URL for baseline request",
			"variantUrl":   "full URL for variant request",
			"method":       "HTTP method (GET/POST)",
			"headers":      "custom headers (JSON object)",
			"baselineBody": "request body for baseline (POST only)",
			"variantBody":  "request body for variant (POST only)",
			"marker":       "string to search for in variant response",
			"hypothesis":   "what this probe is testing",
		},
		Required: []string{"baselineUrl", "variantUrl"},
	}
}

func (t *BehaviorProbeTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	var parsed behaviorProbeInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.BaselineURL) == "" || strings.TrimSpace(parsed.VariantURL) == "" {
		return fmt.Errorf("baselineUrl and variantUrl are required")
	}
	// Validate both URLs are in scope
	if err := policy.ValidateTarget(ctx, parsed.BaselineURL); err != nil {
		return err
	}
	return policy.ValidateTarget(ctx, parsed.VariantURL)
}

func (t *BehaviorProbeTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed behaviorProbeInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}

	method := strings.ToUpper(strings.TrimSpace(parsed.Method))
	if method == "" {
		method = "GET"
	}

	// Build curl commands
	baselineCurl := buildProbeCurl(parsed.BaselineURL, method, parsed.Headers, parsed.BaselineBody)
	variantCurl := buildProbeCurl(parsed.VariantURL, method, parsed.Headers, parsed.VariantBody)

	command := []string{"sh", "-lc", fmt.Sprintf(`set -eu
echo '## baseline_response'
%s 2>/dev/null | head -c 4000 || true
echo
echo '## baseline_meta'
%s 2>/dev/null || true
echo
echo '## variant_response'
%s 2>/dev/null | head -c 4000 || true
echo
echo '## variant_meta'
%s 2>/dev/null || true
`,
		baselineCurl+" -i",
		strings.Replace(baselineCurl, "curl -ksS", "curl -ksSo /dev/null -w 'status=%{http_code} size=%{size_download}'", 1),
		variantCurl+" -i",
		strings.Replace(variantCurl, "curl -ksS", "curl -ksSo /dev/null -w 'status=%{http_code} size=%{size_download}'", 1),
	)}

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

	observation := parseProbeObservation(parsed.Hypothesis, parsed.Marker, runResult.Stdout)
	raw, _ := json.MarshalIndent(observation, "", "  ")

	summary := fmt.Sprintf("Probe [%s]: ", parsed.Hypothesis)
	if observation.StatusDiff || observation.LengthDiff || observation.MarkerFound {
		summary += "BEHAVIORAL DIFFERENCE DETECTED"
		if observation.MarkerFound {
			summary += " (marker found)"
		}
	} else {
		summary += "no observable difference"
	}

	return &ToolResult{
		StartedAt:  started,
		FinishedAt: runResult.FinishedAt,
		Status:     runResult.Status,
		Summary:    summary,
		Stdout:     string(raw),
		Stderr:     runResult.Stderr,
		Metadata: map[string]any{
			"hypothesis":  parsed.Hypothesis,
			"statusDiff":  observation.StatusDiff,
			"lengthDiff":  observation.LengthDiff,
			"markerFound": observation.MarkerFound,
			"observation": observation,
		},
		CommandHint: runResult.CommandPreview,
	}, nil
}

func (t *BehaviorProbeTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	hypothesis, _ := result.Metadata["hypothesis"].(string)
	markerFound, _ := result.Metadata["markerFound"].(bool)
	statusDiff, _ := result.Metadata["statusDiff"].(bool)
	lengthDiff, _ := result.Metadata["lengthDiff"].(bool)

	relationType := "baseline"
	if markerFound || statusDiff || lengthDiff {
		relationType = "poc_result"
	}

	evidence := []EvidenceDraft{{
		Type:         "http_exchange",
		Title:        fmt.Sprintf("Behavior observation: %s", hypothesis),
		Summary:      result.Summary,
		Raw:          result.Stdout,
		RelationType: relationType,
		Redacted:     false,
	}}
	return evidence, nil
}

func buildProbeCurl(targetURL, method string, headers map[string]string, body string) string {
	parts := []string{"curl", "-ksS", "--max-time", "10", "-X", method}
	for key, value := range headers {
		parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", key, value))
	}
	if body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		parts = append(parts, "-d", shellSingleQuote(body))
	}
	parts = append(parts, shellSingleQuote(targetURL))
	return strings.Join(parts, " ")
}

func parseProbeObservation(hypothesis, marker, stdout string) ProbeObservation {
	obs := ProbeObservation{Hypothesis: hypothesis}

	sections := strings.Split(stdout, "## ")
	for _, section := range sections {
		if strings.HasPrefix(section, "baseline_meta") {
			line := strings.TrimSpace(strings.TrimPrefix(section, "baseline_meta\n"))
			fmt.Sscanf(line, "status=%d size=%d", &obs.BaselineStatus, &obs.BaselineLength)
		} else if strings.HasPrefix(section, "variant_meta") {
			line := strings.TrimSpace(strings.TrimPrefix(section, "variant_meta\n"))
			fmt.Sscanf(line, "status=%d size=%d", &obs.VariantStatus, &obs.VariantLength)
		} else if strings.HasPrefix(section, "baseline_response") {
			obs.BaselinePreview = truncateStr(strings.TrimPrefix(section, "baseline_response\n"), 1000)
		} else if strings.HasPrefix(section, "variant_response") {
			obs.VariantPreview = truncateStr(strings.TrimPrefix(section, "variant_response\n"), 1000)
		}
	}

	// Detect differences
	if obs.BaselineStatus != obs.VariantStatus && obs.VariantStatus != 0 && obs.BaselineStatus != 0 {
		obs.StatusDiff = true
	}
	if obs.BaselineLength > 0 && obs.VariantLength > 0 {
		diff := obs.VariantLength - obs.BaselineLength
		if diff < 0 {
			diff = -diff
		}
		if float64(diff)/float64(max(obs.BaselineLength, 1)) > 0.1 {
			obs.LengthDiff = true
		}
	}

	// Check marker
	if marker != "" && strings.Contains(obs.VariantPreview, marker) {
		obs.MarkerFound = true
	}

	return obs
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
