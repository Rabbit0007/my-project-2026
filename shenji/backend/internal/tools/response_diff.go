package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"shenji/backend/internal/safety"
)

type ResponseDiffTool struct{}

type responseDiffInput struct {
	Target           string `json:"target"`
	Marker           string `json:"marker"`
	BaselineURL      string `json:"baselineUrl"`
	ValidationURL    string `json:"validationUrl"`
	BaselineStatus   int    `json:"baselineStatus"`
	ValidationStatus int    `json:"validationStatus"`
	BaselineBody     string `json:"baselineBody"`
	ValidationBody   string `json:"validationBody"`
}

func (t ResponseDiffTool) Name() string { return "response_diff" }
func (t ResponseDiffTool) Kind() string { return "http" }
func (t ResponseDiffTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Compare baseline and validation HTTP responses to extract observable differences.",
		Properties: map[string]string{
			"target":           "authorized target",
			"marker":           "validation marker",
			"baselineUrl":      "baseline request URL",
			"validationUrl":    "validation request URL",
			"baselineStatus":   "baseline status code",
			"validationStatus": "validation status code",
			"baselineBody":     "baseline response body",
			"validationBody":   "validation response body",
		},
		Required: []string{"target", "baselineUrl", "validationUrl"},
	}
}

func (t ResponseDiffTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	_ = ctx
	_ = policy
	var parsed responseDiffInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.Target) == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

func (t ResponseDiffTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	_ = ctx
	var parsed responseDiffInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}
	statusChanged := parsed.BaselineStatus != parsed.ValidationStatus
	bodyChanged := parsed.BaselineBody != parsed.ValidationBody
	reflectedMarker := parsed.Marker != "" && strings.Contains(parsed.ValidationBody, parsed.Marker)
	summaryParts := []string{}
	if statusChanged {
		summaryParts = append(summaryParts, fmt.Sprintf("status changed %d -> %d", parsed.BaselineStatus, parsed.ValidationStatus))
	}
	if bodyChanged {
		summaryParts = append(summaryParts, fmt.Sprintf("body length changed %d -> %d", len(parsed.BaselineBody), len(parsed.ValidationBody)))
	}
	if reflectedMarker {
		summaryParts = append(summaryParts, "marker reflected in response")
	}
	if len(summaryParts) == 0 {
		summaryParts = append(summaryParts, "no observable diff detected")
	}
	raw := fmt.Sprintf(
		"target: %s\nbaseline_url: %s\nvalidation_url: %s\nsummary: %s\n",
		parsed.Target,
		parsed.BaselineURL,
		parsed.ValidationURL,
		strings.Join(summaryParts, "; "),
	)
	return &ToolResult{
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		Status:     "success",
		Summary:    strings.Join(summaryParts, "; "),
		Stdout:     safety.RedactSensitive(raw),
		Metadata: map[string]any{
			"target":           parsed.Target,
			"statusChanged":    statusChanged,
			"bodyChanged":      bodyChanged,
			"reflectedMarker":  reflectedMarker,
			"baselineStatus":   parsed.BaselineStatus,
			"validationStatus": parsed.ValidationStatus,
			"baselineUrl":      parsed.BaselineURL,
			"validationUrl":    parsed.ValidationURL,
			"baselineBody":     safety.RedactSensitive(parsed.BaselineBody),
			"validationBody":   safety.RedactSensitive(parsed.ValidationBody),
		},
		CommandHint: "response_diff " + parsed.Target,
	}, nil
}

func (t ResponseDiffTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	_ = ctx
	target, _ := result.Metadata["target"].(string)
	request, _ := json.Marshal(map[string]any{
		"method": "GET",
		"url":    result.Metadata["validationUrl"],
	})
	response, _ := json.Marshal(map[string]any{
		"status":  result.Metadata["validationStatus"],
		"body":    result.Metadata["validationBody"],
		"summary": result.Summary,
	})
	return []EvidenceDraft{{
		Type:             "response_diff",
		Title:            "HTTP response diff evidence",
		Summary:          result.Summary,
		Raw:              result.Stdout,
		Target:           target,
		RequestSnapshot:  request,
		ResponseSnapshot: response,
		RelationType:     "poc_result",
		Redacted:         true,
	}}, nil
}
