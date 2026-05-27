package tools

import (
	"context"
	"encoding/json"
	"time"

	"shenji/backend/internal/safety"
)

type ReportAssemblerTool struct{}

func (t ReportAssemblerTool) Name() string { return "report_assembler" }
func (t ReportAssemblerTool) Kind() string { return "report" }
func (t ReportAssemblerTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Assemble markdown/html report artifacts from validated findings and evidence references.",
		Properties:  map[string]string{"taskId": "task id"},
		Required:    []string{"taskId"},
	}
}

func (t ReportAssemblerTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	_ = ctx
	_ = input
	_ = policy
	return nil
}

func (t ReportAssemblerTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	_ = ctx
	started := time.Now().UTC()
	return &ToolResult{
		StartedAt:  started,
		FinishedAt: time.Now().UTC(),
		Status:     "success",
		Summary:    "Report assembler tool request accepted",
		Stdout:     string(input),
		Metadata:   map[string]any{},
	}, nil
}

func (t ReportAssemblerTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	_ = ctx
	_ = result
	return nil, nil
}
