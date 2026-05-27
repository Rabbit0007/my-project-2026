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

type CodeSliceTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type codeSliceInput struct {
	TaskID   uint   `json:"taskId"`
	Root     string `json:"root"`
	FilePath string `json:"filePath"`
	Line     int    `json:"line"`
	Radius   int    `json:"radius"`
}

func NewCodeSliceTool(manager *runner.RunnerManager, timeout time.Duration) *CodeSliceTool {
	return &CodeSliceTool{manager: manager, timeout: timeout}
}

func (t CodeSliceTool) Name() string { return "code_slice" }
func (t CodeSliceTool) Kind() string { return "code_audit" }
func (t CodeSliceTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Extract a focused code slice around a line for evidence and review.",
		Properties: map[string]string{
			"root":     "workspace extracted root",
			"filePath": "relative source file path",
			"line":     "target line number",
			"radius":   "lines before and after target line",
		},
		Required: []string{"root", "filePath", "line"},
	}
}

func (t CodeSliceTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	_ = ctx
	_ = policy
	var parsed codeSliceInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.Root) == "" || strings.TrimSpace(parsed.FilePath) == "" || parsed.Line <= 0 {
		return fmt.Errorf("root, filePath and line are required")
	}
	return nil
}

func (t CodeSliceTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed codeSliceInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}
	radius := parsed.Radius
	if radius <= 0 {
		radius = 12
	}
	if radius > 60 {
		radius = 60
	}
	startLine := maxInt(1, parsed.Line-radius)
	endLine := parsed.Line + radius
	started := time.Now().UTC()
	script := fmt.Sprintf("nl -ba %s | sed -n '%d,%dp'", shellQuote("./"+parsed.FilePath), startLine, endLine)
	runResult := t.manager.Run(ctx, runner.RunRequest{
		TaskID:        parsed.TaskID,
		RunnerType:    "code_audit",
		ToolName:      t.Name(),
		ImageName:     "runner-code-audit",
		WorkspacePath: parsed.Root,
		Command:       []string{"sh", "-lc", script},
		Timeout:       t.timeout,
		NetworkPolicy: "none",
	})
	lines := []string{}
	for _, raw := range strings.Split(runResult.Stdout, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		prefix := "   "
		fields := strings.Fields(raw)
		if len(fields) > 0 && fields[0] == fmt.Sprintf("%d", parsed.Line) {
			prefix = ">> "
		}
		lines = append(lines, prefix+raw)
	}
	return &ToolResult{
		StartedAt:   started,
		FinishedAt:  runResult.FinishedAt,
		Status:      runResult.Status,
		Summary:     fmt.Sprintf("Extracted code slice for %s:%d", parsed.FilePath, parsed.Line),
		Stdout:      safety.RedactSensitive(strings.Join(lines, "\n")),
		Stderr:      runResult.Stderr,
		Metadata:    map[string]any{"filePath": parsed.FilePath, "line": parsed.Line, "start": startLine, "end": endLine, "image": runResult.ImageName, "containerId": runResult.ContainerID, "workspacePath": parsed.Root},
		CommandHint: runResult.CommandPreview,
	}, nil
}

func (t CodeSliceTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	_ = ctx
	filePath, _ := result.Metadata["filePath"].(string)
	line, _ := result.Metadata["line"].(int)
	return []EvidenceDraft{{
		Type:         "code_snippet",
		Title:        "Focused code slice",
		Summary:      result.Summary,
		Raw:          result.Stdout,
		FilePath:     filePath,
		LineStart:    &line,
		LineEnd:      &line,
		RelationType: "code_source",
		Redacted:     true,
	}}, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
