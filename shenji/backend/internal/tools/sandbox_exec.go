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

type SandboxExecTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type sandboxExecInput struct {
	TaskID        uint     `json:"taskId"`
	Command       string   `json:"command"`
	Args          []string `json:"args"`
	WorkspacePath string   `json:"workspacePath"`
	ProofContext  bool     `json:"proofContext"`
	ProofKind     string   `json:"proofKind"`
	Target        string   `json:"target"`
}

func NewSandboxExecTool(manager *runner.RunnerManager, timeout time.Duration) *SandboxExecTool {
	return &SandboxExecTool{manager: manager, timeout: timeout}
}

func (t *SandboxExecTool) Name() string { return "sandbox_exec" }
func (t *SandboxExecTool) Kind() string { return "sandbox" }
func (t *SandboxExecTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Run an approved non-destructive evidence proof command in a controlled runner seam.",
		Properties:  map[string]string{"command": "whoami/id/hostname/pwd/marker proof/temp proof file or upload evidence command", "args": "optional args", "workspacePath": "task workspace"},
		Required:    []string{"command"},
	}
}

func (t *SandboxExecTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	var parsed sandboxExecInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if parsed.Command == "" {
		return fmt.Errorf("command is required")
	}
	return policy.ValidateCommand(ctx, parsed.Command)
}

func (t *SandboxExecTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed sandboxExecInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}
	if parsed.Command == "" {
		return nil, fmt.Errorf("command is required")
	}
	command := append([]string{parsed.Command}, parsed.Args...)
	result := t.manager.Run(ctx, runner.RunRequest{
		TaskID:        parsed.TaskID,
		RunnerType:    "sandbox",
		ToolName:      t.Name(),
		ImageName:     "runner-sandbox",
		WorkspacePath: parsed.WorkspacePath,
		Command:       command,
		Timeout:       t.timeout,
		NetworkPolicy: "none",
	})
	return &ToolResult{
		StartedAt:  result.StartedAt,
		FinishedAt: result.FinishedAt,
		Status:     result.Status,
		Summary:    fmt.Sprintf("Sandbox command `%s` finished with status %s", result.CommandPreview, result.Status),
		Stdout:     safety.RedactSensitive(result.Stdout),
		Stderr:     safety.RedactSensitive(result.Stderr),
		Metadata: map[string]any{
			"exitCode":      result.ExitCode,
			"image":         result.ImageName,
			"networkPolicy": "none",
			"containerId":   result.ContainerID,
			"workspacePath": parsed.WorkspacePath,
			"proofContext":  parsed.ProofContext,
			"proofKind":     parsed.ProofKind,
			"target":        parsed.Target,
			"command":       result.CommandPreview,
		},
		CommandHint: result.CommandPreview,
	}, nil
}

func (t *SandboxExecTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	_ = ctx
	title := "Evidence proof command output"
	relationType := "command_output"
	target, _ := result.Metadata["target"].(string)
	proofKind, _ := result.Metadata["proofKind"].(string)
	proofContext, _ := result.Metadata["proofContext"].(bool)
	command, _ := result.Metadata["command"].(string)
	if proofContext {
		title = "Command execution PoC proof"
		relationType = "poc_result"
	}
	summary := result.Summary
	if proofContext {
		summary = fmt.Sprintf("命令执行漏洞验证产生回显：command=%s, proof=%s, output=%s", safeInline(command), safeInline(proofKind), safeInline(stdoutPreview(result.Stdout)))
	}
	return []EvidenceDraft{{
		Type:         "command_output",
		Title:        title,
		Summary:      summary,
		Raw:          result.Stdout + "\n" + result.Stderr,
		Target:       target,
		RelationType: relationType,
		Redacted:     true,
	}}, nil
}

func stdoutPreview(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "<empty>"
	}
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 160 {
		return text[:160] + "..."
	}
	return text
}

func safeInline(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "-"
	}
	return strings.ReplaceAll(text, "`", "'")
}
