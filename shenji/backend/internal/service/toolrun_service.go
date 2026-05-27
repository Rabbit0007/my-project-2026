package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"shenji/backend/internal/model"
	"shenji/backend/internal/storage"
	"shenji/backend/internal/tools"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type ToolRunService struct {
	db       *gorm.DB
	store    storage.ArtifactStore
	registry *tools.ToolRegistry
	evidence *EvidenceService
}

type ToolRunRequest struct {
	Task        model.AISecurityTask
	IterationID *uint
	IntentID    *uint
	ToolName    string
	ImageName   string
	Workspace   string
	Input       any
}

type ToolRunOutcome struct {
	ToolRun  model.AIToolRun
	Evidence []model.AIEvidence
	Result   *tools.ToolResult
}

func NewToolRunService(db *gorm.DB, store storage.ArtifactStore, registry *tools.ToolRegistry, evidence *EvidenceService) *ToolRunService {
	return &ToolRunService{db: db, store: store, registry: registry, evidence: evidence}
}

func (s *ToolRunService) Execute(ctx context.Context, req ToolRunRequest) (ToolRunOutcome, error) {
	tool, err := s.registry.MustGet(req.ToolName)
	if err != nil {
		return ToolRunOutcome{}, err
	}
	inputRaw, err := json.Marshal(req.Input)
	if err != nil {
		return ToolRunOutcome{}, err
	}
	policy := safePolicyFromTask(req.Task)
	now := time.Now().UTC()
	toolRun := model.AIToolRun{
		TaskID:             req.Task.ID,
		IterationID:        req.IterationID,
		IntentID:           req.IntentID,
		RunnerType:         tool.Kind(),
		ToolName:           tool.Name(),
		InputJSON:          datatypes.JSON(inputRaw),
		CommandPreview:     tool.Name(),
		ImageName:          req.ImageName,
		WorkspacePath:      req.Workspace,
		NetworkPolicy:      policy.NetworkPolicy,
		ResourceLimits:     mustJSON(map[string]any{"timeoutSeconds": 180, "networkPolicy": policy.NetworkPolicy}),
		Status:             model.ToolRunStatusPending,
		SafePolicySnapshot: mustJSON(policy),
		StartedAt:          now,
		CreatedAt:          now,
	}
	if err := tool.Validate(ctx, inputRaw, policy); err != nil {
		toolRun.Status = model.ToolRunStatusBlocked
		toolRun.BlockReason = err.Error()
		finished := time.Now().UTC()
		toolRun.FinishedAt = &finished
		if createErr := s.db.WithContext(ctx).Create(&toolRun).Error; createErr != nil {
			return ToolRunOutcome{}, createErr
		}
		appendAuditEvent(ctx, s.db, &req.Task.ID, "toolrun.blocked", "safepolicy", err.Error(), map[string]any{"tool": tool.Name()})
		return ToolRunOutcome{ToolRun: toolRun}, err
	}
	toolRun.Status = model.ToolRunStatusRunning
	if err := s.db.WithContext(ctx).Create(&toolRun).Error; err != nil {
		return ToolRunOutcome{}, err
	}

	result, runErr := tool.Run(ctx, inputRaw)
	finished := time.Now().UTC()
	if result == nil {
		result = &tools.ToolResult{StartedAt: now, FinishedAt: finished, Status: "failed", Stderr: fmt.Sprint(runErr), Summary: "Tool execution failed"}
	}
	toolRun.FinishedAt = &finished
	toolRun.CommandPreview = result.CommandHint
	if toolRun.ImageName == "" {
		if image, ok := result.Metadata["image"].(string); ok {
			toolRun.ImageName = image
		}
	}
	if toolRun.ContainerID == "" {
		if containerID, ok := result.Metadata["containerId"].(string); ok {
			toolRun.ContainerID = containerID
		}
	}
	if toolRun.WorkspacePath == "" {
		if workspacePath, ok := result.Metadata["workspacePath"].(string); ok {
			toolRun.WorkspacePath = workspacePath
		}
	}
	if result.Status == "success" {
		toolRun.Status = model.ToolRunStatusSuccess
	} else if result.Status == "timeout" {
		toolRun.Status = model.ToolRunStatusTimeout
	} else {
		toolRun.Status = model.ToolRunStatusFailed
	}
	stdoutRef, _, _ := s.store.PutText(ctx, fmt.Sprintf("task-%d/toolruns/%d-stdout.txt", req.Task.ID, toolRun.ID), result.Stdout)
	stderrRef, _, _ := s.store.PutText(ctx, fmt.Sprintf("task-%d/toolruns/%d-stderr.txt", req.Task.ID, toolRun.ID), result.Stderr)
	toolRun.StdoutRef = stdoutRef
	toolRun.StderrRef = stderrRef
	toolRun.ArtifactRefs = mustJSON(result.Artifacts)
	if err := s.db.WithContext(ctx).Save(&toolRun).Error; err != nil {
		return ToolRunOutcome{}, err
	}
	if runErr != nil {
		return ToolRunOutcome{ToolRun: toolRun, Result: result}, runErr
	}
	drafts, err := tool.ExtractEvidence(ctx, result)
	if err != nil {
		return ToolRunOutcome{ToolRun: toolRun, Result: result}, err
	}
	evidenceItems := make([]model.AIEvidence, 0, len(drafts))
	for _, draft := range drafts {
		item, err := s.evidence.CreateFromDraft(ctx, req.Task.ID, &toolRun.ID, draft)
		if err != nil {
			return ToolRunOutcome{ToolRun: toolRun, Result: result, Evidence: evidenceItems}, err
		}
		evidenceItems = append(evidenceItems, item)
	}
	appendAuditEvent(ctx, s.db, &req.Task.ID, "toolrun.completed", "runner", result.Summary, map[string]any{"tool": tool.Name(), "status": toolRun.Status})
	return ToolRunOutcome{ToolRun: toolRun, Evidence: evidenceItems, Result: result}, nil
}

func (s *ToolRunService) ListByTask(ctx context.Context, taskID uint) ([]model.AIToolRun, error) {
	var runs []model.AIToolRun
	err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at desc").Find(&runs).Error
	return runs, err
}
