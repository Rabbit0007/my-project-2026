package service

import (
	"context"
	"fmt"
	"strings"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type ContextBuilder struct {
	db *gorm.DB
}

type AgentContext struct {
	Task              model.AISecurityTask     `json:"task"`
	Intent            *model.AIIntent          `json:"intent,omitempty"`
	KeyFacts          []model.AIBlackboardNode `json:"keyFacts"`
	RecentEvidence    []model.AIEvidence       `json:"recentEvidence"`
	OpenFindings      []model.AIFinding        `json:"openFindings"`
	AuthorizationView string                   `json:"authorizationView"`
	RecommendedNext   string                   `json:"recommendedNext"`
	// Enhanced fields for Cairn-style reasoning
	MissingFields   []string               `json:"missingFields,omitempty"`
	FailedToolRuns  []FailedToolRunSummary `json:"failedToolRuns,omitempty"`
	FileStructure   []string               `json:"fileStructure,omitempty"`
	SourceSinkPairs []SourceSinkPair       `json:"sourceSinkPairs,omitempty"`
	Capabilities    []string               `json:"capabilities,omitempty"`
	GraphSummary    *GraphSummary          `json:"graphSummary,omitempty"`
}

type FailedToolRunSummary struct {
	ToolName string `json:"toolName"`
	FilePath string `json:"filePath,omitempty"`
	Error    string `json:"error"`
}

type SourceSinkPair struct {
	FilePath   string `json:"filePath"`
	SourceType string `json:"sourceType"`
	SinkType   string `json:"sinkType"`
}

func NewContextBuilder(db *gorm.DB) *ContextBuilder {
	return &ContextBuilder{db: db}
}

func (b *ContextBuilder) Build(ctx context.Context, taskID uint, intent *model.AIIntent, maxItems int) (AgentContext, error) {
	if maxItems <= 0 || maxItems > 80 {
		maxItems = 30
	}
	var task model.AISecurityTask
	if err := b.db.WithContext(ctx).First(&task, taskID).Error; err != nil {
		return AgentContext{}, err
	}
	var facts []model.AIBlackboardNode
	if err := b.db.WithContext(ctx).
		Where("task_id = ? AND status = ?", taskID, model.BlackboardNodeStatusActive).
		Order("importance_score desc, last_seen_at desc").
		Limit(maxItems).
		Find(&facts).Error; err != nil {
		return AgentContext{}, err
	}
	var evidence []model.AIEvidence
	if err := b.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at desc").Limit(20).Find(&evidence).Error; err != nil {
		return AgentContext{}, err
	}
	var findings []model.AIFinding
	if err := b.db.WithContext(ctx).Where("task_id = ? AND status NOT IN ?", taskID, []string{model.FindingStatusFalsePositive, model.FindingStatusFixed}).Order("created_at desc").Limit(20).Find(&findings).Error; err != nil {
		return AgentContext{}, err
	}
	policy := safePolicyFromTask(task)
	recommended := "Continue collecting evidence through registered tools; do not read raw L0 artifacts unless required."
	if intent != nil {
		recommended = "Execute current intent: " + intent.Objective
	}

	// Enhanced: collect missing fields from hint nodes
	var hintNodes []model.AIBlackboardNode
	_ = b.db.WithContext(ctx).Where("task_id = ? AND node_type = ? AND status = ?", taskID, "hint", model.BlackboardNodeStatusActive).Limit(5).Find(&hintNodes).Error
	missingFields := []string{}
	for _, hint := range hintNodes {
		if strings.Contains(hint.Summary, "Missing") || strings.Contains(hint.Summary, "missing") {
			missingFields = append(missingFields, hint.Summary)
		}
	}

	// Enhanced: collect failed tool runs
	var failedRuns []model.AIToolRun
	_ = b.db.WithContext(ctx).Where("task_id = ? AND status = ?", taskID, "failed").Order("started_at desc").Limit(5).Find(&failedRuns).Error
	failedSummaries := make([]FailedToolRunSummary, 0, len(failedRuns))
	for _, run := range failedRuns {
		failedSummaries = append(failedSummaries, FailedToolRunSummary{
			ToolName: run.ToolName,
			FilePath: run.WorkspacePath,
			Error:    run.BlockReason,
		})
	}

	// Enhanced: collect file structure from evidence
	fileStructure := []string{}
	var fileEvidence []model.AIEvidence
	_ = b.db.WithContext(ctx).Where("task_id = ? AND file_path != ''", taskID).Select("DISTINCT file_path").Limit(20).Find(&fileEvidence).Error
	for _, ev := range fileEvidence {
		if ev.FilePath != "" {
			fileStructure = append(fileStructure, ev.FilePath)
		}
	}

	// Enhanced: collect capabilities
	var caps []model.AICapability
	_ = b.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at desc").Limit(10).Find(&caps).Error
	capStrings := make([]string, 0, len(caps))
	for _, cap := range caps {
		capStrings = append(capStrings, fmt.Sprintf("[%s] %s: %s", cap.Strength, cap.CapabilityType, cap.Target))
	}

	graphSummary := NewCairnLoop(b.db, NewBlackboardService(b.db), NewIntentService(b.db), nil, NewFindingService(b.db), nil, nil, nil, nil).
		BuildGraphSummary(ctx, task, 0, 0)

	return AgentContext{
		Task:              task,
		Intent:            intent,
		KeyFacts:          facts,
		RecentEvidence:    evidence,
		OpenFindings:      findings,
		AuthorizationView: fmt.Sprintf("Non-destructive evidence proof policy, network policy %s", policy.NetworkPolicy),
		RecommendedNext:   recommended,
		MissingFields:     missingFields,
		FailedToolRuns:    failedSummaries,
		FileStructure:     fileStructure,
		Capabilities:      capStrings,
		GraphSummary:      &graphSummary,
	}, nil
}
