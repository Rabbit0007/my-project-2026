package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// CairnLoop implements Rabbit's core state-space loop:
//
//	Fact / Observation / Evidence -> Hypothesis / Intent -> Runner / Explore
//	-> Evidence / New Fact -> Capability / NegativeFact / UnverifiedRisk
//	-> Next Intent.
//
// Tools only observe or validate. Findings are delivery artifacts, Contracts
// are report quality gates, Reports are outputs, and the graph exploration
// loop is the product.
type CairnLoop struct {
	db         *gorm.DB
	blackboard *BlackboardService
	intents    *IntentService
	toolRuns   *ToolRunService
	findings   *FindingService
	contracts  *ContractService
	models     *ModelRuntimeService
	reports    *ReportService
	compactor  *BlackboardCompactor
}

// ExploreResult is the structured output of executing a single Intent.
type ExploreResult struct {
	IntentID         uint               `json:"intent_id"`
	Status           string             `json:"status"` // success / failed / partial / blocked
	Facts            []GraphFact        `json:"facts"`
	NegativeFacts    []GraphFact        `json:"negative_facts"`
	Evidence         []model.AIEvidence `json:"evidence"`
	Capabilities     []CapabilityDraft  `json:"capabilities"`
	SuggestedIntents []IntentSuggestion `json:"suggested_next_intents"`
	Notes            string             `json:"notes"`
}

// GraphDelta is the normalized state change packet produced by Bootstrap,
// Reason, or Explore. Workers may still use the legacy data wrapper, but the
// orchestrator maps it into this shape before mutating the graph.
type GraphDelta struct {
	IntentID                uint               `json:"intent_id,omitempty"`
	NewFacts                []GraphFact        `json:"new_facts"`
	UpdatedFacts            []GraphFact        `json:"updated_facts"`
	NewIntents              []IntentSuggestion `json:"new_intents"`
	CompletedIntents        []uint             `json:"completed_intents"`
	NewEvidence             []model.AIEvidence `json:"new_evidence"`
	NewNegativeFacts        []GraphFact        `json:"new_negative_facts"`
	NewCapabilityCandidates []CapabilityDraft  `json:"new_capability_candidates"`
	VerifiedCapabilities    []CapabilityDraft  `json:"verified_capabilities"`
	UpdatedCoverage         []CoverageUpdate   `json:"updated_coverage"`
	GoalStateUpdate         map[string]any     `json:"goal_state_update,omitempty"`
	Diagnostics             []string           `json:"diagnostics"`
	Errors                  []string           `json:"errors"`
}

// GraphFact is a structured fact to write to the blackboard.
type GraphFact struct {
	NodeType string `json:"node_type"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
}

// CapabilityDraft is a capability discovered during exploration.
type CapabilityDraft struct {
	CapabilityType string `json:"capability_type"`
	Target         string `json:"target"`
	Strength       string `json:"strength"` // suspected / observed / verified
	ProofSummary   string `json:"proof_summary"`
	EvidenceIDs    []uint `json:"evidence_ids"`
	CanAdvanceGoal bool   `json:"can_advance_goal"`
}

// IntentSuggestion is a structured intent suggestion from Reasoner or Explore.
type IntentSuggestion struct {
	IntentType      string   `json:"intent_type"`
	Hypothesis      string   `json:"hypothesis"`
	Objective       string   `json:"objective"`
	SuccessCriteria string   `json:"success_criteria"`
	FailureCriteria string   `json:"failure_criteria"`
	AllowedTools    []string `json:"allowed_tools"`
	RiskLevel       string   `json:"risk_level"`
	Priority        int      `json:"priority"`
	ParentNodeIDs   []uint   `json:"parent_node_ids"`
}

type CoverageUpdate struct {
	SurfaceID    string `json:"surface_id"`
	SurfaceType  string `json:"surface_type"`
	Entrypoint   string `json:"entrypoint"`
	Status       string `json:"status"`
	Priority     string `json:"priority"`
	Reason       string `json:"reason"`
	EvidenceRefs []uint `json:"evidence_refs"`
	NodeRefs     []uint `json:"node_refs"`
}

// ReasonerOutput is the structured output from the Reasoner phase.
type ReasonerOutput struct {
	AnalysisSummary      string             `json:"analysis_summary"`
	GoalProgress         string             `json:"goal_progress"`
	SelectedIntents      []IntentSuggestion `json:"selected_intents"`
	DeprioritizedIntents []struct {
		Reason string `json:"reason"`
	} `json:"deprioritized_intents"`
	ShouldFinalize bool   `json:"should_finalize"`
	FinalizeReason string `json:"finalize_reason"`
}

// GraphSummary is the compressed graph state fed to the Reasoner.
type GraphSummary struct {
	TaskID                  uint                       `json:"task_id"`
	TaskType                string                     `json:"task_type"`
	Goal                    string                     `json:"goal"`
	GoalState               GraphGoalSummary           `json:"goal_state"`
	CoverageState           GraphCoverageState         `json:"coverage_state"`
	ConfirmedFacts          []GraphFactSummary         `json:"confirmed_facts"`
	OpenIntents             []GraphIntentSummary       `json:"open_intents"`
	RecentEvidence          []GraphEvidenceSummary     `json:"recent_evidence"`
	StructuredNegativeFacts []GraphNegativeFactSummary `json:"structured_negative_facts"`
	CapabilityCandidates    []GraphCapabilitySummary   `json:"capability_candidates"`
	VerifiedCapabilities    []GraphCapabilitySummary   `json:"verified_capabilities"`
	Unknowns                []string                   `json:"unknowns"`
	Hints                   []GraphHintSummary         `json:"hints"`
	BudgetState             GraphBudgetState           `json:"budget_state"`
	SurfaceFacts            []string                   `json:"surface_facts"`
	Fingerprints            []string                   `json:"fingerprints"`
	CodeFacts               []string                   `json:"code_facts"`
	BusinessFacts           []string                   `json:"business_facts"`
	SecretFacts             []string                   `json:"secret_facts"`
	Capabilities            []string                   `json:"capabilities"`
	PendingIntents          []string                   `json:"pending_intents"`
	NegativeFacts           []string                   `json:"negative_facts"`
	EnvironmentModel        string                     `json:"environment_model"`
	EvidenceCount           int                        `json:"evidence_count"`
	IterationBudget         int                        `json:"iteration_budget"`
	IterationsCurrent       int                        `json:"iterations_current"`
}

type GraphGoalSummary struct {
	TaskID                         uint                 `json:"task_id"`
	Type                           string               `json:"type"`
	GoalType                       string               `json:"goal_type"`
	Description                    string               `json:"description"`
	SuccessCriteria                []string             `json:"success_criteria"`
	Status                         string               `json:"status"`
	VerifiedCapabilityCount        int                  `json:"verified_capability_count"`
	UnresolvedHighPrioritySurfaces int                  `json:"unresolved_high_priority_surfaces"`
	OpenHighPriorityIntents        int                  `json:"open_high_priority_intents"`
	CoverageSummary                GraphCoverageSummary `json:"coverage_summary"`
	StopReason                     string               `json:"stop_reason"`
	ShouldContinue                 bool                 `json:"should_continue"`
}

type GraphFactSummary struct {
	ID               uint   `json:"id"`
	Kind             string `json:"kind"`
	Subject          string `json:"subject"`
	Summary          string `json:"summary"`
	EvidenceRefs     []uint `json:"evidence_refs"`
	ConfidenceSource string `json:"confidence_source"`
}

type GraphIntentSummary struct {
	ID       uint           `json:"id"`
	Kind     string         `json:"kind"`
	Goal     string         `json:"goal"`
	Reason   string         `json:"reason"`
	Priority float64        `json:"priority"`
	Status   string         `json:"status"`
	Target   map[string]any `json:"target,omitempty"`
}

type GraphEvidenceSummary struct {
	ID        uint   `json:"id"`
	Kind      string `json:"kind"`
	Relation  string `json:"relation"`
	Target    string `json:"target"`
	File      string `json:"file,omitempty"`
	LineStart *int   `json:"line_start,omitempty"`
	LineEnd   *int   `json:"line_end,omitempty"`
	Summary   string `json:"summary"`
}

type GraphNegativeFactSummary struct {
	ID           uint   `json:"id"`
	Kind         string `json:"kind"`
	Summary      string `json:"summary"`
	TestedPath   string `json:"tested_path"`
	Effect       string `json:"effect"`
	EvidenceRefs []uint `json:"evidence_refs"`
}

type GraphCapabilitySummary struct {
	ID             uint   `json:"id"`
	Status         string `json:"status"`
	Summary        string `json:"summary"`
	Impact         string `json:"impact"`
	CapabilityType string `json:"capability_type"`
	Target         string `json:"target"`
	FactRefs       []uint `json:"fact_refs"`
	EvidenceRefs   []uint `json:"evidence_refs"`
}

type GraphHintSummary struct {
	ID      uint    `json:"id"`
	Summary string  `json:"summary"`
	Scope   string  `json:"scope"`
	Weight  float64 `json:"weight"`
}

type GraphBudgetState struct {
	MaxIterations       int `json:"max_iterations"`
	CurrentIteration    int `json:"current_iteration"`
	RemainingIterations int `json:"remaining_iterations"`
}

type GraphCoverageState struct {
	ScopeSummary                   GraphScopeSummary      `json:"scope_summary"`
	SurfaceCoverage                []GraphSurfaceCoverage `json:"surface_coverage"`
	UnresolvedHighPrioritySurfaces int                    `json:"unresolved_high_priority_surfaces"`
	OpenHighPriorityIntents        int                    `json:"open_high_priority_intents"`
	VerifiedCapabilityCount        int                    `json:"verified_capability_count"`
	RefutedPathCount               int                    `json:"refuted_path_count"`
	BlockedPathCount               int                    `json:"blocked_path_count"`
	InconclusivePathCount          int                    `json:"inconclusive_path_count"`
	RecentProgress                 GraphRecentProgress    `json:"recent_progress"`
}

type GraphScopeSummary struct {
	Targets         []string `json:"targets"`
	EntrypointCount int      `json:"entrypoint_count"`
	SurfaceCount    int      `json:"surface_count"`
	AuthContexts    []string `json:"auth_contexts"`
	ExcludedPaths   []string `json:"excluded_paths"`
}

type GraphSurfaceCoverage struct {
	SurfaceID        string   `json:"surface_id"`
	SurfaceType      string   `json:"surface_type"`
	Entrypoint       string   `json:"entrypoint"`
	Status           string   `json:"status"`
	Priority         string   `json:"priority"`
	RiskSignals      []string `json:"risk_signals"`
	OpenIntentRefs   []uint   `json:"open_intent_refs"`
	FactRefs         []uint   `json:"fact_refs"`
	EvidenceRefs     []uint   `json:"evidence_refs"`
	NegativeFactRefs []uint   `json:"negative_fact_refs"`
	CapabilityRefs   []uint   `json:"capability_refs"`
	LastExploredAt   string   `json:"last_explored_at"`
	ResolutionReason string   `json:"resolution_reason"`
}

type GraphCoverageSummary struct {
	TotalSurfaces        int `json:"total_surfaces"`
	ExploredSurfaces     int `json:"explored_surfaces"`
	ResolvedSurfaces     int `json:"resolved_surfaces"`
	ResolvedVerified     int `json:"resolved_verified"`
	ResolvedRefuted      int `json:"resolved_refuted"`
	BlockedSurfaces      int `json:"blocked_surfaces"`
	InconclusiveSurfaces int `json:"inconclusive_surfaces"`
	OutOfScopeSurfaces   int `json:"out_of_scope"`
}

type GraphRecentProgress struct {
	NewFactsLastN        int `json:"new_facts_last_n"`
	NewEvidenceLastN     int `json:"new_evidence_last_n"`
	NewCapabilitiesLastN int `json:"new_capabilities_last_n"`
	NewSurfacesLastN     int `json:"new_surfaces_last_n"`
}

type CapabilityPromotionGate struct {
	Allowed       bool     `json:"allowed"`
	Missing       []string `json:"missing"`
	EvidenceRefs  []uint   `json:"evidence_refs"`
	FactRefs      []uint   `json:"fact_refs"`
	ValidationRef string   `json:"validation_ref"`
	Relations     []string `json:"relations"`
}

type GraphDeltaSummary struct {
	NewFacts                int `json:"new_facts"`
	NewEvidence             int `json:"new_evidence"`
	NewNegativeFacts        int `json:"new_negative_facts"`
	NewCapabilityCandidates int `json:"new_capability_candidates"`
	NewIntents              int `json:"new_intents"`
	UpdatedCoverage         int `json:"updated_coverage"`
}

type GraphSearchLoopDiagnostic struct {
	TaskID              uint                     `json:"task_id"`
	Iteration           int                      `json:"iteration"`
	Phase               string                   `json:"phase"`
	GoalStatus          string                   `json:"goal_status"`
	SelectedIntent      *GraphIntentSummary      `json:"selected_intent,omitempty"`
	ToolsCalled         []string                 `json:"tools_called"`
	GraphDeltaSummary   GraphDeltaSummary        `json:"graph_delta_summary"`
	PromotionGateResult *CapabilityPromotionGate `json:"promotion_gate_result,omitempty"`
	CoverageState       *GraphCoverageState      `json:"coverage_state,omitempty"`
	GoalState           *GraphGoalSummary        `json:"goal_state,omitempty"`
	StopReason          string                   `json:"stop_reason"`
}

var requiredCapabilityEvidenceRelations = []string{
	"entrypoint_or_exposure",
	"impact_sink_or_security_effect",
	"reachability_or_trigger_path",
	"guard_or_control_analysis",
	"reproduction_or_recheck_path",
}

// NewCairnLoop creates a new Cairn-style loop.
func NewCairnLoop(db *gorm.DB, bb *BlackboardService, intents *IntentService, toolRuns *ToolRunService, findings *FindingService, contracts *ContractService, models *ModelRuntimeService, reports *ReportService, compactor *BlackboardCompactor) *CairnLoop {
	return &CairnLoop{
		db: db, blackboard: bb, intents: intents, toolRuns: toolRuns,
		findings: findings, contracts: contracts, models: models,
		reports: reports, compactor: compactor,
	}
}

// BuildGraphSummary creates a compressed view of the current graph state for the Reasoner.
func (l *CairnLoop) BuildGraphSummary(ctx context.Context, task model.AISecurityTask, iterationNo int, maxIterations int) GraphSummary {
	coverageState := l.BuildCoverageState(ctx, task, iterationNo)
	goalState := l.BuildCoverageGoalState(task, coverageState, iterationNo, maxIterations, "")
	summary := GraphSummary{
		TaskID:            task.ID,
		TaskType:          task.TaskType,
		Goal:              task.Objective,
		GoalState:         goalState,
		CoverageState:     coverageState,
		IterationBudget:   maxIterations,
		IterationsCurrent: iterationNo,
		BudgetState: GraphBudgetState{
			MaxIterations:       maxIterations,
			CurrentIteration:    iterationNo,
			RemainingIterations: maxInt(0, maxIterations-iterationNo),
		},
	}

	var nodes []model.AIBlackboardNode
	_ = l.db.WithContext(ctx).
		Where("task_id = ? AND status = ?", task.ID, model.BlackboardNodeStatusActive).
		Order("importance_score desc").
		Limit(60).
		Find(&nodes).Error

	for _, node := range nodes {
		line := node.Title
		if node.Summary != "" && len(node.Summary) < 100 {
			line += ": " + node.Summary
		}
		if isConfirmedFactNode(node.NodeType) {
			summary.ConfirmedFacts = append(summary.ConfirmedFacts, GraphFactSummary{
				ID:               node.ID,
				Kind:             node.NodeType,
				Subject:          node.Title,
				Summary:          firstNonEmpty(node.Summary, node.Title),
				EvidenceRefs:     uintListFromJSON(node.EvidenceRefs),
				ConfidenceSource: graphConfidenceSource(node.EvidenceRefs),
			})
		}
		switch node.NodeType {
		case "origin", "goal":
			// skip, already in summary
		case "surface_fact", "fact":
			if strings.Contains(strings.ToLower(node.Title), "surface") || strings.Contains(strings.ToLower(node.Title), "endpoint") || strings.Contains(strings.ToLower(node.Title), "http") {
				summary.SurfaceFacts = append(summary.SurfaceFacts, line)
			} else if strings.Contains(strings.ToLower(node.Title), "code") || strings.Contains(strings.ToLower(node.Title), "source") || strings.Contains(strings.ToLower(node.Title), "sink") {
				summary.CodeFacts = append(summary.CodeFacts, line)
			} else {
				summary.SurfaceFacts = append(summary.SurfaceFacts, line)
			}
		case "technology_fingerprint":
			summary.Fingerprints = append(summary.Fingerprints, line)
		case "code_fact":
			summary.CodeFacts = append(summary.CodeFacts, line)
		case "business_fact":
			summary.BusinessFacts = append(summary.BusinessFacts, line)
		case "secret_fact", "credential_fact":
			summary.SecretFacts = append(summary.SecretFacts, line)
		case "negative_fact":
			summary.NegativeFacts = append(summary.NegativeFacts, line)
			summary.StructuredNegativeFacts = append(summary.StructuredNegativeFacts, GraphNegativeFactSummary{
				ID:           node.ID,
				Kind:         "negative_fact",
				Summary:      firstNonEmpty(node.Summary, node.Title),
				TestedPath:   graphNodeContentString(node.ContentJSON, "testedPath", "tested_path", "target"),
				Effect:       firstNonEmpty(graphNodeContentString(node.ContentJSON, "effect"), "Avoid repeating this path unless new facts appear."),
				EvidenceRefs: uintListFromJSON(node.EvidenceRefs),
			})
		case "capability":
			summary.Capabilities = append(summary.Capabilities, line)
		}
	}

	// Add capabilities from the capability table
	var caps []model.AICapability
	_ = l.db.WithContext(ctx).Where("task_id = ?", task.ID).Order("created_at desc").Limit(20).Find(&caps).Error
	for _, cap := range caps {
		summary.Capabilities = append(summary.Capabilities, fmt.Sprintf("[%s] %s (%s) - %s", cap.Strength, cap.CapabilityType, cap.Target, cap.ProofSummary))
		item := GraphCapabilitySummary{
			ID:             cap.ID,
			Status:         cap.Strength,
			Summary:        cap.ProofSummary,
			Impact:         impactForCapability(cap.CapabilityType),
			CapabilityType: cap.CapabilityType,
			Target:         cap.Target,
			FactRefs:       uintListFromJSON(cap.SourceNodeIDs),
			EvidenceRefs:   uintListFromJSON(cap.EvidenceRefs),
		}
		if cap.Strength == model.StrengthVerified {
			summary.VerifiedCapabilities = append(summary.VerifiedCapabilities, item)
		} else {
			summary.CapabilityCandidates = append(summary.CapabilityCandidates, item)
		}
	}

	// Add pending intents
	var pendingIntents []model.AIIntent
	_ = l.db.WithContext(ctx).Where("task_id = ? AND status = ?", task.ID, model.IntentStatusPending).Order("priority_score desc").Limit(10).Find(&pendingIntents).Error
	for _, intent := range pendingIntents {
		summary.PendingIntents = append(summary.PendingIntents, fmt.Sprintf("[%s] %s", intent.IntentType, intent.Title))
		constraints := map[string]any{}
		_ = json.Unmarshal(intent.ConstraintsJSON, &constraints)
		summary.OpenIntents = append(summary.OpenIntents, GraphIntentSummary{
			ID:       intent.ID,
			Kind:     intent.IntentType,
			Goal:     firstNonEmpty(intent.Objective, intent.Title),
			Reason:   intent.CreatedReason,
			Priority: intent.PriorityScore,
			Status:   intent.Status,
			Target:   constraints,
		})
	}

	var recentEvidence []model.AIEvidence
	_ = l.db.WithContext(ctx).Where("task_id = ?", task.ID).Order("created_at desc").Limit(12).Find(&recentEvidence).Error
	for _, item := range recentEvidence {
		summary.RecentEvidence = append(summary.RecentEvidence, GraphEvidenceSummary{
			ID:        item.ID,
			Kind:      item.EvidenceType,
			Relation:  item.RelationType,
			Target:    item.Target,
			File:      item.FilePath,
			LineStart: item.LineStart,
			LineEnd:   item.LineEnd,
			Summary:   item.Summary,
		})
	}

	var negativeRows []model.AINegativeFact
	_ = l.db.WithContext(ctx).Where("task_id = ?", task.ID).Order("created_at desc").Limit(12).Find(&negativeRows).Error
	for _, item := range negativeRows {
		summary.StructuredNegativeFacts = append(summary.StructuredNegativeFacts, GraphNegativeFactSummary{
			ID:           item.ID,
			Kind:         "negative_fact",
			Summary:      item.Reason,
			TestedPath:   item.TestedPath,
			Effect:       "Do not repeat this path unless new facts or authorization context appears.",
			EvidenceRefs: uintListFromJSON(item.EvidenceRefs),
		})
	}

	var hints []model.AIBlackboardNode
	_ = l.db.WithContext(ctx).Where("task_id = ? AND node_type = ? AND status = ?", task.ID, "hint", model.BlackboardNodeStatusActive).Order("importance_score desc").Limit(10).Find(&hints).Error
	for _, hint := range hints {
		summary.Hints = append(summary.Hints, GraphHintSummary{ID: hint.ID, Summary: firstNonEmpty(hint.Summary, hint.Title), Scope: hint.SourceType, Weight: hint.ImportanceScore})
	}
	summary.Unknowns = inferGraphUnknowns(summary)

	var env model.AIEnvironmentModel
	if err := l.db.WithContext(ctx).Where("task_id = ?", task.ID).First(&env).Error; err == nil && len(env.ModelJSON) > 0 {
		var envDoc map[string]any
		if json.Unmarshal(env.ModelJSON, &envDoc) == nil {
			summary.EnvironmentModel = summarizeEnvironmentModel(envDoc)
		}
	}

	// Evidence count
	var evidenceCount int64
	_ = l.db.WithContext(ctx).Model(&model.AIEvidence{}).Where("task_id = ?", task.ID).Count(&evidenceCount).Error
	summary.EvidenceCount = int(evidenceCount)

	// Truncate lists to keep prompt small
	summary.SurfaceFacts = truncateStringList(summary.SurfaceFacts, 10)
	summary.CodeFacts = truncateStringList(summary.CodeFacts, 10)
	summary.Fingerprints = truncateStringList(summary.Fingerprints, 5)
	summary.BusinessFacts = truncateStringList(summary.BusinessFacts, 5)
	summary.SecretFacts = truncateStringList(summary.SecretFacts, 5)
	summary.Capabilities = truncateStringList(summary.Capabilities, 8)
	summary.NegativeFacts = truncateStringList(summary.NegativeFacts, 5)
	summary.PendingIntents = truncateStringList(summary.PendingIntents, 5)
	summary.ConfirmedFacts = truncateGraphFacts(summary.ConfirmedFacts, 20)
	summary.OpenIntents = truncateGraphIntents(summary.OpenIntents, 10)
	summary.RecentEvidence = truncateGraphEvidence(summary.RecentEvidence, 12)
	summary.StructuredNegativeFacts = truncateGraphNegativeFacts(summary.StructuredNegativeFacts, 12)
	summary.CapabilityCandidates = truncateGraphCapabilities(summary.CapabilityCandidates, 8)
	summary.VerifiedCapabilities = truncateGraphCapabilities(summary.VerifiedCapabilities, 8)
	summary.Hints = truncateGraphHints(summary.Hints, 8)

	return summary
}

func (l *CairnLoop) BuildCoverageGoalState(task model.AISecurityTask, coverage GraphCoverageState, iterationNo int, maxIterations int, stopReason string) GraphGoalSummary {
	status := "active"
	shouldContinue := true
	remaining := maxInt(0, maxIterations-iterationNo)
	if maxIterations > 0 && iterationNo >= maxIterations {
		status = "budget_exhausted"
		shouldContinue = false
		if stopReason == "" {
			stopReason = "iteration budget exhausted"
		}
	} else if coverage.OpenHighPriorityIntents == 0 && coverage.UnresolvedHighPrioritySurfaces == 0 && coverage.ScopeSummary.SurfaceCount > 0 {
		status = "coverage_sufficient"
		shouldContinue = false
		if stopReason == "" {
			stopReason = "high-priority surfaces resolved and no high-priority intents remain"
		}
	} else if coverage.ScopeSummary.SurfaceCount == 0 && coverage.OpenHighPriorityIntents == 0 && coverage.RecentProgress.NewFactsLastN == 0 && coverage.RecentProgress.NewEvidenceLastN == 0 && coverage.RecentProgress.NewCapabilitiesLastN == 0 && coverage.RecentProgress.NewSurfacesLastN == 0 && remaining == 0 {
		status = "plateau"
		shouldContinue = false
		if stopReason == "" {
			stopReason = "no coverage state or recent graph progress remains"
		}
	}
	return GraphGoalSummary{
		TaskID:      task.ID,
		Type:        "scope_bounded_security_discovery",
		GoalType:    "scope_bounded_security_discovery",
		Description: task.Objective,
		SuccessCriteria: []string{
			"High-priority attack surfaces are verified, refuted, blocked, out of scope, or marked inconclusive.",
			"Evidence-backed VerifiedCapability items are output artifacts, not global stop conditions.",
			"Exploration may stop only on coverage sufficiency, budget exhaustion, blocked scope, or plateau.",
		},
		Status:                         status,
		VerifiedCapabilityCount:        coverage.VerifiedCapabilityCount,
		UnresolvedHighPrioritySurfaces: coverage.UnresolvedHighPrioritySurfaces,
		OpenHighPriorityIntents:        coverage.OpenHighPriorityIntents,
		CoverageSummary:                coverageSummaryFromState(coverage),
		StopReason:                     stopReason,
		ShouldContinue:                 shouldContinue,
	}
}

func (l *CairnLoop) BuildCoverageState(ctx context.Context, task model.AISecurityTask, iterationNo int) GraphCoverageState {
	state := GraphCoverageState{}
	var targets []model.AITaskTarget
	_ = l.db.WithContext(ctx).Where("task_id = ?", task.ID).Find(&targets).Error
	for _, target := range targets {
		if target.ScopeStatus == "in_scope" {
			state.ScopeSummary.Targets = append(state.ScopeSummary.Targets, target.Value)
		} else {
			state.ScopeSummary.ExcludedPaths = append(state.ScopeSummary.ExcludedPaths, target.Value)
		}
	}
	state.ScopeSummary.AuthContexts = authContextsFromTask(task)

	var items []model.AICoverageItem
	_ = l.db.WithContext(ctx).Where("task_id = ?", task.ID).Order("updated_at desc, id asc").Find(&items).Error
	var pendingIntents []model.AIIntent
	_ = l.db.WithContext(ctx).Where("task_id = ? AND status = ?", task.ID, model.IntentStatusPending).Find(&pendingIntents).Error
	var caps []model.AICapability
	_ = l.db.WithContext(ctx).Where("task_id = ?", task.ID).Find(&caps).Error
	var negatives []model.AINegativeFact
	_ = l.db.WithContext(ctx).Where("task_id = ?", task.ID).Find(&negatives).Error

	for _, cap := range caps {
		if cap.Strength == model.StrengthVerified {
			state.VerifiedCapabilityCount++
		}
	}
	for _, item := range items {
		surface := l.coverageItemToGraphSurface(item, pendingIntents, caps, negatives)
		state.SurfaceCoverage = append(state.SurfaceCoverage, surface)
		state.ScopeSummary.SurfaceCount++
		if surface.SurfaceType == model.NodeEntrypoint || strings.Contains(surface.SurfaceType, "flow") || strings.Contains(surface.Entrypoint, "/") {
			state.ScopeSummary.EntrypointCount++
		}
		if isUnresolvedHighPrioritySurface(surface) {
			state.UnresolvedHighPrioritySurfaces++
		}
		switch normalizeCoverageStatus(surface.Status) {
		case model.CoverageStatusResolvedRefuted:
			state.RefutedPathCount++
		case model.CoverageStatusBlocked:
			state.BlockedPathCount++
		case model.CoverageStatusInconclusive:
			state.InconclusivePathCount++
		}
	}
	state.OpenHighPriorityIntents = countOpenHighPriorityIntents(pendingIntents, state.SurfaceCoverage)
	state.RecentProgress = l.recentCoverageProgress(ctx, task.ID)
	return state
}

func (l *CairnLoop) coverageItemToGraphSurface(item model.AICoverageItem, intents []model.AIIntent, caps []model.AICapability, negatives []model.AINegativeFact) GraphSurfaceCoverage {
	entrypoint := firstNonEmpty(item.TargetRef, item.Name)
	priority := normalizeCoveragePriority(item.RiskHint)
	surface := GraphSurfaceCoverage{
		SurfaceID:        fmt.Sprintf("surface_%d", item.ID),
		SurfaceType:      normalizeSurfaceType(item.Category),
		Entrypoint:       entrypoint,
		Status:           normalizeCoverageStatus(item.Status),
		Priority:         priority,
		RiskSignals:      riskSignalsFromCoverageItem(item),
		FactRefs:         uintListFromJSON(item.NodeRefs),
		EvidenceRefs:     uintListFromJSON(item.EvidenceRefs),
		LastExploredAt:   item.UpdatedAt.Format(time.RFC3339),
		ResolutionReason: item.Reason,
	}
	for _, intent := range intents {
		if surfaceMatchesText(surface, intent.Title+" "+intent.Objective+" "+string(intent.ConstraintsJSON)) {
			surface.OpenIntentRefs = append(surface.OpenIntentRefs, intent.ID)
		}
	}
	for _, cap := range caps {
		if surfaceMatchesText(surface, cap.Target+" "+cap.ProofSummary) {
			surface.CapabilityRefs = append(surface.CapabilityRefs, cap.ID)
		}
	}
	for _, nf := range negatives {
		if surfaceMatchesText(surface, nf.TestedPath+" "+nf.Title+" "+nf.Reason) {
			surface.NegativeFactRefs = append(surface.NegativeFactRefs, nf.ID)
		}
	}
	return surface
}

func coverageSummaryFromState(state GraphCoverageState) GraphCoverageSummary {
	summary := GraphCoverageSummary{TotalSurfaces: state.ScopeSummary.SurfaceCount}
	for _, surface := range state.SurfaceCoverage {
		switch normalizeCoverageStatus(surface.Status) {
		case model.CoverageStatusExploring:
			summary.ExploredSurfaces++
		case model.CoverageStatusResolvedVerified:
			summary.ExploredSurfaces++
			summary.ResolvedSurfaces++
			summary.ResolvedVerified++
		case model.CoverageStatusResolvedRefuted:
			summary.ExploredSurfaces++
			summary.ResolvedSurfaces++
			summary.ResolvedRefuted++
		case model.CoverageStatusOutOfScope:
			summary.ExploredSurfaces++
			summary.ResolvedSurfaces++
			summary.OutOfScopeSurfaces++
		case model.CoverageStatusBlocked:
			summary.ExploredSurfaces++
			summary.BlockedSurfaces++
		case model.CoverageStatusInconclusive:
			summary.ExploredSurfaces++
			summary.InconclusiveSurfaces++
		}
	}
	return summary
}

func normalizeSurfaceType(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "upload_flow", "download_flow", "object_access", "query_flow", "auth_flow", "admin_flow", "import_export_flow", "file_operation", "external_request", "template_rendering", "deserialization_flow", "config_exposure":
		return v
	case "upload", "file_upload":
		return "upload_flow"
	case "download", "file_download":
		return "download_flow"
	case "query", "search":
		return "query_flow"
	case "admin":
		return "admin_flow"
	case "file":
		return "file_operation"
	case "auth", "authorization":
		return "auth_flow"
	case "object", "object_read":
		return "object_access"
	default:
		return "unknown"
	}
}

func normalizeCoverageStatus(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case model.CoverageStatusUnexplored, model.CoverageStatusExploring, model.CoverageStatusResolvedVerified, model.CoverageStatusResolvedRefuted, model.CoverageStatusBlocked, model.CoverageStatusInconclusive, model.CoverageStatusOutOfScope:
		return v
	case "", "discovered", "pending":
		return model.CoverageStatusUnexplored
	case "tested", "validated":
		return model.CoverageStatusResolvedVerified
	case "negative", "refuted":
		return model.CoverageStatusResolvedRefuted
	default:
		return v
	}
}

func normalizeCoveragePriority(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(v, "critical"):
		return model.CoveragePriorityCritical
	case strings.Contains(v, "high"):
		return model.CoveragePriorityHigh
	case strings.Contains(v, "low"):
		return model.CoveragePriorityLow
	default:
		return model.CoveragePriorityMedium
	}
}

func riskSignalsFromCoverageItem(item model.AICoverageItem) []string {
	signals := []string{}
	for _, part := range strings.FieldsFunc(item.RiskHint, func(r rune) bool { return r == ',' || r == ';' || r == '|' }) {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			signals = append(signals, trimmed)
		}
	}
	if len(signals) == 0 && item.RiskHint != "" {
		signals = append(signals, item.RiskHint)
	}
	return uniqueStringList(signals)
}

func isUnresolvedHighPrioritySurface(surface GraphSurfaceCoverage) bool {
	status := normalizeCoverageStatus(surface.Status)
	if status == model.CoverageStatusResolvedVerified || status == model.CoverageStatusResolvedRefuted || status == model.CoverageStatusBlocked || status == model.CoverageStatusInconclusive || status == model.CoverageStatusOutOfScope {
		return false
	}
	return surface.Priority == model.CoveragePriorityCritical || surface.Priority == model.CoveragePriorityHigh
}

func countOpenHighPriorityIntents(intents []model.AIIntent, surfaces []GraphSurfaceCoverage) int {
	count := 0
	for _, intent := range intents {
		if intent.IntentType == model.IntentReportFinalize {
			continue
		}
		if intent.PriorityScore >= 0.7 {
			count++
			continue
		}
		for _, surface := range surfaces {
			if !isUnresolvedHighPrioritySurface(surface) {
				continue
			}
			if containsUint(surface.OpenIntentRefs, intent.ID) {
				count++
				break
			}
		}
	}
	return count
}

func surfaceMatchesText(surface GraphSurfaceCoverage, text string) bool {
	needle := strings.ToLower(strings.TrimSpace(surface.Entrypoint))
	if needle == "" {
		return false
	}
	haystack := strings.ToLower(text)
	return strings.Contains(haystack, needle) || strings.Contains(haystack, strings.ToLower(strings.TrimPrefix(needle, "/")))
}

func containsUint(items []uint, target uint) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func authContextsFromTask(task model.AISecurityTask) []string {
	if len(task.AuthorizationJSON) == 0 {
		return nil
	}
	var doc map[string]any
	if json.Unmarshal(task.AuthorizationJSON, &doc) != nil {
		return nil
	}
	result := []string{}
	for key, value := range doc {
		if strings.Contains(strings.ToLower(key), "auth") || strings.Contains(strings.ToLower(key), "role") || strings.Contains(strings.ToLower(key), "tenant") || strings.Contains(strings.ToLower(key), "user") {
			result = append(result, fmt.Sprintf("%s=%v", key, value))
		}
	}
	return truncateStringList(result, 8)
}

func (l *CairnLoop) recentCoverageProgress(ctx context.Context, taskID uint) GraphRecentProgress {
	since := time.Now().Add(-15 * time.Minute)
	var progress GraphRecentProgress
	var facts, evidence, caps, surfaces int64
	_ = l.db.WithContext(ctx).Model(&model.AIBlackboardNode{}).Where("task_id = ? AND created_at >= ?", taskID, since).Count(&facts).Error
	_ = l.db.WithContext(ctx).Model(&model.AIEvidence{}).Where("task_id = ? AND created_at >= ?", taskID, since).Count(&evidence).Error
	_ = l.db.WithContext(ctx).Model(&model.AICapability{}).Where("task_id = ? AND created_at >= ?", taskID, since).Count(&caps).Error
	_ = l.db.WithContext(ctx).Model(&model.AICoverageItem{}).Where("task_id = ? AND created_at >= ?", taskID, since).Count(&surfaces).Error
	progress.NewFactsLastN = int(facts)
	progress.NewEvidenceLastN = int(evidence)
	progress.NewCapabilitiesLastN = int(caps)
	progress.NewSurfacesLastN = int(surfaces)
	return progress
}

// ShouldFinalize stops for graph exploration reasons: exhausted budget,
// repeated no-progress rounds, explicit terminal progress, or no high-value
// pending intent after capability acquisition. Finding count is intentionally
// not a termination signal.
func (l *CairnLoop) ShouldFinalize(ctx context.Context, task model.AISecurityTask, iterationNo int, maxIterations int, consecutiveNoProgress int) bool {
	return l.ShouldFinalizeWithNoProgressLimit(ctx, task, iterationNo, maxIterations, consecutiveNoProgress, defaultNoProgressFinalizeRounds)
}

func (l *CairnLoop) ShouldFinalizeWithNoProgressLimit(ctx context.Context, task model.AISecurityTask, iterationNo int, maxIterations int, consecutiveNoProgress int, noProgressLimit int) bool {
	if noProgressLimit <= 0 {
		noProgressLimit = defaultNoProgressFinalizeRounds
	}
	// Budget exhausted
	if iterationNo >= maxIterations {
		return true
	}

	coverage := l.BuildCoverageState(ctx, task, iterationNo)
	if coverage.OpenHighPriorityIntents > 0 || coverage.UnresolvedHighPrioritySurfaces > 0 {
		return false
	}

	// If graph exploration still has actionable runtime intents, keep exploring.
	// Priority is a planner ordering signal, not a completion signal; low-scored
	// pending validation can still produce Evidence, NegativeFact, or UnverifiedRisk.
	var pendingActionable int64
	_ = l.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("task_id = ? AND status = ? AND intent_type IN ?", task.ID, model.IntentStatusPending, runtimeIntentTypeList()).
		Where("intent_type <> ?", model.IntentReportFinalize).
		Count(&pendingActionable).Error
	if pendingActionable > 0 {
		return false
	}

	if coverage.ScopeSummary.SurfaceCount > 0 && coverage.UnresolvedHighPrioritySurfaces == 0 && coverage.OpenHighPriorityIntents == 0 {
		return true
	}

	// No progress for N consecutive rounds. This is deliberately greater
	// than one failed validation so Rabbit can pivot through NegativeFact /
	// UnverifiedRisk before it decides the graph has stopped expanding.
	if consecutiveNoProgress >= noProgressLimit {
		return true
	}

	// All verified capabilities have been attempted for goal progression
	var verifiedCaps int64
	_ = l.db.WithContext(ctx).Model(&model.AICapability{}).
		Where("task_id = ? AND strength = ?", task.ID, model.StrengthVerified).
		Count(&verifiedCaps).Error

	// Legacy fallback for tasks without explicit coverage items. A verified
	// capability is not sufficient while coverage says high-priority surfaces
	// remain unresolved.
	if verifiedCaps > 0 && iterationNo > 5 {
		return true
	}

	return false
}

// WriteCapability persists a capability to the database and blackboard.
func (l *CairnLoop) WriteCapability(ctx context.Context, taskID uint, draft CapabilityDraft, intentID *uint) (model.AICapability, error) {
	hypotheses := NewHypothesisLifecycleService(l.db, l.blackboard)
	var backingHypothesis model.AIHypothesisNode
	var err error
	if draft.Strength == model.StrengthVerified {
		backingHypothesis, err = hypotheses.EnsureCapabilityHypothesis(ctx, taskID, draft.CapabilityType, draft.Target, draft.EvidenceIDs, intentID)
		if err != nil && err != gorm.ErrRecordNotFound {
			return model.AICapability{}, err
		}
	}
	var hypothesisID *uint
	if backingHypothesis.ID != 0 {
		hypothesisID = &backingHypothesis.ID
	}
	var existing model.AICapability
	query := l.db.WithContext(ctx).
		Where("task_id = ? AND capability_type = ? AND target = ?", taskID, draft.CapabilityType, draft.Target)
	if hypothesisID == nil {
		query = query.Where("validated_by_hypothesis_id IS NULL")
	} else {
		query = query.Where("validated_by_hypothesis_id = ?", *hypothesisID)
	}
	err = query.First(&existing).Error
	if err == nil {
		if existing.Strength == model.StrengthVerified {
			_ = l.MarkCoverageResolvedByCapability(ctx, existing)
		}
		return existing, nil
	}
	if err != gorm.ErrRecordNotFound {
		return model.AICapability{}, err
	}
	cap := model.AICapability{
		TaskID:                  taskID,
		CapabilityType:          draft.CapabilityType,
		Target:                  draft.Target,
		Strength:                draft.Strength,
		ProofSummary:            draft.ProofSummary,
		EvidenceRefs:            mustJSON(draft.EvidenceIDs),
		DerivedFromEvidenceRefs: mustJSON(draft.EvidenceIDs),
		AcquiredByIntentID:      intentID,
		ValidatedByHypothesisID: hypothesisID,
		CanAdvanceGoal:          draft.CanAdvanceGoal,
		RiskLevel:               "low",
		CreatedAt:               time.Now().UTC(),
		UpdatedAt:               time.Now().UTC(),
	}
	if err := l.db.WithContext(ctx).Create(&cap).Error; err != nil {
		return cap, err
	}

	// Write to blackboard graph
	capNode, _ := l.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        "capability",
		Title:           fmt.Sprintf("[%s] %s", cap.Strength, cap.CapabilityType),
		Summary:         cap.ProofSummary,
		Content:         cap,
		DedupSeed:       fmt.Sprintf("cap-%s-%s", cap.CapabilityType, cap.Target),
		ImportanceScore: capabilityImportance(cap.Strength),
		SourceType:      "agent",
		SourceID:        fmt.Sprintf("capability-%d", cap.ID),
		EvidenceRefs:    draft.EvidenceIDs,
	})
	if capNode.ID != 0 && backingHypothesis.ID != 0 {
		hNode, _ := l.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        model.NodeHypothesis,
			Title:           backingHypothesis.Title,
			Summary:         backingHypothesis.Description,
			Content:         backingHypothesis,
			DedupSeed:       fmt.Sprintf("hypothesis-%d", backingHypothesis.ID),
			ImportanceScore: 0.98,
			SourceType:      "hypothesis-lifecycle",
			SourceID:        fmt.Sprintf("%d", backingHypothesis.ID),
			EvidenceRefs:    draft.EvidenceIDs,
		})
		if hNode.ID != 0 {
			_ = l.blackboard.AddEdge(ctx, taskID, capNode.ID, hNode.ID, model.EdgeValidatedBy, 0.94, map[string]any{"capabilityId": cap.ID, "hypothesisId": backingHypothesis.ID})
			_ = l.blackboard.AddEdge(ctx, taskID, hNode.ID, capNode.ID, model.EdgeProduces, 0.92, map[string]any{"capabilityId": cap.ID, "hypothesisId": backingHypothesis.ID})
		}
	}
	for _, evidenceID := range draft.EvidenceIDs {
		if capNode.ID == 0 {
			continue
		}
		eNode, _ := l.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        model.NodeEvidence,
			Title:           fmt.Sprintf("Evidence %d", evidenceID),
			Summary:         "Evidence linked to capability derivation.",
			Content:         map[string]any{"evidenceId": evidenceID},
			DedupSeed:       fmt.Sprintf("evidence-ref-%d", evidenceID),
			ImportanceScore: 0.72,
			SourceType:      "hypothesis-lifecycle",
			SourceID:        fmt.Sprintf("%d", evidenceID),
			EvidenceRefs:    []uint{evidenceID},
		})
		if eNode.ID != 0 {
			_ = l.blackboard.AddEdge(ctx, taskID, capNode.ID, eNode.ID, model.EdgeDerivedFrom, 0.9, map[string]any{"capabilityId": cap.ID, "evidenceId": evidenceID})
		}
	}
	if cap.Strength == model.StrengthVerified {
		_ = l.MarkCoverageResolvedByCapability(ctx, cap)
		_, _ = hypotheses.ExpandFromCapability(ctx, cap, ExpansionBudget{})
	} else if cap.Strength == model.StrengthObserved {
		_, _ = hypotheses.CreateObservedCapabilityValidationIntent(ctx, cap)
	}

	return cap, nil
}

// WriteExploreResult persists all outputs from an Explore phase to the graph.
func (l *CairnLoop) WriteExploreResult(ctx context.Context, taskID uint, result ExploreResult) error {
	for _, item := range result.Evidence {
		_, _ = l.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        model.NodeEvidence,
			Title:           firstNonEmpty(item.Title, fmt.Sprintf("Evidence %d", item.ID)),
			Summary:         item.Summary,
			Content:         item,
			DedupSeed:       fmt.Sprintf("evidence-%d-%s", item.ID, item.Hash),
			ImportanceScore: 0.72,
			SourceType:      "graph-delta",
			SourceID:        fmt.Sprintf("intent-%d", result.IntentID),
			EvidenceRefs:    evidenceIDsFromItems([]model.AIEvidence{item}),
		})
	}

	// Write facts
	for _, fact := range result.Facts {
		nodeType := fact.NodeType
		if nodeType == "" {
			nodeType = "fact"
		}
		_, _ = l.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        nodeType,
			Title:           fact.Title,
			Summary:         fact.Summary,
			Content:         fact,
			DedupSeed:       "fact-" + fact.Title,
			ImportanceScore: 0.75,
			SourceType:      "agent",
			SourceID:        fmt.Sprintf("intent-%d", result.IntentID),
		})
	}

	// Write negative facts
	for _, nf := range result.NegativeFacts {
		_, _ = l.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        "negative_fact",
			Title:           nf.Title,
			Summary:         nf.Summary,
			Content:         nf,
			DedupSeed:       "neg-" + nf.Title,
			ImportanceScore: 0.4,
			SourceType:      "agent",
			SourceID:        fmt.Sprintf("intent-%d", result.IntentID),
		})
	}

	// Write capabilities
	for _, capDraft := range result.Capabilities {
		intentID := result.IntentID
		_, _ = l.WriteCapability(ctx, taskID, capDraft, &intentID)
	}

	// Create suggested follow-up intents
	for _, suggestion := range result.SuggestedIntents {
		l.CreateIntentFromSuggestion(ctx, taskID, suggestion)
	}

	return nil
}

// ApplyGraphDelta is the single mutation boundary for Cairn-style worker
// packets. It preserves the existing ExploreResult path while making the
// graph update contract explicit for Bootstrap, Reason, and Explore.
func (l *CairnLoop) ApplyGraphDelta(ctx context.Context, taskID uint, delta GraphDelta) error {
	result := ExploreResult{
		IntentID:         delta.IntentID,
		Status:           "completed",
		Facts:            append(append([]GraphFact{}, delta.NewFacts...), delta.UpdatedFacts...),
		NegativeFacts:    delta.NewNegativeFacts,
		Evidence:         delta.NewEvidence,
		Capabilities:     delta.NewCapabilityCandidates,
		SuggestedIntents: delta.NewIntents,
		Notes:            strings.Join(append(delta.Diagnostics, delta.Errors...), "; "),
	}
	if err := l.WriteExploreResult(ctx, taskID, result); err != nil {
		return err
	}
	for _, update := range delta.UpdatedCoverage {
		if err := l.ApplyCoverageUpdate(ctx, taskID, update); err != nil {
			return err
		}
	}
	for _, draft := range delta.VerifiedCapabilities {
		draft.Strength = model.StrengthVerified
		draft.CanAdvanceGoal = true
		intentID := delta.IntentID
		var intentRef *uint
		if intentID != 0 {
			intentRef = &intentID
		}
		if _, err := l.WriteCapability(ctx, taskID, draft, intentRef); err != nil {
			return err
		}
	}
	for _, intentID := range delta.CompletedIntents {
		if l.intents != nil {
			_ = l.intents.Finish(ctx, intentID, true)
		}
	}
	return nil
}

func (l *CairnLoop) EmitGraphSearchDiagnostic(ctx context.Context, diagnostic GraphSearchLoopDiagnostic) {
	if l == nil || l.db == nil {
		return
	}
	taskID := diagnostic.TaskID
	appendAuditEvent(ctx, l.db, &taskID, "graph_search.loop_diagnostic", "graph-search-loop", diagnostic.Phase, diagnostic)
}

func SummarizeGraphDelta(delta GraphDelta) GraphDeltaSummary {
	return GraphDeltaSummary{
		NewFacts:                len(delta.NewFacts) + len(delta.UpdatedFacts),
		NewEvidence:             len(delta.NewEvidence),
		NewNegativeFacts:        len(delta.NewNegativeFacts),
		NewCapabilityCandidates: len(delta.NewCapabilityCandidates) + len(delta.VerifiedCapabilities),
		NewIntents:              len(delta.NewIntents),
		UpdatedCoverage:         len(delta.UpdatedCoverage),
	}
}

// CreateIntentFromSuggestion creates a structured intent from a suggestion.
func (l *CairnLoop) CreateIntentFromSuggestion(ctx context.Context, taskID uint, s IntentSuggestion) {
	title := s.Objective
	if title == "" {
		title = s.Hypothesis
	}
	if title == "" {
		return
	}
	if l.intentMatchesNegativeFact(ctx, taskID, title, s.Objective) {
		return
	}

	// Check for duplicates
	var existing int64
	_ = l.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("task_id = ? AND title = ? AND status IN ?", taskID, title, []string{model.IntentStatusPending, model.IntentStatusRunning}).
		Count(&existing).Error
	if existing > 0 {
		return
	}

	intentType := s.IntentType
	if intentType == "" {
		intentType = model.IntentResolveUnknown
	}
	normalizedIntentType, metadata, ok := normalizeGraphSearchIntentType(intentType)
	if !ok {
		return
	}
	intentType = normalizedIntentType

	priority := float64(s.Priority) / 100.0
	if priority <= 0 {
		priority = 0.7
	}
	priority, priorityMetadata := l.scoreIntentSuggestionPriority(ctx, taskID, s, priority)
	metadata = mergeIntentMetadata(metadata, priorityMetadata)

	intent := model.AIIntent{
		TaskID:     taskID,
		IntentType: intentType,
		Title:      title,
		Objective:  s.Objective,
		ConstraintsJSON: mustJSON(mergeIntentMetadata(map[string]any{
			"hypothesis":       s.Hypothesis,
			"success_criteria": s.SuccessCriteria,
			"failure_criteria": s.FailureCriteria,
			"allowed_tools":    s.AllowedTools,
			"risk_level":       s.RiskLevel,
		}, metadata)),
		RequiredEvidence: mustJSON([]string{}),
		PriorityScore:    priority,
		Status:           model.IntentStatusPending,
		CreatedBy:        "agent",
		CreatedReason:    "Cairn reasoner suggested exploration",
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	_ = l.db.WithContext(ctx).Create(&intent).Error
}

func (l *CairnLoop) scoreIntentSuggestionPriority(ctx context.Context, taskID uint, s IntentSuggestion, base float64) (float64, map[string]any) {
	score := base
	reasons := []string{}
	surfaceRefs := []string{}
	text := strings.ToLower(strings.Join([]string{s.Objective, s.Hypothesis, s.SuccessCriteria, s.FailureCriteria, strings.Join(s.AllowedTools, " "), s.RiskLevel}, " "))
	var items []model.AICoverageItem
	_ = l.db.WithContext(ctx).Where("task_id = ?", taskID).Find(&items).Error
	for _, item := range items {
		surface := GraphSurfaceCoverage{
			SurfaceID:   fmt.Sprintf("surface_%d", item.ID),
			Entrypoint:  firstNonEmpty(item.TargetRef, item.Name),
			Status:      normalizeCoverageStatus(item.Status),
			Priority:    normalizeCoveragePriority(item.RiskHint),
			SurfaceType: normalizeSurfaceType(item.Category),
		}
		if !surfaceMatchesText(surface, text) {
			continue
		}
		surfaceRefs = append(surfaceRefs, surface.SurfaceID)
		if isUnresolvedHighPrioritySurface(surface) {
			score += 0.18
			reasons = append(reasons, "covers_unexplored_surface")
			if surface.Priority == model.CoveragePriorityCritical || surface.Priority == model.CoveragePriorityHigh {
				score += 0.08
				reasons = append(reasons, "high_priority_surface")
			}
		}
		if surface.SurfaceType == "file_operation" || surface.SurfaceType == "object_access" || surface.SurfaceType == "admin_flow" || surface.SurfaceType == "query_flow" {
			score += 0.04
			reasons = append(reasons, "risk_signal:"+surface.SurfaceType)
		}
	}
	if strings.Contains(text, "guard") || strings.Contains(text, "authorization") || strings.Contains(text, "evidence") || strings.Contains(text, "recheck") {
		score += 0.07
		reasons = append(reasons, "evidence_gap")
	}
	if l.intentMatchesNegativeFact(ctx, taskID, s.Objective, s.Hypothesis) {
		score -= 0.45
		reasons = append(reasons, "negative_fact_penalty")
	}
	if score > 1 {
		score = 1
	}
	if score < 0.05 {
		score = 0.05
	}
	return score, map[string]any{
		"priority_reasons": uniqueStringList(reasons),
		"surface_refs":     uniqueStringList(surfaceRefs),
	}
}

func (l *CairnLoop) intentMatchesNegativeFact(ctx context.Context, taskID uint, values ...string) bool {
	needle := strings.ToLower(strings.Join(values, "\n"))
	if strings.TrimSpace(needle) == "" {
		return false
	}
	var negatives []model.AINegativeFact
	_ = l.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at desc").Limit(50).Find(&negatives).Error
	for _, neg := range negatives {
		for _, candidate := range []string{neg.TestedPath, neg.Title, neg.SimilarPatternKey} {
			candidate = strings.ToLower(strings.TrimSpace(candidate))
			if candidate != "" && strings.Contains(needle, candidate) {
				return true
			}
		}
	}
	var nodes []model.AIBlackboardNode
	_ = l.db.WithContext(ctx).Where("task_id = ? AND node_type = ? AND status = ?", taskID, model.NodeNegativeFact, model.BlackboardNodeStatusActive).Limit(50).Find(&nodes).Error
	for _, node := range nodes {
		for _, candidate := range []string{node.Title, graphNodeContentString(node.ContentJSON, "testedPath", "tested_path", "target")} {
			candidate = strings.ToLower(strings.TrimSpace(candidate))
			if candidate != "" && strings.Contains(needle, candidate) {
				return true
			}
		}
	}
	return false
}

// PromoteCapabilitiesToFindings converts verified capabilities with delivery-ready evidence into Findings.
//
// A capability is graph state, not a report artifact. Bootstrap capabilities
// and generic proof summaries stay in the exploration graph until a validated
// path carries the fields needed by the report contract.
func (l *CairnLoop) PromoteCapabilitiesToFindings(ctx context.Context, task model.AISecurityTask) error {
	if err := l.VerifyCapabilityCandidatesFromEvidence(ctx, task.ID); err != nil {
		return err
	}
	var caps []model.AICapability
	_ = l.db.WithContext(ctx).
		Where("task_id = ? AND strength = ? AND can_advance_goal = ?", task.ID, model.StrengthVerified, true).
		Find(&caps).Error

	for _, cap := range caps {
		gate := l.EvaluateCapabilityPromotionGate(ctx, cap)
		if !gate.Allowed {
			continue
		}
		// Check if a finding already exists for this capability
		var existingFinding int64
		_ = l.db.WithContext(ctx).Model(&model.AIFinding{}).
			Where("task_id = ? AND vulnerability_type = ? AND affected_target = ?", task.ID, cap.CapabilityType, cap.Target).
			Count(&existingFinding).Error
		if existingFinding > 0 {
			continue
		}

		var evidenceIDs []uint
		_ = json.Unmarshal(cap.EvidenceRefs, &evidenceIDs)
		if len(evidenceIDs) == 0 || isBootstrapOnlyCapability(cap.CapabilityType) {
			continue
		}

		details, ok := deliveryDetailsForCapability(cap, evidenceIDs)
		if !ok {
			continue
		}

		title := fmt.Sprintf("已验证能力: %s (%s)", capabilityLabel(cap.CapabilityType), cap.Target)
		finding, err := l.findings.UpsertCandidate(ctx, task.ID, title, cap.CapabilityType, cap.Target, cap.Target, capabilitySeverity(cap.CapabilityType), details, evidenceIDs, model.ValidationDynamicallyValidated)
		if err != nil {
			continue
		}
		if l.contracts != nil {
			_, _ = l.contracts.CheckFinding(ctx, &finding)
		}
	}
	return nil
}

func (l *CairnLoop) VerifyCapabilityCandidatesFromEvidence(ctx context.Context, taskID uint) error {
	var caps []model.AICapability
	if err := l.db.WithContext(ctx).
		Where("task_id = ? AND strength IN ? AND can_advance_goal = ?", taskID, []string{model.StrengthObserved, model.StrengthSuspected}, true).
		Find(&caps).Error; err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, cap := range caps {
		gate := l.EvaluateCapabilityPromotionGate(ctx, cap)
		if !gate.Allowed {
			continue
		}
		cap.Strength = model.StrengthVerified
		cap.UpdatedAt = now
		if err := l.db.WithContext(ctx).Save(&cap).Error; err != nil {
			return err
		}
		_ = l.MarkCoverageResolvedByCapability(ctx, cap)
	}
	return nil
}

func (l *CairnLoop) MarkCoverageResolvedByCapability(ctx context.Context, cap model.AICapability) error {
	if l == nil || l.db == nil {
		return nil
	}
	var items []model.AICoverageItem
	if err := l.db.WithContext(ctx).Where("task_id = ?", cap.TaskID).Find(&items).Error; err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, item := range items {
		surface := GraphSurfaceCoverage{Entrypoint: firstNonEmpty(item.TargetRef, item.Name)}
		if !surfaceMatchesText(surface, cap.Target+" "+cap.ProofSummary) {
			continue
		}
		status := normalizeCoverageStatus(item.Status)
		if status == model.CoverageStatusBlocked || status == model.CoverageStatusOutOfScope {
			continue
		}
		item.Status = model.CoverageStatusResolvedVerified
		item.Reason = firstNonEmpty(item.Reason, "resolved by verified capability "+fmt.Sprint(cap.ID))
		item.EvidenceRefs = mergeJSONUintRefs(item.EvidenceRefs, uintListFromJSON(cap.EvidenceRefs))
		item.UpdatedAt = now
		if err := l.db.WithContext(ctx).Save(&item).Error; err != nil {
			return err
		}
	}
	return nil
}

func (l *CairnLoop) ApplyCoverageResolutionFromNegativeFact(ctx context.Context, nf model.AINegativeFact) error {
	if l == nil || l.db == nil {
		return nil
	}
	var items []model.AICoverageItem
	if err := l.db.WithContext(ctx).Where("task_id = ?", nf.TaskID).Find(&items).Error; err != nil {
		return err
	}
	status := coverageStatusFromNegativeFact(nf)
	now := time.Now().UTC()
	for _, item := range items {
		surface := GraphSurfaceCoverage{Entrypoint: firstNonEmpty(item.TargetRef, item.Name)}
		if !surfaceMatchesText(surface, nf.TestedPath+" "+nf.Title+" "+nf.Reason) {
			continue
		}
		item.Status = status
		item.Reason = firstNonEmpty(nf.Reason, nf.Title)
		item.EvidenceRefs = mergeJSONUintRefs(item.EvidenceRefs, uintListFromJSON(nf.EvidenceRefs))
		item.UpdatedAt = now
		if err := l.db.WithContext(ctx).Save(&item).Error; err != nil {
			return err
		}
	}
	return nil
}

func (l *CairnLoop) ApplyCoverageUpdate(ctx context.Context, taskID uint, update CoverageUpdate) error {
	if l == nil || l.db == nil {
		return nil
	}
	entrypoint := strings.TrimSpace(update.Entrypoint)
	if entrypoint == "" {
		return nil
	}
	var item model.AICoverageItem
	err := l.db.WithContext(ctx).
		Where("task_id = ? AND (target_ref = ? OR name = ?)", taskID, entrypoint, entrypoint).
		First(&item).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	now := time.Now().UTC()
	if err == gorm.ErrRecordNotFound {
		item = model.AICoverageItem{
			TaskID:       taskID,
			Category:     normalizeSurfaceType(update.SurfaceType),
			Name:         entrypoint,
			TargetRef:    entrypoint,
			RiskHint:     normalizeCoveragePriority(update.Priority),
			Status:       normalizeCoverageStatus(update.Status),
			Reason:       update.Reason,
			EvidenceRefs: mustJSON(update.EvidenceRefs),
			NodeRefs:     mustJSON(update.NodeRefs),
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		return l.db.WithContext(ctx).Create(&item).Error
	}
	if update.SurfaceType != "" {
		item.Category = normalizeSurfaceType(update.SurfaceType)
	}
	if update.Priority != "" {
		item.RiskHint = normalizeCoveragePriority(update.Priority)
	}
	if update.Status != "" {
		item.Status = normalizeCoverageStatus(update.Status)
	}
	if update.Reason != "" {
		item.Reason = update.Reason
	}
	item.EvidenceRefs = mergeJSONUintRefs(item.EvidenceRefs, update.EvidenceRefs)
	item.NodeRefs = mergeJSONUintRefs(item.NodeRefs, update.NodeRefs)
	item.UpdatedAt = now
	return l.db.WithContext(ctx).Save(&item).Error
}

func coverageStatusFromNegativeFact(nf model.AINegativeFact) string {
	text := strings.ToLower(nf.Title + " " + nf.TestedPath + " " + nf.Reason + " " + nf.SimilarPatternKey)
	switch {
	case strings.Contains(text, "out_of_scope") || strings.Contains(text, "out of scope"):
		return model.CoverageStatusOutOfScope
	case strings.Contains(text, "auth_required") || strings.Contains(text, "missing credentials") || strings.Contains(text, "environment") || strings.Contains(text, "blocked"):
		return model.CoverageStatusBlocked
	case strings.Contains(text, "inconclusive") || strings.Contains(text, "insufficient"):
		return model.CoverageStatusInconclusive
	default:
		return model.CoverageStatusResolvedRefuted
	}
}

func mergeJSONUintRefs(existing datatypes.JSON, more []uint) datatypes.JSON {
	refs := uintListFromJSON(existing)
	refs = append(refs, more...)
	return mustJSON(compactUintList(refs))
}

func (l *CairnLoop) EvaluateCapabilityPromotionGate(ctx context.Context, cap model.AICapability) CapabilityPromotionGate {
	gate := CapabilityPromotionGate{
		EvidenceRefs: uintListFromJSON(cap.EvidenceRefs),
		FactRefs:     uintListFromJSON(cap.SourceNodeIDs),
	}
	evidenceItems := l.loadCapabilityEvidence(ctx, cap.TaskID, gate.EvidenceRefs)
	gate.Relations = capabilityEvidenceRelations(evidenceItems)
	structuredCoverage := structuredEvidenceCoversCapability(evidenceItems)
	legacyDetails := false
	details, ok := deliveryDetailsForCapability(cap, gate.EvidenceRefs)
	if ok {
		legacyDetails = true
	}
	if cap.Strength != model.StrengthVerified && !structuredCoverage {
		gate.Missing = append(gate.Missing, "verified_capability")
	}
	if !cap.CanAdvanceGoal {
		gate.Missing = append(gate.Missing, "goal_advancing_capability")
	}
	if len(gate.EvidenceRefs) == 0 {
		gate.Missing = append(gate.Missing, "evidence_refs")
	}
	if isBootstrapOnlyCapability(cap.CapabilityType) {
		gate.Missing = append(gate.Missing, "delivery_capability")
	}
	if len(evidenceItems) > 0 {
		if !structuredCoverage && !legacyDetails {
			for _, relation := range missingRequiredEvidenceRelations(evidenceItems) {
				gate.Missing = append(gate.Missing, "evidence_relation:"+relation)
			}
			if !hasEvidenceRelation(evidenceItems, "validation_or_observed_signal") && !hasEvidenceRelation(evidenceItems, "strong_static_proof") {
				gate.Missing = append(gate.Missing, "validation_or_observed_signal_or_strong_static_proof")
			}
		}
		if structuredCoverage {
			for _, relation := range missingRequiredEvidenceRelations(evidenceItems) {
				gate.Missing = append(gate.Missing, "evidence_relation:"+relation)
			}
			if !hasEvidenceRelation(evidenceItems, "validation_or_observed_signal") && !hasEvidenceRelation(evidenceItems, "strong_static_proof") {
				gate.Missing = append(gate.Missing, "validation_or_observed_signal_or_strong_static_proof")
			}
		}
	} else if !legacyDetails {
		gate.Missing = append(gate.Missing, "complete_delivery_proof_chain")
	}
	if ok {
		gate.ValidationRef = firstNonEmpty(
			fmt.Sprint(details["validation_evidence"]),
			fmt.Sprint(details["observed_result"]),
			fmt.Sprint(details["request_packet"]),
		)
		if len(evidenceItems) == 0 {
			for _, field := range []string{"entrypoint", "controlled_input", "propagation_path", "sensitive_sink_or_behavior"} {
				if strings.TrimSpace(fmt.Sprint(details[field])) == "" {
					gate.Missing = append(gate.Missing, field)
				}
			}
		}
	} else if len(evidenceItems) == 0 {
		for _, field := range []string{"entrypoint", "controlled_input", "propagation_path", "sensitive_sink_or_behavior"} {
			if strings.TrimSpace(fmt.Sprint(details[field])) == "" {
				gate.Missing = append(gate.Missing, field)
			}
		}
	}
	if len(gate.FactRefs) == 0 && ok {
		// Older capabilities may encode the source/sink/dataflow/guard chain in
		// delivery details rather than SourceNodeIDs. This keeps the gate
		// evidence-first without breaking existing graph records.
		if strings.TrimSpace(fmt.Sprint(details["propagation_path"])) == "" {
			gate.Missing = append(gate.Missing, "fact_refs_or_propagation_path")
		}
	}
	gate.Missing = uniqueStringList(gate.Missing)
	gate.Allowed = len(gate.Missing) == 0
	return gate
}

func (l *CairnLoop) loadCapabilityEvidence(ctx context.Context, taskID uint, ids []uint) []model.AIEvidence {
	if len(ids) == 0 {
		return nil
	}
	var items []model.AIEvidence
	_ = l.db.WithContext(ctx).Where("task_id = ? AND id IN ?", taskID, ids).Find(&items).Error
	return items
}

func capabilityEvidenceRelations(items []model.AIEvidence) []string {
	relations := []string{}
	for _, item := range items {
		relation := strings.TrimSpace(item.RelationType)
		if relation != "" {
			relations = append(relations, relation)
		}
	}
	return uniqueStringList(relations)
}

func structuredEvidenceCoversCapability(items []model.AIEvidence) bool {
	if len(items) == 0 {
		return false
	}
	if len(missingRequiredEvidenceRelations(items)) != 0 {
		return false
	}
	return hasEvidenceRelation(items, "validation_or_observed_signal") || hasEvidenceRelation(items, "strong_static_proof")
}

func missingRequiredEvidenceRelations(items []model.AIEvidence) []string {
	missing := []string{}
	for _, relation := range requiredCapabilityEvidenceRelations {
		if !hasEvidenceRelation(items, relation) {
			missing = append(missing, relation)
		}
	}
	if !hasEvidenceRelation(items, "validation_or_observed_signal") && !hasEvidenceRelation(items, "strong_static_proof") {
		missing = append(missing, "validation_or_observed_signal")
	}
	return missing
}

func hasEvidenceRelation(items []model.AIEvidence, relation string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.RelationType), relation) {
			return true
		}
	}
	return false
}

func isBootstrapOnlyCapability(capType string) bool {
	switch capType {
	case model.CapInternalServiceAccess, model.CapSourceCodeRead:
		return true
	default:
		return false
	}
}

func deliveryDetailsForCapability(cap model.AICapability, evidenceIDs []uint) (map[string]any, bool) {
	details := map[string]any{}
	if err := json.Unmarshal([]byte(cap.ProofSummary), &details); err != nil || len(details) == 0 {
		return nil, false
	}
	if _, ok := details["evidence_mapping"]; !ok {
		details["evidence_mapping"] = evidenceIDs
	}
	if _, ok := details["sensitive_sink_or_behavior"]; !ok {
		details["sensitive_sink_or_behavior"] = cap.CapabilityType
	}
	if _, ok := details["scope_statement"]; !ok && strings.TrimSpace(cap.Scope) != "" {
		details["scope_statement"] = cap.Scope
	}
	if !deliveryDetailsComplete(details) {
		return nil, false
	}
	return details, true
}

func deliveryDetailsComplete(details map[string]any) bool {
	for _, field := range genericContractFields {
		value, ok := details[field]
		if !ok || value == nil {
			return false
		}
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || text == "[]" || text == "<nil>" || text == "未形成可交付证据" {
			return false
		}
	}
	return true
}

func truncateStringList(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func truncateGraphFacts(items []GraphFactSummary, max int) []GraphFactSummary {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func truncateGraphIntents(items []GraphIntentSummary, max int) []GraphIntentSummary {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func truncateGraphEvidence(items []GraphEvidenceSummary, max int) []GraphEvidenceSummary {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func truncateGraphNegativeFacts(items []GraphNegativeFactSummary, max int) []GraphNegativeFactSummary {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func truncateGraphCapabilities(items []GraphCapabilitySummary, max int) []GraphCapabilitySummary {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func truncateGraphHints(items []GraphHintSummary, max int) []GraphHintSummary {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func isConfirmedFactNode(nodeType string) bool {
	switch nodeType {
	case model.NodeOrigin, model.NodeGoal, model.NodeSurfaceFact, model.NodeBehaviorFact, model.NodeBusinessFact,
		model.NodeCodeFact, model.NodeSecretFact, model.NodeCredentialFact, model.NodeEntrypoint,
		model.NodeAttackSurface, model.NodeAuthBoundary, model.NodeDataflow, model.NodeSink,
		model.NodeTestedPath, "fact":
		return true
	default:
		return false
	}
}

func graphConfidenceSource(raw datatypes.JSON) string {
	if len(uintListFromJSON(raw)) > 0 {
		return "evidence"
	}
	return "graph_observation"
}

func uintListFromJSON(raw datatypes.JSON) []uint {
	if len(raw) == 0 {
		return nil
	}
	var ids []uint
	if err := json.Unmarshal(raw, &ids); err == nil {
		return ids
	}
	var stringsIDs []string
	if err := json.Unmarshal(raw, &stringsIDs); err == nil {
		out := make([]uint, 0, len(stringsIDs))
		for _, value := range stringsIDs {
			var id uint
			if _, err := fmt.Sscanf(value, "%d", &id); err == nil && id > 0 {
				out = append(out, id)
			}
		}
		return out
	}
	return nil
}

func graphNodeContentString(raw datatypes.JSON, keys ...string) string {
	if len(raw) == 0 {
		return ""
	}
	values := map[string]any{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return ""
	}
	for _, key := range keys {
		if value, ok := values[key]; ok && value != nil {
			text := strings.TrimSpace(fmt.Sprint(value))
			if text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func inferGraphUnknowns(summary GraphSummary) []string {
	unknowns := []string{}
	if len(summary.ConfirmedFacts) == 0 {
		unknowns = append(unknowns, "Initial attack surface facts are not established.")
	}
	if len(summary.OpenIntents) == 0 && len(summary.VerifiedCapabilities) == 0 {
		unknowns = append(unknowns, "No open intent currently explains the next evidence-producing step.")
	}
	if len(summary.RecentEvidence) == 0 {
		unknowns = append(unknowns, "No recent evidence is available to support fact or capability promotion.")
	}
	if len(summary.CapabilityCandidates) > 0 && len(summary.VerifiedCapabilities) == 0 {
		unknowns = append(unknowns, "Capability candidates exist but still need validation evidence.")
	}
	return truncateStringList(unknowns, 6)
}

func uniqueStringList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		text := strings.TrimSpace(value)
		if text == "" {
			continue
		}
		if _, ok := seen[text]; ok {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	return out
}

func capabilityImportance(strength string) float64 {
	switch strength {
	case model.StrengthVerified:
		return 0.95
	case model.StrengthObserved:
		return 0.8
	default:
		return 0.6
	}
}

func capabilityLabel(capType string) string {
	labels := map[string]string{
		model.CapFileRead:              "文件读取",
		model.CapFileWrite:             "文件写入",
		model.CapCommandExecution:      "命令执行",
		model.CapDatabaseRead:          "数据库读取",
		model.CapAdminAccess:           "管理员访问",
		model.CapAuthenticatedSession:  "认证会话",
		model.CapSecretDiscovered:      "密钥泄露",
		model.CapUploadWrite:           "文件上传",
		model.CapSSRFInternalAccess:    "SSRF 内网访问",
		model.CapArbitraryObjectAccess: "越权对象访问",
		model.CapBusinessStateManip:    "业务状态篡改",
		model.CapSQLInjection:          "SQL 注入",
		model.CapPathTraversal:         "路径遍历",
	}
	if label, ok := labels[capType]; ok {
		return label
	}
	return capType
}

func capabilitySeverity(capType string) string {
	switch capType {
	case model.CapCommandExecution, model.CapFileWrite, model.CapAdminAccess:
		return "critical"
	case model.CapFileRead, model.CapDatabaseRead, model.CapSQLInjection, model.CapUploadWrite, model.CapSSRFInternalAccess:
		return "high"
	case model.CapArbitraryObjectAccess, model.CapBusinessStateManip, model.CapPathTraversal, model.CapSecretDiscovered:
		return "high"
	default:
		return "medium"
	}
}
