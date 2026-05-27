package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"shenji/backend/internal/model"

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
	TaskID            uint     `json:"task_id"`
	TaskType          string   `json:"task_type"`
	Goal              string   `json:"goal"`
	SurfaceFacts      []string `json:"surface_facts"`
	Fingerprints      []string `json:"fingerprints"`
	CodeFacts         []string `json:"code_facts"`
	BusinessFacts     []string `json:"business_facts"`
	SecretFacts       []string `json:"secret_facts"`
	Capabilities      []string `json:"capabilities"`
	PendingIntents    []string `json:"pending_intents"`
	NegativeFacts     []string `json:"negative_facts"`
	EnvironmentModel  string   `json:"environment_model"`
	EvidenceCount     int      `json:"evidence_count"`
	IterationBudget   int      `json:"iteration_budget"`
	IterationsCurrent int      `json:"iterations_current"`
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
	summary := GraphSummary{
		TaskID:            task.ID,
		TaskType:          task.TaskType,
		Goal:              task.Objective,
		IterationBudget:   maxIterations,
		IterationsCurrent: iterationNo,
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
		case "capability":
			summary.Capabilities = append(summary.Capabilities, line)
		}
	}

	// Add capabilities from the capability table
	var caps []model.AICapability
	_ = l.db.WithContext(ctx).Where("task_id = ?", task.ID).Order("created_at desc").Limit(20).Find(&caps).Error
	for _, cap := range caps {
		summary.Capabilities = append(summary.Capabilities, fmt.Sprintf("[%s] %s (%s) - %s", cap.Strength, cap.CapabilityType, cap.Target, cap.ProofSummary))
	}

	// Add pending intents
	var pendingIntents []model.AIIntent
	_ = l.db.WithContext(ctx).Where("task_id = ? AND status = ?", task.ID, model.IntentStatusPending).Order("priority_score desc").Limit(10).Find(&pendingIntents).Error
	for _, intent := range pendingIntents {
		summary.PendingIntents = append(summary.PendingIntents, fmt.Sprintf("[%s] %s", intent.IntentType, intent.Title))
	}

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

	return summary
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

	// No progress for N consecutive rounds. This is deliberately greater
	// than one failed validation so Rabbit can pivot through NegativeFact /
	// UnverifiedRisk before it decides the graph has stopped expanding.
	if consecutiveNoProgress >= noProgressLimit {
		return true
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

	// All verified capabilities have been attempted for goal progression
	var verifiedCaps int64
	_ = l.db.WithContext(ctx).Model(&model.AICapability{}).
		Where("task_id = ? AND strength = ?", task.ID, model.StrengthVerified).
		Count(&verifiedCaps).Error

	// If we have verified capabilities and no remaining actionable intents, finalize.
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
		_, _ = hypotheses.ExpandFromCapability(ctx, cap, ExpansionBudget{})
	} else if cap.Strength == model.StrengthObserved {
		_, _ = hypotheses.CreateObservedCapabilityValidationIntent(ctx, cap)
	}

	return cap, nil
}

// WriteExploreResult persists all outputs from an Explore phase to the graph.
func (l *CairnLoop) WriteExploreResult(ctx context.Context, taskID uint, result ExploreResult) error {
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

// CreateIntentFromSuggestion creates a structured intent from a suggestion.
func (l *CairnLoop) CreateIntentFromSuggestion(ctx context.Context, taskID uint, s IntentSuggestion) {
	title := s.Objective
	if title == "" {
		title = s.Hypothesis
	}
	if title == "" {
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
		intentType = "behavior_probe"
	}

	priority := float64(s.Priority) / 100.0
	if priority <= 0 {
		priority = 0.7
	}

	intent := model.AIIntent{
		TaskID:     taskID,
		IntentType: intentType,
		Title:      title,
		Objective:  s.Objective,
		ConstraintsJSON: mustJSON(map[string]any{
			"hypothesis":       s.Hypothesis,
			"success_criteria": s.SuccessCriteria,
			"failure_criteria": s.FailureCriteria,
			"allowed_tools":    s.AllowedTools,
			"risk_level":       s.RiskLevel,
		}),
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

// PromoteCapabilitiesToFindings converts verified capabilities with delivery-ready evidence into Findings.
//
// A capability is graph state, not a report artifact. Bootstrap capabilities
// and generic proof summaries stay in the exploration graph until a validated
// path carries the fields needed by the report contract.
func (l *CairnLoop) PromoteCapabilitiesToFindings(ctx context.Context, task model.AISecurityTask) error {
	var caps []model.AICapability
	_ = l.db.WithContext(ctx).
		Where("task_id = ? AND strength = ? AND can_advance_goal = ?", task.ID, model.StrengthVerified, true).
		Find(&caps).Error

	for _, cap := range caps {
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
		_, _ = l.contracts.CheckFinding(ctx, &finding)
	}
	return nil
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
