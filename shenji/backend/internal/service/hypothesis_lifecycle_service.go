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

type HypothesisLifecycleService struct {
	db         *gorm.DB
	blackboard *BlackboardService
}

type HypothesisDraft struct {
	TaskID                uint
	HypothesisType        string
	Title                 string
	Description           string
	ConfidenceState       string
	SourceObservationRefs []string
	TargetEntity          string
	ExpectedCapability    string
	IntentConstraints     map[string]any
	ExpansionScore        float64
}

type HypothesisResolution struct {
	IntentID         uint
	EvidenceIDs      []uint
	ToolBlocked      bool
	ToolFailed       bool
	ValidationFailed bool
	Reason           string
}

type ExpansionBudget struct {
	MaxPendingHypotheses int
	MaxPendingIntents    int
	MaxGeneratedPerRound int
	MaxActiveBranches    int
	LowValueThreshold    float64
}

func (b ExpansionBudget) toConfig() ExplorationBudgetConfig {
	cfg := DefaultExplorationBudgetConfig()
	if b.MaxPendingHypotheses > 0 {
		cfg.MaxPendingHypothesesPerTask = b.MaxPendingHypotheses
	}
	if b.MaxPendingIntents > 0 {
		cfg.MaxPendingValidationIntentsPerTask = b.MaxPendingIntents
	}
	if b.MaxGeneratedPerRound > 0 {
		cfg.MaxGeneratedIntentsPerRound = b.MaxGeneratedPerRound
	}
	if b.MaxActiveBranches > 0 {
		cfg.MaxActiveBranchesPerTask = b.MaxActiveBranches
	}
	if b.LowValueThreshold > 0 {
		cfg.LowValueBranchThreshold = b.LowValueThreshold
	}
	return cfg
}

func NewHypothesisLifecycleService(db *gorm.DB, blackboard *BlackboardService) *HypothesisLifecycleService {
	return &HypothesisLifecycleService{db: db, blackboard: blackboard}
}

func (s *HypothesisLifecycleService) EnsureDefaultGoalProfile(ctx context.Context, task model.AISecurityTask) (model.AIGoalProfile, error) {
	var existing model.AIGoalProfile
	err := s.db.WithContext(ctx).Where("task_id = ?", task.ID).First(&existing).Error
	if err == nil {
		return existing, nil
	}
	if err != gorm.ErrRecordNotFound {
		return model.AIGoalProfile{}, err
	}

	goalType, mode := inferGoalTypeAndMode(task)
	now := time.Now().UTC()
	profile := model.AIGoalProfile{
		TaskID:         task.ID,
		GoalType:       goalType,
		Name:           defaultGoalName(goalType, task.TaskType),
		Description:    "Hypothesis-driven exploration profile generated for backward-compatible task bootstrap.",
		RawUserGoal:    task.Objective,
		NormalizedGoal: normalizeGoal(task.Objective),
		Mode:           mode,
		CompletionPolicy: mustJSON(map[string]any{
			"stagnation_rounds":               3,
			"coverage_threshold":              0.8,
			"max_pending_hypotheses":          80,
			"max_pending_validation_intents":  40,
			"max_generated_intents_per_round": 6,
		}),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.db.WithContext(ctx).Create(&profile).Error; err != nil {
		return profile, err
	}
	nodeType := model.NodeCoverageGoal
	if goalType == model.GoalTypeExpansion {
		nodeType = model.NodeExpansionGoal
	}
	_, _ = s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          task.ID,
		NodeType:        nodeType,
		Title:           profile.Name,
		Summary:         profile.NormalizedGoal,
		Content:         profile,
		DedupSeed:       fmt.Sprintf("goal-profile-%d", profile.ID),
		ImportanceScore: 0.94,
		SourceType:      "system",
		SourceID:        fmt.Sprintf("goal-profile-%d", profile.ID),
	})
	appendAuditEvent(ctx, s.db, &task.ID, "goal_profile.created", "hypothesis-lifecycle", "Default GoalProfile assigned for task.", map[string]any{"goalType": goalType, "mode": mode})
	if goalType == model.GoalTypeExpansion {
		_ = s.ensureObjectiveLadder(ctx, task.ID, profile.ID)
	}
	return profile, nil
}

func (s *HypothesisLifecycleService) FormHypothesis(ctx context.Context, draft HypothesisDraft) (model.AIHypothesisNode, error) {
	if draft.HypothesisType == "" {
		draft.HypothesisType = model.HypothesisTypeInfoDisclosureCandidate
	}
	if draft.ConfidenceState == "" {
		draft.ConfidenceState = model.ConfidencePlausible
	}
	draft.Title = sanitizeUTF8(strings.TrimSpace(draft.Title))
	if draft.Title == "" {
		draft.Title = "Security hypothesis requires validation"
	}
	key := hypothesisPatternKey(draft.HypothesisType, draft.TargetEntity, draft.Title)
	if s.hasNegativePattern(ctx, draft.TaskID, key) {
		appendAuditEvent(ctx, s.db, &draft.TaskID, "hypothesis.suppressed_by_negative_fact", "dynamic-intent-expander", draft.Title, map[string]any{"patternKey": key})
		return model.AIHypothesisNode{}, gorm.ErrRecordNotFound
	}
	var existing model.AIHypothesisNode
	err := s.db.WithContext(ctx).
		Where("task_id = ? AND hypothesis_type = ? AND lower(title) = lower(?) AND target_entity = ? AND status IN ?",
			draft.TaskID, draft.HypothesisType, draft.Title, draft.TargetEntity,
			[]string{model.HypothesisStatusPending, model.HypothesisStatusValidating, model.HypothesisStatusValidated}).
		First(&existing).Error
	if err == nil {
		return existing, nil
	}
	if err != gorm.ErrRecordNotFound {
		return model.AIHypothesisNode{}, err
	}
	now := time.Now().UTC()
	h := model.AIHypothesisNode{
		TaskID:                 draft.TaskID,
		HypothesisType:         draft.HypothesisType,
		Title:                  draft.Title,
		Description:            sanitizeUTF8(draft.Description),
		ConfidenceState:        draft.ConfidenceState,
		Status:                 model.HypothesisStatusPending,
		SourceObservationRefs:  mustJSON(draft.SourceObservationRefs),
		SupportingEvidenceRefs: mustJSON([]uint{}),
		TargetEntity:           sanitizeUTF8(draft.TargetEntity),
		ExpectedCapability:     draft.ExpectedCapability,
		ValidationIntentRefs:   mustJSON([]uint{}),
		NegativeFactRefs:       mustJSON([]uint{}),
		UnverifiedRiskRefs:     mustJSON([]uint{}),
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := s.db.WithContext(ctx).Create(&h).Error; err != nil {
		return h, err
	}
	hNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          draft.TaskID,
		NodeType:        model.NodeHypothesis,
		Title:           h.Title,
		Summary:         h.Description,
		Content:         h,
		DedupSeed:       fmt.Sprintf("hypothesis-%d", h.ID),
		ImportanceScore: hypothesisImportance(h.ConfidenceState),
		SourceType:      "hypothesis-lifecycle",
		SourceID:        fmt.Sprintf("%d", h.ID),
	})
	for _, ref := range draft.SourceObservationRefs {
		if id, ok := parseUintRef(ref); ok && hNode.ID != 0 {
			_ = s.blackboard.AddEdge(ctx, draft.TaskID, id, hNode.ID, model.EdgeForms, 0.8, map[string]any{"hypothesisId": h.ID})
		}
	}
	appendAuditEvent(ctx, s.db, &draft.TaskID, "hypothesis.formed", "hypothesis-lifecycle", h.Title, map[string]any{"hypothesisId": h.ID, "type": h.HypothesisType, "expectedCapability": h.ExpectedCapability})
	return h, nil
}

func (s *HypothesisLifecycleService) CreateValidationIntent(ctx context.Context, h model.AIHypothesisNode, intentType, validationMethod string, priority float64, extraConstraints ...map[string]any) (model.AIIntent, error) {
	if intentType == "" {
		intentType = model.IntentBehaviorProbe
	}
	if validationMethod == "" {
		validationMethod = "collect_evidence"
	}
	existing, err := s.findExistingValidationIntent(ctx, h)
	if err == nil {
		return existing, nil
	}
	if err != gorm.ErrRecordNotFound {
		return model.AIIntent{}, err
	}
	if priority <= 0 {
		priority = 0.74
	}
	intent := model.AIIntent{
		TaskID:     h.TaskID,
		IntentType: intentType,
		Title:      "Validate hypothesis: " + h.Title,
		Objective:  h.Description,
		RequiredEvidence: mustJSON([]string{
			"validation_result",
			"scope_statement",
			"safety_statement",
		}),
		PriorityScore: priority,
		Status:        model.IntentStatusPending,
		CreatedBy:     "dynamic-intent-expander",
		CreatedReason: "Generated from pending hypothesis with expected capability gain.",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	intent.WithValidationMetadata(model.ValidationIntentMetadata{
		HypothesisID:               &h.ID,
		ValidationMethod:           validationMethod,
		ExpectedEvidence:           "evidence that validates or refutes: " + h.Title,
		ExpectedCapability:         h.ExpectedCapability,
		SuccessCondition:           "Evidence demonstrates the hypothesis is true within authorized scope.",
		FailureCondition:           "Evidence shows the path is not exploitable or does not support the hypothesis.",
		SafetyLevel:                "authorized_non_destructive",
		EnvironmentContextSnapshot: s.environmentSnapshot(ctx, h.TaskID),
	})
	if len(extraConstraints) > 0 && len(extraConstraints[0]) > 0 {
		intent.ConstraintsJSON = mergeIntentConstraints(intent.ConstraintsJSON, extraConstraints[0])
	}
	if err := s.db.WithContext(ctx).Create(&intent).Error; err != nil {
		return intent, err
	}
	_ = s.appendHypothesisIntentRef(ctx, h.ID, intent.ID)
	hNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          h.TaskID,
		NodeType:        model.NodeHypothesis,
		Title:           h.Title,
		Summary:         h.Description,
		Content:         h,
		DedupSeed:       fmt.Sprintf("hypothesis-%d", h.ID),
		ImportanceScore: hypothesisImportance(h.ConfidenceState),
		SourceType:      "hypothesis-lifecycle",
		SourceID:        fmt.Sprintf("%d", h.ID),
	})
	intentNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          h.TaskID,
		NodeType:        model.NodeIntent,
		Title:           intent.Title,
		Summary:         intent.Objective,
		Content:         intent,
		DedupSeed:       fmt.Sprintf("intent-%d", intent.ID),
		ImportanceScore: priority,
		SourceType:      intent.CreatedBy,
		SourceID:        fmt.Sprintf("%d", intent.ID),
	})
	if hNode.ID != 0 && intentNode.ID != 0 {
		_ = s.blackboard.AddEdge(ctx, h.TaskID, hNode.ID, intentNode.ID, model.EdgeGenerates, 0.86, map[string]any{"hypothesisId": h.ID, "intentId": intent.ID})
	}
	appendAuditEvent(ctx, s.db, &h.TaskID, "validation_intent.generated", "dynamic-intent-expander", intent.Title, map[string]any{"hypothesisId": h.ID, "intentId": intent.ID, "method": validationMethod})
	return intent, nil
}

func (s *HypothesisLifecycleService) findExistingValidationIntent(ctx context.Context, h model.AIHypothesisNode) (model.AIIntent, error) {
	statuses := []string{model.IntentStatusPending, model.IntentStatusRunning, model.IntentStatusCompleted}
	if s.db.Dialector != nil && s.db.Dialector.Name() == "postgres" {
		var existing model.AIIntent
		err := s.db.WithContext(ctx).
			Where("task_id = ? AND constraints_json @> ? AND status IN ?", h.TaskID, mustJSON(map[string]any{"hypothesis_id": h.ID}), statuses).
			First(&existing).Error
		return existing, err
	}

	var candidates []model.AIIntent
	if err := s.db.WithContext(ctx).
		Where("task_id = ? AND status IN ?", h.TaskID, statuses).
		Find(&candidates).Error; err != nil {
		return model.AIIntent{}, err
	}
	for _, candidate := range candidates {
		meta := candidate.ValidationMetadata()
		if meta.HypothesisID != nil && *meta.HypothesisID == h.ID {
			return candidate, nil
		}
	}
	return model.AIIntent{}, gorm.ErrRecordNotFound
}

func mergeIntentConstraints(base []byte, extra map[string]any) []byte {
	values := map[string]any{}
	if len(base) > 0 {
		_ = json.Unmarshal(base, &values)
	}
	for key, value := range extra {
		if strings.TrimSpace(key) == "" || value == nil {
			continue
		}
		values[key] = value
	}
	return model.JSONValue(values)
}

func (s *HypothesisLifecycleService) ResolveIntentResult(ctx context.Context, taskID uint, intent model.AIIntent, r HypothesisResolution) error {
	meta := intent.ValidationMetadata()
	if meta.HypothesisID == nil {
		return nil
	}
	var h model.AIHypothesisNode
	if err := s.db.WithContext(ctx).First(&h, *meta.HypothesisID).Error; err != nil {
		return err
	}
	if h.Status == model.HypothesisStatusValidated || h.Status == model.HypothesisStatusRefuted {
		return nil
	}
	if r.ToolBlocked {
		_, err := s.MarkInconclusive(ctx, h, model.UnverifiedReasonSafetyRestriction, firstNonEmpty(r.Reason, "Validation was blocked by safety policy."), r.EvidenceIDs, &intent.ID)
		return err
	}
	if r.ToolFailed {
		_, err := s.MarkInconclusive(ctx, h, model.UnverifiedReasonInconclusiveEvidence, firstNonEmpty(r.Reason, "Validation tool failed before the hypothesis could be resolved."), r.EvidenceIDs, &intent.ID)
		return err
	}
	if r.ValidationFailed && validationFailureShouldRemainInconclusive(r.Reason) {
		_, err := s.MarkInconclusive(ctx, h, model.UnverifiedReasonMethodNotObservable, firstNonEmpty(r.Reason, "The current validation method produced evidence, but it did not resolve the hypothesis."), r.EvidenceIDs, &intent.ID)
		return err
	}
	if len(r.EvidenceIDs) == 0 || r.ValidationFailed {
		_, err := s.RefuteHypothesis(ctx, h, firstNonEmpty(r.Reason, "Validation produced no supporting evidence."), r.EvidenceIDs, &intent.ID)
		return err
	}
	_, err := s.ValidateHypothesis(ctx, h, r.EvidenceIDs, &intent.ID)
	return err
}

func validationFailureShouldRemainInconclusive(reason string) bool {
	text := strings.ToLower(strings.TrimSpace(reason))
	return strings.Contains(text, model.UnverifiedReasonMethodNotObservable) ||
		strings.Contains(text, "no observable diff") ||
		strings.Contains(text, "no observable difference") ||
		strings.Contains(text, "alternate validation") ||
		strings.Contains(text, "interaction context") ||
		strings.Contains(text, "method did not")
}

func (s *HypothesisLifecycleService) ValidateHypothesis(ctx context.Context, h model.AIHypothesisNode, evidenceIDs []uint, intentID *uint) (model.AIHypothesisNode, error) {
	now := time.Now().UTC()
	updates := map[string]any{
		"confidence_state":         model.ConfidenceValidated,
		"status":                   model.HypothesisStatusValidated,
		"supporting_evidence_refs": mustJSON(evidenceIDs),
		"validated_at":             now,
		"updated_at":               now,
	}
	if err := s.db.WithContext(ctx).Model(&model.AIHypothesisNode{}).Where("id = ?", h.ID).Updates(updates).Error; err != nil {
		return h, err
	}
	h.ConfidenceState = model.ConfidenceValidated
	h.Status = model.HypothesisStatusValidated
	h.SupportingEvidenceRefs = mustJSON(evidenceIDs)
	h.ValidatedAt = &now
	_, _ = s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          h.TaskID,
		NodeType:        model.NodeHypothesis,
		Title:           h.Title,
		Summary:         h.Description,
		Content:         h,
		DedupSeed:       fmt.Sprintf("hypothesis-%d", h.ID),
		ImportanceScore: 0.98,
		SourceType:      "hypothesis-lifecycle",
		SourceID:        fmt.Sprintf("%d", h.ID),
		EvidenceRefs:    evidenceIDs,
	})
	appendAuditEvent(ctx, s.db, &h.TaskID, "hypothesis.validated", "hypothesis-lifecycle", h.Title, map[string]any{"hypothesisId": h.ID, "intentId": intentID, "evidenceIds": evidenceIDs})
	return h, nil
}

func (s *HypothesisLifecycleService) RefuteHypothesis(ctx context.Context, h model.AIHypothesisNode, reason string, evidenceIDs []uint, intentID *uint) (model.AINegativeFact, error) {
	now := time.Now().UTC()
	nf := model.AINegativeFact{
		TaskID:              h.TaskID,
		HypothesisID:        &h.ID,
		Title:               "Refuted: " + h.Title,
		TestedPath:          h.TargetEntity,
		Reason:              sanitizeUTF8(reason),
		EvidenceRefs:        mustJSON(evidenceIDs),
		SimilarPatternKey:   hypothesisPatternKey(h.HypothesisType, h.TargetEntity, h.Title),
		CreatedFromIntentID: intentID,
		CreatedAt:           now,
	}
	if err := s.db.WithContext(ctx).Create(&nf).Error; err != nil {
		return nf, err
	}
	_ = s.db.WithContext(ctx).Model(&model.AIHypothesisNode{}).Where("id = ?", h.ID).Updates(map[string]any{
		"confidence_state":   model.ConfidenceRefuted,
		"status":             model.HypothesisStatusRefuted,
		"negative_fact_refs": mustJSON([]uint{nf.ID}),
		"updated_at":         now,
	}).Error
	nfNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          h.TaskID,
		NodeType:        model.NodeNegativeFact,
		Title:           nf.Title,
		Summary:         nf.Reason,
		Content:         nf,
		DedupSeed:       fmt.Sprintf("negative-fact-%d", nf.ID),
		ImportanceScore: 0.54,
		SourceType:      "hypothesis-lifecycle",
		SourceID:        fmt.Sprintf("%d", nf.ID),
		EvidenceRefs:    evidenceIDs,
	})
	hNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          h.TaskID,
		NodeType:        model.NodeHypothesis,
		Title:           h.Title,
		Summary:         h.Description,
		Content:         h,
		DedupSeed:       fmt.Sprintf("hypothesis-%d", h.ID),
		ImportanceScore: 0.42,
		SourceType:      "hypothesis-lifecycle",
		SourceID:        fmt.Sprintf("%d", h.ID),
	})
	if nfNode.ID != 0 && hNode.ID != 0 {
		_ = s.blackboard.AddEdge(ctx, h.TaskID, nfNode.ID, hNode.ID, model.EdgeRefutes, 0.9, map[string]any{"negativeFactId": nf.ID, "hypothesisId": h.ID})
	}
	_ = s.suppressSimilarPendingBranches(ctx, h, nf)
	appendAuditEvent(ctx, s.db, &h.TaskID, "hypothesis.refuted", "hypothesis-lifecycle", h.Title, map[string]any{"hypothesisId": h.ID, "negativeFactId": nf.ID, "intentId": intentID})
	return nf, nil
}

func (s *HypothesisLifecycleService) MarkInconclusive(ctx context.Context, h model.AIHypothesisNode, reason, detail string, evidenceIDs []uint, intentID *uint) (model.AIUnverifiedRisk, error) {
	now := time.Now().UTC()
	risk := model.AIUnverifiedRisk{
		TaskID:            h.TaskID,
		HypothesisID:      &h.ID,
		Title:             "Unverified: " + h.Title,
		Reason:            reason,
		Detail:            sanitizeUTF8(detail),
		ObservationRefs:   h.SourceObservationRefs,
		EvidenceRefs:      mustJSON(evidenceIDs),
		BlockedByIntentID: intentID,
		CreatedAt:         now,
	}
	if err := s.db.WithContext(ctx).Create(&risk).Error; err != nil {
		return risk, err
	}
	_ = s.db.WithContext(ctx).Model(&model.AIHypothesisNode{}).Where("id = ?", h.ID).Updates(map[string]any{
		"confidence_state":     model.ConfidenceInconclusive,
		"status":               model.HypothesisStatusInconclusive,
		"unverified_risk_refs": mustJSON([]uint{risk.ID}),
		"updated_at":           now,
	}).Error
	riskNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          h.TaskID,
		NodeType:        model.NodeUnverifiedRisk,
		Title:           risk.Title,
		Summary:         risk.Detail,
		Content:         risk,
		DedupSeed:       fmt.Sprintf("unverified-risk-%d", risk.ID),
		ImportanceScore: 0.7,
		SourceType:      "hypothesis-lifecycle",
		SourceID:        fmt.Sprintf("%d", risk.ID),
		EvidenceRefs:    evidenceIDs,
	})
	hNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          h.TaskID,
		NodeType:        model.NodeHypothesis,
		Title:           h.Title,
		Summary:         h.Description,
		Content:         h,
		DedupSeed:       fmt.Sprintf("hypothesis-%d", h.ID),
		ImportanceScore: 0.62,
		SourceType:      "hypothesis-lifecycle",
		SourceID:        fmt.Sprintf("%d", h.ID),
	})
	if riskNode.ID != 0 && hNode.ID != 0 {
		_ = s.blackboard.AddEdge(ctx, h.TaskID, riskNode.ID, hNode.ID, model.EdgeBlocks, 0.82, map[string]any{"unverifiedRiskId": risk.ID, "hypothesisId": h.ID})
	}
	appendAuditEvent(ctx, s.db, &h.TaskID, "hypothesis.inconclusive", "hypothesis-lifecycle", h.Title, map[string]any{"hypothesisId": h.ID, "unverifiedRiskId": risk.ID, "reason": reason})
	return risk, nil
}

func (s *HypothesisLifecycleService) EnsureCapabilityHypothesis(ctx context.Context, taskID uint, capType, target string, evidenceIDs []uint, intentID *uint) (model.AIHypothesisNode, error) {
	if intentID != nil {
		var intent model.AIIntent
		if err := s.db.WithContext(ctx).First(&intent, *intentID).Error; err == nil {
			if hid := intent.HypothesisID(); hid != nil {
				var h model.AIHypothesisNode
				if err := s.db.WithContext(ctx).First(&h, *hid).Error; err == nil {
					if h.Status != model.HypothesisStatusValidated {
						return s.ValidateHypothesis(ctx, h, evidenceIDs, intentID)
					}
					return h, nil
				}
			}
		}
	}
	h, err := s.FormHypothesis(ctx, HypothesisDraft{
		TaskID:                taskID,
		HypothesisType:        model.HypothesisTypeLegacy,
		Title:                 "Legacy capability proof: " + capType,
		Description:           "Synthetic hypothesis created to provide backward-compatible capability lineage.",
		ConfidenceState:       model.ConfidenceStrong,
		SourceObservationRefs: []string{},
		TargetEntity:          target,
		ExpectedCapability:    capType,
	})
	if err != nil {
		return h, err
	}
	return s.ValidateHypothesis(ctx, h, evidenceIDs, intentID)
}

func (s *HypothesisLifecycleService) ExpandFromCapability(ctx context.Context, cap model.AICapability, budget ExpansionBudget) ([]model.AIHypothesisNode, error) {
	decision := NewExplorationBudgetManager(s.db).AllowIntentGenerationFor(ctx, cap.TaskID, budget.MaxGeneratedPerRound, budget.toConfig(), "capability_expansion")
	if !decision.Allowed {
		appendAuditEvent(ctx, s.db, &cap.TaskID, "dynamic_expander.throttled", "exploration-budget-manager", decision.Reason, map[string]any{"capabilityId": cap.ID, "metrics": decision.Metrics})
		return nil, nil
	}
	candidates := s.contextualHypothesesForCapability(ctx, cap)
	sortHypothesisDraftsByExpansionValue(candidates)
	created := []model.AIHypothesisNode{}
	for _, draft := range candidates {
		if len(created) >= decision.MaxToGenerate {
			break
		}
		h, err := s.FormHypothesis(ctx, draft)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				continue
			}
			return created, err
		}
		created = append(created, h)
		intentType := intentTypeForCapability(h.ExpectedCapability)
		_, _ = s.CreateValidationIntent(ctx, h, intentType, "contextual_capability_expansion", 0.78)
	}
	appendAuditEvent(ctx, s.db, &cap.TaskID, "dynamic_expander.completed", "dynamic-intent-expander", "Contextual capability expansion completed.", map[string]any{"capabilityId": cap.ID, "generatedHypotheses": len(created)})
	return created, nil
}

func (s *HypothesisLifecycleService) CreateObservedCapabilityValidationIntent(ctx context.Context, cap model.AICapability) (model.AIIntent, error) {
	evidenceIDs := uintJSONList(cap.EvidenceRefs)
	sourceRefs := []string{fmt.Sprintf("capability:%d", cap.ID)}
	for _, evidenceID := range evidenceIDs {
		sourceRefs = append(sourceRefs, fmt.Sprintf("evidence:%d", evidenceID))
	}
	h, err := s.FormHypothesis(ctx, HypothesisDraft{
		TaskID:                cap.TaskID,
		HypothesisType:        hypothesisTypeForCapability(cap.CapabilityType),
		Title:                 "Verify observed capability: " + cap.CapabilityType,
		Description:           fmt.Sprintf("Re-validate observed capability %s on %s using Rabbit-controlled validation before it can advance the goal.", cap.CapabilityType, cap.Target),
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: sourceRefs,
		TargetEntity:          cap.Target,
		ExpectedCapability:    cap.CapabilityType,
	})
	if err != nil {
		return model.AIIntent{}, err
	}
	return s.CreateValidationIntent(ctx, h, intentTypeForCapability(cap.CapabilityType), "observed_capability_promotion", 0.82)
}

func (s *HypothesisLifecycleService) contextualHypothesesForCapability(ctx context.Context, cap model.AICapability) []HypothesisDraft {
	env := s.environmentSnapshot(ctx, cap.TaskID)
	sourceRef := fmt.Sprintf("capability:%d", cap.ID)
	targetLower := strings.ToLower(cap.Target + " " + cap.ProofSummary)
	drafts := []HypothesisDraft{}
	add := func(t, title, desc, expected string) {
		drafts = append(drafts, HypothesisDraft{
			TaskID:                cap.TaskID,
			HypothesisType:        t,
			Title:                 title,
			Description:           desc,
			ConfidenceState:       model.ConfidencePlausible,
			SourceObservationRefs: []string{sourceRef},
			TargetEntity:          cap.Target,
			ExpectedCapability:    expected,
		})
	}
	switch cap.CapabilityType {
	case model.CapFileRead, model.CapConfigRead, model.CapSourceCodeRead:
		if looksConfigLike(targetLower) {
			add(model.HypothesisTypeSecretReuseCandidate, "Readable configuration may contain reusable secrets", "Validate whether the proven read capability exposes credentials, API keys, JWT secrets, or database DSNs that can unlock additional state.", model.CapSecretDiscovered)
		}
		add(model.HypothesisTypeInfoDisclosureCandidate, "Readable file path may reveal hidden attack surface", "Validate whether the readable artifact identifies internal routes, upstream services, admin paths, or deployment assumptions useful for further exploration.", model.CapInternalServiceAccess)
	case model.CapSecretDiscovered, model.CapCredentialObtained:
		add(model.HypothesisTypeCredentialReuseCandidate, "Discovered secret may enable authenticated access", "Validate whether the discovered secret can establish an authenticated session or access a privileged API in authorized scope.", model.CapAuthenticatedSession)
	case model.CapAuthenticatedSession:
		add(model.HypothesisTypeAuthzBypassCandidate, "Authenticated session may cross an authorization boundary", "Validate whether the session can reach admin or cross-tenant objects without the expected ownership or role checks.", model.CapCrossUserObjectAccess)
		add(model.HypothesisTypeBusinessLogicCandidate, "Authenticated workflow may allow unauthorized state transition", "Validate whether state-changing requests enforce actor, object, and workflow-step constraints under safe non-destructive fixtures.", model.CapUnauthorizedState)
	case model.CapCommandExecution:
		if envMatches(env, "orchestration_layer", "kubernetes") || strings.Contains(targetLower, "kubernetes") || strings.Contains(targetLower, "serviceaccount") {
			add(model.HypothesisTypeLateralAccessCandidate, "Command execution context may expose Kubernetes service account access", "Validate read-only access to service account metadata, namespace context, and API reachability inside authorized scope.", model.CapInternalServiceAccess)
		}
		add(model.HypothesisTypeFileReadCandidate, "Command execution may enable sensitive local configuration reads", "Validate whether non-destructive local reads expose environment, config, or credential material.", model.CapFileRead)
	case model.CapSQLInjection:
		add(model.HypothesisTypeInfoDisclosureCandidate, "SQL injection capability may expose database-backed state", "Validate whether the proven input can reveal additional authorized-scope records, schema signals, or protected state using non-destructive differential evidence rather than bulk extraction.", model.CapDatabaseRead)
	case model.CapCrossUserObjectAccess:
		add(model.HypothesisTypeBusinessLogicCandidate, "Cross-user object access may enable unauthorized state changes", "Validate whether the same boundary weakness permits safe state transitions, workflow bypass, replay, or business value tampering.", model.CapUnauthorizedState)
	case model.CapUnauthorizedState:
		add(model.HypothesisTypeBusinessLogicCandidate, "Unauthorized state transition may bypass workflow constraints", "Validate whether alternate request ordering, replay, or omitted workflow steps can reproduce the transition safely.", model.CapWorkflowStepBypass)
	case model.CapWorkflowStepBypass:
		add(model.HypothesisTypeBusinessLogicCandidate, "Workflow bypass may permit business value tampering", "Validate whether safe fixture values can be modified outside expected process constraints.", model.CapBusinessValueTamper)
	}
	return drafts
}

func (s *HypothesisLifecycleService) ensureObjectiveLadder(ctx context.Context, taskID, goalProfileID uint) error {
	names := []string{"Foothold Context", "Local Privilege / Secrets", "Reachable Assets", "Identity / Credential Expansion", "Critical Assets", "High-Value Proof"}
	for idx, name := range names {
		row := model.AIObjectiveLadder{
			TaskID:         taskID,
			GoalProfileID:  &goalProfileID,
			Level:          idx + 1,
			Name:           name,
			Status:         "pending",
			CapabilityRefs: mustJSON([]uint{}),
			HypothesisRefs: mustJSON([]uint{}),
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		_ = s.db.WithContext(ctx).Where("task_id = ? AND level = ?", taskID, row.Level).FirstOrCreate(&row).Error
	}
	return nil
}

func (s *HypothesisLifecycleService) appendHypothesisIntentRef(ctx context.Context, hypothesisID, intentID uint) error {
	var h model.AIHypothesisNode
	if err := s.db.WithContext(ctx).First(&h, hypothesisID).Error; err != nil {
		return err
	}
	ids := uintJSONList(h.ValidationIntentRefs)
	ids = appendUniqueUint(ids, intentID)
	return s.db.WithContext(ctx).Model(&model.AIHypothesisNode{}).Where("id = ?", hypothesisID).Updates(map[string]any{
		"validation_intent_refs": mustJSON(ids),
		"status":                 model.HypothesisStatusValidating,
		"updated_at":             time.Now().UTC(),
	}).Error
}

func (s *HypothesisLifecycleService) environmentSnapshot(ctx context.Context, taskID uint) map[string]any {
	var env model.AIEnvironmentModel
	if err := s.db.WithContext(ctx).Where("task_id = ?", taskID).First(&env).Error; err != nil || len(env.ModelJSON) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if json.Unmarshal(env.ModelJSON, &out) != nil {
		return map[string]any{}
	}
	return out
}

func (s *HypothesisLifecycleService) hasNegativePattern(ctx context.Context, taskID uint, patternKey string) bool {
	var count int64
	_ = s.db.WithContext(ctx).Model(&model.AINegativeFact{}).Where("task_id = ? AND similar_pattern_key = ?", taskID, patternKey).Count(&count).Error
	return count > 0
}

func (s *HypothesisLifecycleService) suppressSimilarPendingBranches(ctx context.Context, h model.AIHypothesisNode, nf model.AINegativeFact) error {
	var similar []model.AIHypothesisNode
	if err := s.db.WithContext(ctx).
		Where("task_id = ? AND id <> ? AND hypothesis_type = ? AND target_entity = ? AND status IN ?",
			h.TaskID, h.ID, h.HypothesisType, h.TargetEntity,
			[]string{model.HypothesisStatusPending, model.HypothesisStatusValidating}).
		Find(&similar).Error; err != nil {
		return err
	}
	suppressedIDs := []uint{}
	for _, item := range similar {
		if err := s.db.WithContext(ctx).Model(&model.AIHypothesisNode{}).Where("id = ?", item.ID).Updates(map[string]any{
			"status":             model.HypothesisStatusSuppressed,
			"confidence_state":   model.ConfidenceRefuted,
			"negative_fact_refs": mustJSON([]uint{nf.ID}),
			"updated_at":         time.Now().UTC(),
		}).Error; err != nil {
			return err
		}
		suppressedIDs = append(suppressedIDs, item.ID)
		_ = s.db.WithContext(ctx).Model(&model.AIIntent{}).
			Where("task_id = ? AND status = ? AND constraints_json @> ?", h.TaskID, model.IntentStatusPending, mustJSON(map[string]any{"hypothesis_id": item.ID})).
			Updates(map[string]any{"status": model.IntentStatusSuppressed, "updated_at": time.Now().UTC()}).Error
	}
	if len(suppressedIDs) > 0 {
		appendAuditEvent(ctx, s.db, &h.TaskID, "negative_fact.suppressed_similar_branches", "hypothesis-lifecycle", "Suppressed pending branches matching a refuted hypothesis.", map[string]any{"negativeFactId": nf.ID, "suppressedHypothesisIds": suppressedIDs})
	}
	return nil
}

func inferGoalTypeAndMode(task model.AISecurityTask) (string, string) {
	objective := strings.ToLower(task.Objective)
	if strings.Contains(objective, "proof") || strings.Contains(objective, "prove") || strings.Contains(objective, "证明") || strings.Contains(objective, "拿到") {
		return model.GoalTypeTerminal, model.GoalModeTerminalProof
	}
	switch task.TaskType {
	case model.TaskTypeCodeAudit:
		return model.GoalTypeCoverage, model.GoalModeCodeAudit
	case model.TaskTypePentest:
		return model.GoalTypeCoverage, model.GoalModeWebPentest
	case model.TaskTypeInternalPentest:
		return model.GoalTypeExpansion, model.GoalModeInternal
	case model.TaskTypeTerminalProof:
		return model.GoalTypeTerminal, model.GoalModeTerminalProof
	case model.TaskTypeHybrid:
		return model.GoalTypeCoverage, model.GoalModeWebPentest
	default:
		return model.GoalTypeCoverage, model.GoalModeCodeAudit
	}
}

func defaultGoalName(goalType, taskType string) string {
	switch goalType {
	case model.GoalTypeTerminal:
		return "Terminal proof objective"
	case model.GoalTypeExpansion:
		return "Hypothesis-driven expansion objective"
	default:
		return "Hypothesis-driven coverage objective for " + taskType
	}
}

func normalizeGoal(goal string) string {
	goal = strings.TrimSpace(goal)
	if goal == "" {
		return "Validate authorized security hypotheses with evidence and record unverified or negative outcomes explicitly."
	}
	return goal
}

func hypothesisImportance(confidence string) float64 {
	switch confidence {
	case model.ConfidenceValidated:
		return 0.98
	case model.ConfidenceStrong:
		return 0.86
	case model.ConfidencePlausible:
		return 0.74
	case model.ConfidenceRefuted:
		return 0.38
	default:
		return 0.62
	}
}

func hypothesisPatternKey(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return strings.Join(cleaned, "|")
}

func uintJSONList(raw []byte) []uint {
	if len(raw) == 0 {
		return []uint{}
	}
	var ids []uint
	if json.Unmarshal(raw, &ids) == nil {
		return ids
	}
	var floats []float64
	if json.Unmarshal(raw, &floats) == nil {
		for _, f := range floats {
			ids = append(ids, uint(f))
		}
	}
	return ids
}

func appendUniqueUint(values []uint, next uint) []uint {
	for _, value := range values {
		if value == next {
			return values
		}
	}
	return append(values, next)
}

func parseUintRef(ref string) (uint, bool) {
	var id uint
	if _, err := fmt.Sscanf(ref, "node:%d", &id); err == nil && id > 0 {
		return id, true
	}
	if _, err := fmt.Sscanf(ref, "blackboard_node:%d", &id); err == nil && id > 0 {
		return id, true
	}
	return 0, false
}

func looksConfigLike(text string) bool {
	configHints := []string{".env", "config", "settings", "application.yml", "application.properties", "nginx.conf", "database", "jwt", "secret", "credential"}
	for _, hint := range configHints {
		if strings.Contains(text, hint) {
			return true
		}
	}
	return false
}

func envMatches(env map[string]any, field, expected string) bool {
	value, ok := env[field]
	if !ok {
		return false
	}
	switch v := value.(type) {
	case string:
		return strings.Contains(strings.ToLower(v), expected)
	case map[string]any:
		for key, raw := range v {
			if strings.Contains(strings.ToLower(key), expected) {
				return true
			}
			if s, ok := raw.(string); ok && strings.Contains(strings.ToLower(s), expected) {
				return true
			}
		}
	}
	return false
}

func intentTypeForCapability(capability string) string {
	switch capability {
	case model.CapAuthenticatedSession, model.CapAdminAccess:
		return model.IntentAuthProbe
	case model.CapFileRead, model.CapConfigRead, model.CapSecretDiscovered:
		return model.IntentSecretVerify
	case model.CapInternalServiceAccess, model.CapLateralAccess, model.CapDatabaseRead:
		return model.IntentCapabilityExpand
	case model.CapSQLInjection:
		return model.IntentSQLiProbe
	default:
		return model.IntentBehaviorProbe
	}
}

func hypothesisTypeForCapability(capability string) string {
	switch capability {
	case model.CapCrossUserObjectAccess, model.CapArbitraryObjectAccess:
		return model.HypothesisTypeIDORCandidate
	case model.CapUnauthorizedState, model.CapWorkflowStepBypass, model.CapBusinessValueTamper, model.CapReplaySuccess:
		return model.HypothesisTypeBusinessLogicCandidate
	case model.CapSQLInjection:
		return model.HypothesisTypeInjectionCandidate
	case model.CapDatabaseRead:
		return model.HypothesisTypeInfoDisclosureCandidate
	case model.CapFileRead, model.CapConfigRead, model.CapSourceCodeRead:
		return model.HypothesisTypeFileReadCandidate
	case model.CapFileWrite, model.CapUploadWrite:
		return model.HypothesisTypeFileWriteCandidate
	case model.CapCommandExecution:
		return model.HypothesisTypeCommandExecutionCandidate
	case model.CapSSRFInternalAccess, model.CapInternalServiceAccess:
		return model.HypothesisTypeSSRFCandidate
	case model.CapAdminAccess, model.CapAuthenticatedSession:
		return model.HypothesisTypeAuthzBypassCandidate
	case model.CapSecretDiscovered, model.CapCredentialObtained:
		return model.HypothesisTypeSecretReuseCandidate
	default:
		return model.HypothesisTypeInfoDisclosureCandidate
	}
}
