package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type StateExpansionPlannerService struct {
	db *gorm.DB
}

type StateExpansionScoringWeights struct {
	CapabilityUnlock float64
	GraphExpansion   float64
	Novelty          float64
	RiskValue        float64
	CoverageGain     float64
	EvidenceQuality  float64
	ExecutionCost    float64
	SafetyRisk       float64
	DuplicatePenalty float64
	GoalTypeBoost    float64
	EnvironmentBoost float64
}

func DefaultStateExpansionScoringWeights() StateExpansionScoringWeights {
	return StateExpansionScoringWeights{
		CapabilityUnlock: 0.24,
		GraphExpansion:   0.20,
		RiskValue:        0.17,
		Novelty:          0.12,
		CoverageGain:     0.05,
		EvidenceQuality:  0.08,
		ExecutionCost:    0.08,
		SafetyRisk:       0.08,
		DuplicatePenalty: 0.22,
		GoalTypeBoost:    0.12,
		EnvironmentBoost: 0.08,
	}
}

type negativePenaltyResult struct {
	Score  float64
	Refs   []uint
	Reason string
}

type environmentAlignmentResult struct {
	Boost  float64
	Refs   []string
	Reason string
}

type plannerContext struct {
	GoalProfile   model.AIGoalProfile
	Environment   map[string]any
	Capabilities  []model.AICapability
	NegativeFacts []model.AINegativeFact
	CoverageItems []model.AICoverageItem
}

func NewStateExpansionPlannerService(db *gorm.DB) *StateExpansionPlannerService {
	return &StateExpansionPlannerService{db: db}
}

func (s *StateExpansionPlannerService) ScorePendingValidationIntents(ctx context.Context, task model.AISecurityTask) error {
	pctx := s.loadPlannerContext(ctx, task)
	var intents []model.AIIntent
	if err := s.db.WithContext(ctx).
		Where("task_id = ? AND status = ?", task.ID, model.IntentStatusPending).
		Order("priority_score desc, created_at asc").
		Limit(80).
		Find(&intents).Error; err != nil {
		return err
	}
	scored := 0
	skippedNoMetadata := 0
	skippedMissingHypothesis := 0
	negativePenaltyCount := 0
	environmentBoostCount := 0
	var topIntentID uint
	var topScore float64
	for _, intent := range intents {
		meta := intent.ValidationMetadata()
		if meta.HypothesisID == nil {
			skippedNoMetadata++
			continue
		}
		var h model.AIHypothesisNode
		if err := s.db.WithContext(ctx).First(&h, *meta.HypothesisID).Error; err != nil {
			skippedMissingHypothesis++
			continue
		}
		score := ScoreBranchValue(task, pctx, h, intent)
		intent.PriorityScore = score.FinalScore
		if err := intent.WithBranchValue(score); err != nil {
			return err
		}
		intent.UpdatedAt = time.Now().UTC()
		if err := s.db.WithContext(ctx).Save(&intent).Error; err != nil {
			return err
		}
		if score.DuplicatePenalty > 0 {
			negativePenaltyCount++
		}
		if score.EnvironmentAlignmentBoost != 0 {
			environmentBoostCount++
		}
		if topIntentID == 0 || score.FinalScore > topScore {
			topIntentID = intent.ID
			topScore = score.FinalScore
		}
		scored++
	}
	if scored > 0 || skippedNoMetadata > 0 || skippedMissingHypothesis > 0 {
		appendAuditEvent(ctx, s.db, &task.ID, "state_expansion_planner.scored", "state-expansion-planner", "Pending validation intents rescored by branch value.", map[string]any{
			"pendingIntents":              len(intents),
			"scoredIntents":               scored,
			"skippedNoValidationMetadata": skippedNoMetadata,
			"skippedMissingHypothesis":    skippedMissingHypothesis,
			"topIntentId":                 topIntentID,
			"topScore":                    topScore,
			"negativePenaltyCount":        negativePenaltyCount,
			"environmentBoostCount":       environmentBoostCount,
		})
	}
	return nil
}

func (s *StateExpansionPlannerService) loadPlannerContext(ctx context.Context, task model.AISecurityTask) plannerContext {
	pctx := plannerContext{Environment: map[string]any{}}
	_ = s.db.WithContext(ctx).Where("task_id = ?", task.ID).First(&pctx.GoalProfile).Error
	if pctx.GoalProfile.GoalType == "" {
		pctx.GoalProfile.GoalType, pctx.GoalProfile.Mode = inferGoalTypeAndMode(task)
	}
	var env model.AIEnvironmentModel
	if err := s.db.WithContext(ctx).Where("task_id = ?", task.ID).First(&env).Error; err == nil && len(env.ModelJSON) > 0 {
		_ = json.Unmarshal(env.ModelJSON, &pctx.Environment)
	}
	_ = s.db.WithContext(ctx).Where("task_id = ?", task.ID).Find(&pctx.Capabilities).Error
	_ = s.db.WithContext(ctx).Where("task_id = ?", task.ID).Find(&pctx.NegativeFacts).Error
	_ = s.db.WithContext(ctx).Where("task_id = ?", task.ID).Find(&pctx.CoverageItems).Error
	return pctx
}

func ScoreBranchValue(task model.AISecurityTask, pctx plannerContext, h model.AIHypothesisNode, intent model.AIIntent) model.BranchValue {
	return ScoreBranchValueWithWeights(task, pctx, h, intent, DefaultStateExpansionScoringWeights())
}

func ScoreBranchValueWithWeights(task model.AISecurityTask, pctx plannerContext, h model.AIHypothesisNode, intent model.AIIntent, weights StateExpansionScoringWeights) model.BranchValue {
	negative := duplicatePenaltyScore(h, pctx.NegativeFacts)
	environment := environmentAlignment(h, pctx.Environment)
	score := model.BranchValue{
		CapabilityUnlockScore:     capabilityUnlockScore(h.ExpectedCapability, pctx.GoalProfile.GoalType),
		GraphExpansionScore:       graphExpansionScore(h),
		NoveltyScore:              noveltyScore(h, pctx.Capabilities, pctx.NegativeFacts),
		RiskValue:                 riskValue(h.HypothesisType, h.ExpectedCapability),
		CoverageGain:              coverageGainScore(h, pctx.CoverageItems, pctx.GoalProfile.GoalType),
		ExecutionCost:             executionCostScore(intent),
		SafetyRisk:                safetyRiskScore(intent, h),
		DuplicatePenalty:          negative.Score,
		EvidenceQuality:           expectedEvidenceQuality(intent),
		EnvironmentAlignmentBoost: environment.Boost,
		NegativeFactRefs:          negative.Refs,
		MatchedEnvironmentRefs:    environment.Refs,
		ScoredAt:                  time.Now().UTC(),
	}
	if pctx.GoalProfile.GoalType == model.GoalTypeTerminal {
		score.GoalTypeBoost = terminalAlignmentBonus(task.Objective, h)
	}
	if pctx.GoalProfile.GoalType == model.GoalTypeExpansion {
		score.GoalTypeBoost = expansionLadderBonus(h.ExpectedCapability)
	}
	score.FinalScore = clamp01(
		weights.CapabilityUnlock*score.CapabilityUnlockScore +
			weights.GraphExpansion*score.GraphExpansionScore +
			weights.RiskValue*score.RiskValue +
			weights.Novelty*score.NoveltyScore +
			weights.CoverageGain*score.CoverageGain +
			weights.EvidenceQuality*score.EvidenceQuality +
			weights.GoalTypeBoost*score.GoalTypeBoost +
			weights.EnvironmentBoost*score.EnvironmentAlignmentBoost -
			weights.ExecutionCost*score.ExecutionCost -
			weights.SafetyRisk*score.SafetyRisk -
			weights.DuplicatePenalty*score.DuplicatePenalty,
	)
	score.Reason = branchScoreReason(score, pctx.GoalProfile.GoalType, h, negative, environment)
	return score
}

func capabilityUnlockScore(capability, goalType string) float64 {
	base := map[string]float64{
		model.CapCommandExecution:      1.0,
		model.CapAdminAccess:           0.96,
		model.CapCredentialObtained:    0.92,
		model.CapAuthenticatedSession:  0.86,
		model.CapSecretDiscovered:      0.84,
		model.CapFileWrite:             0.82,
		model.CapSQLInjection:          0.82,
		model.CapFileRead:              0.78,
		model.CapInternalServiceAccess: 0.76,
		model.CapLateralAccess:         0.9,
		model.CapUploadWrite:           0.72,
		model.CapArbitraryObjectAccess: 0.68,
		model.CapCrossUserObjectAccess: 0.88,
		model.CapUnauthorizedState:     0.84,
		model.CapBusinessValueTamper:   0.82,
		model.CapWorkflowStepBypass:    0.8,
		model.CapReplaySuccess:         0.72,
		model.CapBrowserExecution:      0.62,
	}
	if value, ok := base[capability]; ok {
		return value
	}
	if goalType == model.GoalTypeCoverage {
		return 0.48
	}
	return 0.42
}

func graphExpansionScore(h model.AIHypothesisNode) float64 {
	score := 0.45
	switch h.ExpectedCapability {
	case model.CapCommandExecution, model.CapAdminAccess, model.CapCredentialObtained, model.CapAuthenticatedSession, model.CapInternalServiceAccess, model.CapLateralAccess, model.CapCrossUserObjectAccess, model.CapUnauthorizedState:
		score += 0.28
	case model.CapFileRead, model.CapSecretDiscovered, model.CapSQLInjection, model.CapBusinessValueTamper, model.CapWorkflowStepBypass:
		score += 0.18
	}
	if len(h.SourceObservationRefs) > 2 {
		score += 0.06
	}
	return clamp01(score)
}

func noveltyScore(h model.AIHypothesisNode, caps []model.AICapability, negatives []model.AINegativeFact) float64 {
	score := 0.5
	target := strings.ToLower(h.TargetEntity)
	newCapability := true
	newTarget := true
	for _, cap := range caps {
		if cap.CapabilityType == h.ExpectedCapability && strings.EqualFold(strings.TrimSpace(cap.Target), strings.TrimSpace(h.TargetEntity)) {
			score -= 0.45
			newCapability = false
			newTarget = false
		} else if cap.CapabilityType == h.ExpectedCapability {
			score -= 0.18
			newCapability = false
		}
	}
	newHypothesisType := true
	for _, nf := range negatives {
		if nf.SimilarPatternKey == hypothesisPatternKey(h.HypothesisType, h.TargetEntity, h.Title) {
			score -= 0.5
		}
		if strings.EqualFold(nf.TestedPath, h.TargetEntity) {
			newTarget = false
			score -= 0.18
		}
		if strings.Contains(strings.ToLower(nf.Title), strings.ToLower(h.HypothesisType)) {
			newHypothesisType = false
		}
	}
	if newTarget {
		score += 0.12
	}
	if strings.Contains(target, "?") || strings.Contains(target, "param") || strings.Contains(target, "parameter") {
		score += 0.06
	}
	if newHypothesisType {
		score += 0.1
	}
	if newCapability {
		score += 0.12
	}
	return clamp01(score)
}

func riskValue(hType, capability string) float64 {
	switch capability {
	case model.CapCommandExecution, model.CapAdminAccess:
		return 1.0
	case model.CapFileWrite, model.CapCredentialObtained, model.CapSQLInjection:
		return 0.9
	case model.CapFileRead, model.CapSecretDiscovered, model.CapInternalServiceAccess:
		return 0.82
	}
	switch hType {
	case model.HypothesisTypeCommandExecutionCandidate, model.HypothesisTypeDeserializationCandidate:
		return 0.92
	case model.HypothesisTypeInjectionCandidate, model.HypothesisTypeSSRFCandidate, model.HypothesisTypeFileReadCandidate:
		return 0.82
	case model.HypothesisTypeIDORCandidate, model.HypothesisTypeAuthzBypassCandidate:
		return 0.78
	default:
		return 0.55
	}
}

func coverageGainScore(h model.AIHypothesisNode, items []model.AICoverageItem, goalType string) float64 {
	if goalType != model.GoalTypeCoverage {
		return 0.35
	}
	if len(items) == 0 {
		return 0.5
	}
	target := strings.ToLower(h.TargetEntity + " " + h.Title)
	for _, item := range items {
		if item.Status == "tested" || item.Status == "validated" || item.Status == "negative" {
			continue
		}
		if strings.Contains(target, strings.ToLower(item.Name)) || strings.Contains(target, strings.ToLower(item.TargetRef)) {
			return 0.86
		}
	}
	return 0.45
}

func executionCostScore(intent model.AIIntent) float64 {
	switch intent.IntentType {
	case model.IntentSecretVerify, model.IntentAuthProbe:
		return 0.35
	case model.IntentCapabilityExpand:
		return 0.58
	case model.IntentCommandInjProbe, model.IntentSSRFProbe:
		return 0.7
	case "code_trace", model.IntentCodeSliceAnalysis, model.IntentDataflowTrace:
		return 0.46
	default:
		return 0.42
	}
}

func safetyRiskScore(intent model.AIIntent, h model.AIHypothesisNode) float64 {
	meta := intent.ValidationMetadata()
	if strings.Contains(strings.ToLower(meta.SafetyLevel), "high") {
		return 0.72
	}
	switch h.ExpectedCapability {
	case model.CapCommandExecution, model.CapFileWrite, model.CapLateralAccess:
		return 0.62
	case model.CapAdminAccess:
		return 0.38
	default:
		return 0.24
	}
}

func duplicatePenaltyScore(h model.AIHypothesisNode, negatives []model.AINegativeFact) negativePenaltyResult {
	key := hypothesisPatternKey(h.HypothesisType, h.TargetEntity, h.Title)
	result := negativePenaltyResult{}
	for _, nf := range negatives {
		if nf.SimilarPatternKey == key {
			result.Score = 1.0
			result.Refs = append(result.Refs, nf.ID)
			result.Reason = fmt.Sprintf("Penalized because similar pattern was refuted by NegativeFact %d.", nf.ID)
			return result
		}
		if strings.EqualFold(nf.TestedPath, h.TargetEntity) && strings.Contains(strings.ToLower(nf.Title), strings.ToLower(h.HypothesisType)) {
			result.Score = 0.7
			result.Refs = append(result.Refs, nf.ID)
			result.Reason = fmt.Sprintf("Penalized because target and hypothesis type overlap with NegativeFact %d.", nf.ID)
			return result
		}
	}
	return result
}

func expectedEvidenceQuality(intent model.AIIntent) float64 {
	meta := intent.ValidationMetadata()
	textParts := []string{meta.ExpectedEvidence, meta.SuccessCondition, intent.Objective, string(intent.RequiredEvidence), string(intent.ConstraintsJSON)}
	text := strings.ToLower(strings.Join(textParts, "\n"))
	score := 0.28
	if strings.Contains(text, "baseline") {
		score += 0.12
	}
	if strings.Contains(text, "response diff") || strings.Contains(text, "response_diff") {
		score += 0.16
	}
	if strings.Contains(text, "marker") || strings.Contains(text, "successful marker") {
		score += 0.14
	}
	if strings.Contains(text, "raw request") || strings.Contains(text, "request_snapshot") || strings.Contains(text, "request snapshot") {
		score += 0.1
	}
	if strings.Contains(text, "raw response") || strings.Contains(text, "response_snapshot") || strings.Contains(text, "response snapshot") {
		score += 0.1
	}
	if strings.Contains(text, "scope") || strings.Contains(text, "authorized") || strings.Contains(text, "safety_statement") {
		score += 0.08
	}
	if strings.Contains(text, "reproduce") || strings.Contains(text, "reproducible") || strings.Contains(text, "proof") || strings.Contains(text, "success_condition") || strings.Contains(text, "validate") {
		score += 0.14
	}
	return clamp01(score)
}

func terminalAlignmentBonus(objective string, h model.AIHypothesisNode) float64 {
	text := strings.ToLower(objective + " " + h.Title + " " + h.Description + " " + h.ExpectedCapability)
	switch {
	case strings.Contains(text, "admin") && h.ExpectedCapability == model.CapAdminAccess:
		return 0.18
	case strings.Contains(text, "command") && h.ExpectedCapability == model.CapCommandExecution:
		return 0.18
	case strings.Contains(text, "file") && h.ExpectedCapability == model.CapFileRead:
		return 0.12
	case strings.Contains(text, "session") && h.ExpectedCapability == model.CapAuthenticatedSession:
		return 0.12
	default:
		return 0
	}
}

func expansionLadderBonus(capability string) float64 {
	switch capability {
	case model.CapCredentialObtained, model.CapLateralAccess, model.CapInternalServiceAccess, model.CapAdminAccess:
		return 0.16
	case model.CapSecretDiscovered, model.CapAuthenticatedSession:
		return 0.1
	default:
		return 0
	}
}

func environmentAlignment(h model.AIHypothesisNode, env map[string]any) environmentAlignmentResult {
	hText := strings.ToLower(h.Title + " " + h.Description + " " + h.HypothesisType + " " + h.ExpectedCapability)
	checks := []struct {
		Field   string
		Value   string
		Needles []string
	}{
		{"orchestration_layer", "kubernetes", []string{"kubernetes", "service account", "namespace", "lateral"}},
		{"container_runtime", "docker", []string{"container", "docker", "file_read", "config"}},
		{"runtime_environment", "php", []string{"php", "upload", "file", "sql"}},
		{"runtime_environment", "java", []string{"java", "xxe", "deserialization", "spring"}},
		{"framework_stack", "spring_boot", []string{"spring", "java", "ssti", "deserialization"}},
		{"session_model", "cookie_session", []string{"session", "auth", "cookie"}},
		{"authentication_mechanism", "token_auth", []string{"jwt", "token", "auth"}},
	}
	result := environmentAlignmentResult{}
	for _, check := range checks {
		confidence, ok := environmentConfidence(env, check.Field, check.Value)
		if !ok {
			continue
		}
		matchedNeedle := false
		for _, needle := range check.Needles {
			if strings.Contains(hText, needle) {
				matchedNeedle = true
				break
			}
		}
		if !matchedNeedle {
			continue
		}
		ref := fmt.Sprintf("%s.%s=%s", check.Field, check.Value, confidence)
		boost := environmentBoostForConfidence(confidence)
		if confidence == model.ConfidenceRefuted {
			result.Boost -= 0.22
			result.Refs = append(result.Refs, ref)
			result.Reason = appendReason(result.Reason, "Environment signal "+ref+" refutes this branch and lowers graph expansion value.")
			continue
		}
		if boost > 0 {
			result.Boost += boost
			result.Refs = append(result.Refs, ref)
			result.Reason = appendReason(result.Reason, "Environment signal "+ref+" aligns with this hypothesis.")
		}
	}
	result.Boost = clampRange(result.Boost, -0.35, 0.35)
	return result
}

func environmentConfidence(env map[string]any, field, value string) (string, bool) {
	raw, ok := env[field]
	if !ok {
		return model.ConfidenceUnknown, false
	}
	switch bucket := raw.(type) {
	case map[string]any:
		if confidence, ok := bucket[value].(string); ok {
			return strings.ToLower(strings.TrimSpace(confidence)), true
		}
	case map[string]string:
		if confidence, ok := bucket[value]; ok {
			return strings.ToLower(strings.TrimSpace(confidence)), true
		}
	case string:
		if strings.EqualFold(bucket, value) {
			return model.ConfidencePlausible, true
		}
	}
	return model.ConfidenceUnknown, false
}

func environmentBoostForConfidence(confidence string) float64 {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case model.ConfidenceConfirmed, model.ConfidenceValidated:
		return 0.26
	case model.ConfidenceStrong:
		return 0.2
	case model.ConfidencePlausible:
		return 0.13
	case model.ConfidenceSuspected:
		return 0.06
	case model.ConfidenceUnknown, "":
		return 0
	case model.ConfidenceRefuted:
		return -0.22
	default:
		return 0
	}
}

func branchScoreReason(score model.BranchValue, goalType string, h model.AIHypothesisNode, negative negativePenaltyResult, environment environmentAlignmentResult) string {
	parts := []string{}
	if score.CapabilityUnlockScore >= 0.8 {
		parts = append(parts, "high capability gain")
	}
	if score.GraphExpansionScore >= 0.75 {
		parts = append(parts, "strong graph expansion")
	}
	if score.NoveltyScore >= 0.7 {
		parts = append(parts, "novel branch")
	}
	if score.DuplicatePenalty >= 0.7 {
		parts = append(parts, "negative-fact duplicate penalty")
	}
	if negative.Reason != "" {
		parts = append(parts, negative.Reason)
	}
	if environment.Reason != "" {
		parts = append(parts, environment.Reason)
	}
	switch goalType {
	case model.GoalTypeTerminal:
		if score.GoalTypeBoost > 0 {
			parts = append(parts, fmt.Sprintf("Boosted for terminal goal because expected capability %s is close to the explicit proof objective.", h.ExpectedCapability))
		} else {
			parts = append(parts, "Terminal goal active; no explicit proof-objective boost matched.")
		}
	case model.GoalTypeCoverage:
		parts = append(parts, "Coverage gain is treated as a secondary factor behind capability and graph expansion.")
	case model.GoalTypeExpansion:
		if score.GoalTypeBoost > 0 {
			parts = append(parts, fmt.Sprintf("Boosted for expansion goal because expected capability %s can advance the Objective Ladder.", h.ExpectedCapability))
		} else {
			parts = append(parts, "Expansion goal active; branch did not receive Objective Ladder capability boost.")
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "balanced branch value")
	}
	return strings.Join(parts, ", ")
}

func clamp01(value float64) float64 {
	return math.Max(0, math.Min(1, value))
}

func clampRange(value, minValue, maxValue float64) float64 {
	return math.Max(minValue, math.Min(maxValue, value))
}

func appendReason(existing, next string) string {
	if strings.TrimSpace(existing) == "" {
		return next
	}
	return existing + " " + next
}
