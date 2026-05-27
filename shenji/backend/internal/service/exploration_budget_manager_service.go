package service

import (
	"context"
	"sort"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type ExplorationBudgetConfig struct {
	MaxActiveBranchesPerTask           int
	MaxPendingHypothesesPerTask        int
	MaxPendingValidationIntentsPerTask int
	MaxGeneratedIntentsPerRound        int
	BranchDecayRounds                  int
	LowValueBranchThreshold            float64
	LowValueSuppressBatch              int
}

type ExplorationBudgetMetrics struct {
	ActiveBranchCount            int64   `json:"active_branch_count"`
	PendingHypothesisCount       int64   `json:"pending_hypothesis_count"`
	PendingValidationIntentCount int64   `json:"pending_validation_intent_count"`
	IntentGenerationRate         int64   `json:"intent_generation_rate"`
	GraphExpansionVelocity       int64   `json:"graph_expansion_velocity"`
	AverageBranchValue           float64 `json:"average_branch_value"`
	ContextGrowthRate            int64   `json:"context_growth_rate"`
	SuppressedLowValueBranches   int     `json:"suppressed_low_value_branches"`
}

type ExplorationBudgetThresholds struct {
	MaxActiveBranchesPerTask           int     `json:"max_active_branches_per_task"`
	MaxPendingHypothesesPerTask        int     `json:"max_pending_hypotheses_per_task"`
	MaxPendingValidationIntentsPerTask int     `json:"max_pending_validation_intents_per_task"`
	MaxGeneratedIntentsPerRound        int     `json:"max_generated_intents_per_round"`
	BranchDecayRounds                  int     `json:"branch_decay_rounds"`
	LowValueBranchThreshold            float64 `json:"low_value_branch_threshold"`
	LowValueSuppressBatch              int     `json:"low_value_suppress_batch"`
}

type BudgetDecision struct {
	Allowed                 bool                        `json:"allowed"`
	Decision                string                      `json:"decision"`
	Reason                  string                      `json:"reason"`
	MaxToGenerate           int                         `json:"max_generate"`
	GeneratedCountRequested int                         `json:"generated_count_requested"`
	GeneratedCountAllowed   int                         `json:"generated_count_allowed"`
	Metrics                 ExplorationBudgetMetrics    `json:"metrics"`
	Thresholds              ExplorationBudgetThresholds `json:"thresholds"`
	SuppressedHypothesisIDs []uint                      `json:"suppressed_hypothesis_ids"`
	SuppressedIntentIDs     []uint                      `json:"suppressed_intent_ids"`
	TriggeredBy             string                      `json:"triggered_by"`
}

type SuppressionResult struct {
	Count         int    `json:"count"`
	HypothesisIDs []uint `json:"hypothesis_ids"`
	IntentIDs     []uint `json:"intent_ids"`
	TriggeredBy   string `json:"triggered_by"`
}

type ExplorationBudgetManager struct {
	db *gorm.DB
}

func NewExplorationBudgetManager(db *gorm.DB) *ExplorationBudgetManager {
	return &ExplorationBudgetManager{db: db}
}

func DefaultExplorationBudgetConfig() ExplorationBudgetConfig {
	return ExplorationBudgetConfig{
		MaxActiveBranchesPerTask:           24,
		MaxPendingHypothesesPerTask:        80,
		MaxPendingValidationIntentsPerTask: 40,
		MaxGeneratedIntentsPerRound:        6,
		BranchDecayRounds:                  3,
		LowValueBranchThreshold:            0.24,
		LowValueSuppressBatch:              8,
	}
}

func (m *ExplorationBudgetManager) Metrics(ctx context.Context, taskID uint) ExplorationBudgetMetrics {
	metrics := ExplorationBudgetMetrics{}
	activeStatuses := []string{model.HypothesisStatusPending, model.HypothesisStatusValidating}
	_ = m.db.WithContext(ctx).Model(&model.AIHypothesisNode{}).
		Where("task_id = ? AND status IN ?", taskID, activeStatuses).
		Count(&metrics.ActiveBranchCount).Error
	metrics.PendingHypothesisCount = metrics.ActiveBranchCount
	_ = m.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("task_id = ? AND status = ?", taskID, model.IntentStatusPending).
		Count(&metrics.PendingValidationIntentCount).Error
	since := time.Now().UTC().Add(-1 * time.Hour)
	_ = m.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("task_id = ? AND created_by = ? AND created_at >= ?", taskID, "dynamic-intent-expander", since).
		Count(&metrics.IntentGenerationRate).Error
	_ = m.db.WithContext(ctx).Model(&model.AIBlackboardNode{}).
		Where("task_id = ? AND created_at >= ?", taskID, since).
		Count(&metrics.GraphExpansionVelocity).Error
	metrics.ContextGrowthRate = metrics.GraphExpansionVelocity
	metrics.AverageBranchValue = m.averagePendingBranchValue(ctx, taskID)
	return metrics
}

func (m *ExplorationBudgetManager) AllowIntentGeneration(ctx context.Context, taskID uint, requested int, cfg ExplorationBudgetConfig) BudgetDecision {
	return m.AllowIntentGenerationFor(ctx, taskID, requested, cfg, "unspecified")
}

func (m *ExplorationBudgetManager) AllowIntentGenerationFor(ctx context.Context, taskID uint, requested int, cfg ExplorationBudgetConfig, triggeredBy string) BudgetDecision {
	cfg = normalizeBudgetConfig(cfg)
	metrics := m.Metrics(ctx, taskID)
	decision := evaluateBudgetDecision(metrics, requested, cfg, triggeredBy)
	if metrics.ActiveBranchCount >= int64(cfg.MaxActiveBranchesPerTask) {
		suppressed, _ := m.SuppressLowValueBranchesFor(ctx, taskID, cfg, triggeredBy)
		metrics = m.Metrics(ctx, taskID)
		metrics.SuppressedLowValueBranches = suppressed.Count
		decision = evaluateBudgetDecision(metrics, requested, cfg, triggeredBy)
		decision.SuppressedHypothesisIDs = suppressed.HypothesisIDs
		decision.SuppressedIntentIDs = suppressed.IntentIDs
		if suppressed.Count > 0 && decision.Allowed {
			decision.Decision = "suppressed"
			decision.Reason = "suppressed low-value branches before allowing generation"
		}
		if metrics.ActiveBranchCount >= int64(cfg.MaxActiveBranchesPerTask) {
			m.recordBudgetDecision(ctx, taskID, decision)
			return decision
		}
	}
	if metrics.PendingHypothesisCount >= int64(cfg.MaxPendingHypothesesPerTask) {
		suppressed, _ := m.SuppressLowValueBranchesFor(ctx, taskID, cfg, triggeredBy)
		metrics = m.Metrics(ctx, taskID)
		metrics.SuppressedLowValueBranches = suppressed.Count
		decision = evaluateBudgetDecision(metrics, requested, cfg, triggeredBy)
		decision.SuppressedHypothesisIDs = appendUniqueUintList(decision.SuppressedHypothesisIDs, suppressed.HypothesisIDs...)
		decision.SuppressedIntentIDs = appendUniqueUintList(decision.SuppressedIntentIDs, suppressed.IntentIDs...)
		if suppressed.Count > 0 && decision.Allowed {
			decision.Decision = "suppressed"
			decision.Reason = "suppressed low-value branches before allowing generation"
		}
		if metrics.PendingHypothesisCount >= int64(cfg.MaxPendingHypothesesPerTask) {
			m.recordBudgetDecision(ctx, taskID, decision)
			return decision
		}
	}
	if metrics.PendingValidationIntentCount >= int64(cfg.MaxPendingValidationIntentsPerTask) {
		suppressed, _ := m.SuppressLowValueBranchesFor(ctx, taskID, cfg, triggeredBy)
		metrics = m.Metrics(ctx, taskID)
		metrics.SuppressedLowValueBranches = suppressed.Count
		decision = evaluateBudgetDecision(metrics, requested, cfg, triggeredBy)
		decision.SuppressedHypothesisIDs = appendUniqueUintList(decision.SuppressedHypothesisIDs, suppressed.HypothesisIDs...)
		decision.SuppressedIntentIDs = appendUniqueUintList(decision.SuppressedIntentIDs, suppressed.IntentIDs...)
		if suppressed.Count > 0 && decision.Allowed {
			decision.Decision = "suppressed"
			decision.Reason = "suppressed low-value branches before allowing generation"
		}
		if metrics.PendingValidationIntentCount >= int64(cfg.MaxPendingValidationIntentsPerTask) {
			m.recordBudgetDecision(ctx, taskID, decision)
			return decision
		}
	}
	decision = evaluateBudgetDecision(metrics, requested, cfg, triggeredBy)
	m.recordBudgetDecision(ctx, taskID, decision)
	return decision
}

func (m *ExplorationBudgetManager) SuppressLowValueBranches(ctx context.Context, taskID uint, cfg ExplorationBudgetConfig) (int, error) {
	result, err := m.SuppressLowValueBranchesFor(ctx, taskID, cfg, "unspecified")
	return result.Count, err
}

func (m *ExplorationBudgetManager) SuppressLowValueBranchesFor(ctx context.Context, taskID uint, cfg ExplorationBudgetConfig, triggeredBy string) (SuppressionResult, error) {
	cfg = normalizeBudgetConfig(cfg)
	result := SuppressionResult{TriggeredBy: triggeredBy}
	var intents []model.AIIntent
	if err := m.db.WithContext(ctx).
		Where("task_id = ? AND status = ?", taskID, model.IntentStatusPending).
		Order("priority_score asc, created_at asc").
		Limit(cfg.LowValueSuppressBatch).
		Find(&intents).Error; err != nil {
		return result, err
	}
	for _, intent := range selectSuppressibleLowValueIntents(intents, cfg) {
		if !shouldSuppressLowValueIntent(intent, cfg) {
			continue
		}
		hid := intent.HypothesisID()
		if hid == nil {
			continue
		}
		if err := m.db.WithContext(ctx).Model(&model.AIIntent{}).Where("id = ?", intent.ID).Updates(map[string]any{
			"status":     model.IntentStatusSuppressed,
			"updated_at": time.Now().UTC(),
		}).Error; err != nil {
			return result, err
		}
		_ = m.db.WithContext(ctx).Model(&model.AIHypothesisNode{}).Where("id = ? AND status IN ?", *hid, []string{model.HypothesisStatusPending, model.HypothesisStatusValidating}).Updates(map[string]any{
			"status":     model.HypothesisStatusSuppressed,
			"updated_at": time.Now().UTC(),
		}).Error
		result.Count++
		result.IntentIDs = append(result.IntentIDs, intent.ID)
		result.HypothesisIDs = append(result.HypothesisIDs, *hid)
	}
	if result.Count > 0 {
		appendAuditEvent(ctx, m.db, &taskID, "exploration_budget.low_value_suppressed", "exploration-budget-manager", "Suppressed stale or low-value pending branches before blocking new high-value formation.", map[string]any{
			"decision":                  "suppressed",
			"reason":                    "priority_score at or below low_value_branch_threshold",
			"metrics":                   m.Metrics(ctx, taskID),
			"thresholds":                thresholdsFromConfig(cfg),
			"suppressed_hypothesis_ids": result.HypothesisIDs,
			"suppressed_intent_ids":     result.IntentIDs,
			"triggered_by":              triggeredBy,
		})
	}
	return result, nil
}

func evaluateBudgetDecision(metrics ExplorationBudgetMetrics, requested int, cfg ExplorationBudgetConfig, triggeredBy string) BudgetDecision {
	cfg = normalizeBudgetConfig(cfg)
	decision := BudgetDecision{
		Allowed:                 true,
		Decision:                "allowed",
		MaxToGenerate:           requested,
		GeneratedCountRequested: requested,
		Reason:                  "within exploration budget",
		Metrics:                 metrics,
		Thresholds:              thresholdsFromConfig(cfg),
		TriggeredBy:             triggeredBy,
	}
	if decision.MaxToGenerate <= 0 || decision.MaxToGenerate > cfg.MaxGeneratedIntentsPerRound {
		decision.MaxToGenerate = cfg.MaxGeneratedIntentsPerRound
	}
	decision.GeneratedCountAllowed = decision.MaxToGenerate
	if requested > decision.MaxToGenerate {
		decision.Decision = "clamped"
		decision.Reason = "requested generation exceeds max_generated_intents_per_round or remaining slots"
	}
	if metrics.ActiveBranchCount >= int64(cfg.MaxActiveBranchesPerTask) {
		decision.Allowed = false
		decision.Decision = "blocked"
		decision.MaxToGenerate = 0
		decision.GeneratedCountAllowed = 0
		decision.Reason = "active branch count exceeds max_active_branches_per_task"
		return decision
	}
	if metrics.PendingHypothesisCount >= int64(cfg.MaxPendingHypothesesPerTask) {
		decision.Allowed = false
		decision.Decision = "blocked"
		decision.MaxToGenerate = 0
		decision.GeneratedCountAllowed = 0
		decision.Reason = "pending hypothesis count exceeds max_pending_hypotheses_per_task"
		return decision
	}
	if metrics.PendingValidationIntentCount >= int64(cfg.MaxPendingValidationIntentsPerTask) {
		decision.Allowed = false
		decision.Decision = "blocked"
		decision.MaxToGenerate = 0
		decision.GeneratedCountAllowed = 0
		decision.Reason = "pending validation intent count exceeds max_pending_validation_intents_per_task"
		return decision
	}
	remainingIntentSlots := cfg.MaxPendingValidationIntentsPerTask - int(metrics.PendingValidationIntentCount)
	remainingHypothesisSlots := cfg.MaxPendingHypothesesPerTask - int(metrics.PendingHypothesisCount)
	if remainingIntentSlots < decision.MaxToGenerate {
		decision.MaxToGenerate = maxInt(remainingIntentSlots, 0)
		decision.Decision = "clamped"
	}
	if remainingHypothesisSlots < decision.MaxToGenerate {
		decision.MaxToGenerate = maxInt(remainingHypothesisSlots, 0)
		decision.Decision = "clamped"
	}
	decision.GeneratedCountAllowed = decision.MaxToGenerate
	if decision.MaxToGenerate <= 0 {
		decision.Allowed = false
		decision.Decision = "blocked"
		decision.Reason = "no remaining generation slots"
	}
	return decision
}

func shouldSuppressLowValueIntent(intent model.AIIntent, cfg ExplorationBudgetConfig) bool {
	cfg = normalizeBudgetConfig(cfg)
	return intent.Status == model.IntentStatusPending && intent.HypothesisID() != nil && intent.PriorityScore <= cfg.LowValueBranchThreshold
}

func selectSuppressibleLowValueIntents(intents []model.AIIntent, cfg ExplorationBudgetConfig) []model.AIIntent {
	cfg = normalizeBudgetConfig(cfg)
	candidates := append([]model.AIIntent(nil), intents...)
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].PriorityScore == candidates[j].PriorityScore {
			return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
		}
		return candidates[i].PriorityScore < candidates[j].PriorityScore
	})
	selected := []model.AIIntent{}
	for _, intent := range candidates {
		if !shouldSuppressLowValueIntent(intent, cfg) {
			continue
		}
		selected = append(selected, intent)
		if len(selected) >= cfg.LowValueSuppressBatch {
			break
		}
	}
	return selected
}

func hypothesisCountsAsActiveBranch(h model.AIHypothesisNode) bool {
	return h.Status == model.HypothesisStatusPending || h.Status == model.HypothesisStatusValidating
}

func thresholdsFromConfig(cfg ExplorationBudgetConfig) ExplorationBudgetThresholds {
	cfg = normalizeBudgetConfig(cfg)
	return ExplorationBudgetThresholds{
		MaxActiveBranchesPerTask:           cfg.MaxActiveBranchesPerTask,
		MaxPendingHypothesesPerTask:        cfg.MaxPendingHypothesesPerTask,
		MaxPendingValidationIntentsPerTask: cfg.MaxPendingValidationIntentsPerTask,
		MaxGeneratedIntentsPerRound:        cfg.MaxGeneratedIntentsPerRound,
		BranchDecayRounds:                  cfg.BranchDecayRounds,
		LowValueBranchThreshold:            cfg.LowValueBranchThreshold,
		LowValueSuppressBatch:              cfg.LowValueSuppressBatch,
	}
}

func (m *ExplorationBudgetManager) recordBudgetDecision(ctx context.Context, taskID uint, decision BudgetDecision) {
	appendAuditEvent(ctx, m.db, &taskID, "exploration_budget.decision", "exploration-budget-manager", decision.Reason, budgetDecisionAuditMetadata(decision))
}

func budgetDecisionAuditMetadata(decision BudgetDecision) map[string]any {
	return map[string]any{
		"decision":                  decision.Decision,
		"reason":                    decision.Reason,
		"metrics":                   decision.Metrics,
		"thresholds":                decision.Thresholds,
		"generated_count_requested": decision.GeneratedCountRequested,
		"generated_count_allowed":   decision.GeneratedCountAllowed,
		"suppressed_hypothesis_ids": decision.SuppressedHypothesisIDs,
		"suppressed_intent_ids":     decision.SuppressedIntentIDs,
		"triggered_by":              decision.TriggeredBy,
	}
}

func (m *ExplorationBudgetManager) averagePendingBranchValue(ctx context.Context, taskID uint) float64 {
	var intents []model.AIIntent
	_ = m.db.WithContext(ctx).
		Where("task_id = ? AND status = ?", taskID, model.IntentStatusPending).
		Limit(80).
		Find(&intents).Error
	total := 0.0
	count := 0
	for _, intent := range intents {
		branch, err := intent.BranchValue()
		if err != nil || branch == nil {
			continue
		}
		total += branch.FinalScore
		count++
	}
	if count == 0 {
		return 0
	}
	return total / float64(count)
}

func normalizeBudgetConfig(cfg ExplorationBudgetConfig) ExplorationBudgetConfig {
	defaults := DefaultExplorationBudgetConfig()
	if cfg.MaxActiveBranchesPerTask <= 0 {
		cfg.MaxActiveBranchesPerTask = defaults.MaxActiveBranchesPerTask
	}
	if cfg.MaxPendingHypothesesPerTask <= 0 {
		cfg.MaxPendingHypothesesPerTask = defaults.MaxPendingHypothesesPerTask
	}
	if cfg.MaxPendingValidationIntentsPerTask <= 0 {
		cfg.MaxPendingValidationIntentsPerTask = defaults.MaxPendingValidationIntentsPerTask
	}
	if cfg.MaxGeneratedIntentsPerRound <= 0 {
		cfg.MaxGeneratedIntentsPerRound = defaults.MaxGeneratedIntentsPerRound
	}
	if cfg.BranchDecayRounds <= 0 {
		cfg.BranchDecayRounds = defaults.BranchDecayRounds
	}
	if cfg.LowValueBranchThreshold <= 0 {
		cfg.LowValueBranchThreshold = defaults.LowValueBranchThreshold
	}
	if cfg.LowValueSuppressBatch <= 0 {
		cfg.LowValueSuppressBatch = defaults.LowValueSuppressBatch
	}
	return cfg
}

func appendUniqueUintList(values []uint, next ...uint) []uint {
	seen := map[uint]struct{}{}
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range next {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}
