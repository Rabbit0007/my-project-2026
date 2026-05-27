package service

import (
	"strings"
	"testing"
	"time"

	"shenji/backend/internal/model"
)

func TestExplorationBudgetBlocksWhenPendingIntentLimitExceeded(t *testing.T) {
	decision := evaluateBudgetDecision(ExplorationBudgetMetrics{
		PendingValidationIntentCount: 3,
	}, 2, ExplorationBudgetConfig{
		MaxPendingValidationIntentsPerTask: 3,
		MaxPendingHypothesesPerTask:        100,
		MaxActiveBranchesPerTask:           100,
		MaxGeneratedIntentsPerRound:        2,
	}, "evidence_expansion")
	if decision.Allowed {
		t.Fatalf("expected budget to block generation, got %+v", decision)
	}
	if decision.Decision != "blocked" {
		t.Fatalf("expected blocked decision, got %s", decision.Decision)
	}
	if !strings.Contains(decision.Reason, "pending validation intent") {
		t.Fatalf("expected pending intent reason, got %q", decision.Reason)
	}
}

func TestExplorationBudgetBlocksWhenActiveBranchLimitExceeded(t *testing.T) {
	decision := evaluateBudgetDecision(ExplorationBudgetMetrics{
		ActiveBranchCount: 5,
	}, 1, ExplorationBudgetConfig{
		MaxActiveBranchesPerTask:           5,
		MaxPendingHypothesesPerTask:        100,
		MaxPendingValidationIntentsPerTask: 100,
		MaxGeneratedIntentsPerRound:        2,
	}, "capability_expansion")
	if decision.Allowed {
		t.Fatalf("expected active branch limit to block, got %+v", decision)
	}
	if !strings.Contains(decision.Reason, "active branch") {
		t.Fatalf("expected active branch reason, got %q", decision.Reason)
	}
}

func TestExplorationBudgetClampsGeneratedPerRound(t *testing.T) {
	decision := evaluateBudgetDecision(ExplorationBudgetMetrics{}, 10, ExplorationBudgetConfig{
		MaxPendingValidationIntentsPerTask: 100,
		MaxPendingHypothesesPerTask:        100,
		MaxActiveBranchesPerTask:           100,
		MaxGeneratedIntentsPerRound:        2,
	}, "evidence_expansion")
	if !decision.Allowed {
		t.Fatalf("expected allowed decision, got %+v", decision)
	}
	if decision.MaxToGenerate != 2 {
		t.Fatalf("expected max generated to be clamped to 2, got %d", decision.MaxToGenerate)
	}
	if decision.Decision != "clamped" || decision.GeneratedCountRequested != 10 || decision.GeneratedCountAllowed != 2 {
		t.Fatalf("expected clamped decision with counts, got %+v", decision)
	}
}

func TestShouldSuppressLowValueIntentRequiresPendingHypothesisBackedIntent(t *testing.T) {
	hypothesisID := uint(7)
	intent := model.AIIntent{
		Status:        model.IntentStatusPending,
		PriorityScore: 0.1,
	}
	intent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &hypothesisID})
	if !shouldSuppressLowValueIntent(intent, ExplorationBudgetConfig{LowValueBranchThreshold: 0.2}) {
		t.Fatal("expected low-value hypothesis-backed pending intent to be suppressible")
	}
	intent.Status = model.IntentStatusCompleted
	if shouldSuppressLowValueIntent(intent, ExplorationBudgetConfig{LowValueBranchThreshold: 0.2}) {
		t.Fatal("completed intent should not be suppressible")
	}
	intent.Status = model.IntentStatusPending
	intent.PriorityScore = 0.9
	if shouldSuppressLowValueIntent(intent, ExplorationBudgetConfig{LowValueBranchThreshold: 0.2}) {
		t.Fatal("high-value intent should not be suppressible")
	}
}

func TestBudgetPerTaskIsolationDecisionUsesProvidedMetrics(t *testing.T) {
	cfg := ExplorationBudgetConfig{
		MaxPendingValidationIntentsPerTask: 2,
		MaxPendingHypothesesPerTask:        100,
		MaxActiveBranchesPerTask:           100,
		MaxGeneratedIntentsPerRound:        2,
	}
	taskA := evaluateBudgetDecision(ExplorationBudgetMetrics{PendingValidationIntentCount: 2}, 1, cfg, "evidence_expansion")
	taskB := evaluateBudgetDecision(ExplorationBudgetMetrics{PendingValidationIntentCount: 1}, 1, cfg, "evidence_expansion")
	if taskA.Allowed {
		t.Fatalf("expected task A blocked, got %+v", taskA)
	}
	if !taskB.Allowed {
		t.Fatalf("expected task B allowed, got %+v", taskB)
	}
}

func TestBudgetDecisionContainsMetricsThresholdsReasonAndTrigger(t *testing.T) {
	decision := evaluateBudgetDecision(ExplorationBudgetMetrics{
		ActiveBranchCount:  1,
		AverageBranchValue: 0.42,
	}, 1, ExplorationBudgetConfig{}, "capability_expansion")
	if decision.Reason == "" || decision.TriggeredBy != "capability_expansion" {
		t.Fatalf("expected reason and trigger, got %+v", decision)
	}
	if decision.Thresholds.MaxActiveBranchesPerTask != 24 || decision.Thresholds.MaxGeneratedIntentsPerRound != 6 {
		t.Fatalf("expected default thresholds snapshot, got %+v", decision.Thresholds)
	}
	metadata := budgetDecisionAuditMetadata(decision)
	for _, key := range []string{"decision", "reason", "metrics", "thresholds", "generated_count_requested", "generated_count_allowed", "triggered_by"} {
		if _, ok := metadata[key]; !ok {
			t.Fatalf("expected audit metadata key %s in %+v", key, metadata)
		}
	}
}

func TestSuppressedIntentIsNotEligibleForNextPending(t *testing.T) {
	suppressed := model.AIIntent{IntentType: model.IntentBehaviorProbe, Status: model.IntentStatusSuppressed, PriorityScore: 1.0}
	pending := model.AIIntent{IntentType: model.IntentBehaviorProbe, Status: model.IntentStatusPending, PriorityScore: 0.2}
	if intentEligibleForNextPending(suppressed) {
		t.Fatal("suppressed intent must not be eligible for NextPending")
	}
	if !intentEligibleForNextPending(pending) {
		t.Fatal("pending intent should be eligible for NextPending")
	}
	for _, removed := range removedIntentTypes() {
		if intentEligibleForNextPending(model.AIIntent{IntentType: removed, Status: model.IntentStatusPending, PriorityScore: 1.0}) {
			t.Fatalf("removed intent type %s must not be eligible for NextPending", removed)
		}
	}
}

func TestSuppressedHypothesisIsNotNegativeFact(t *testing.T) {
	h := model.AIHypothesisNode{Status: model.HypothesisStatusSuppressed}
	if h.Status == model.HypothesisStatusRefuted || h.ConfidenceState == model.ConfidenceRefuted {
		t.Fatalf("suppressed hypothesis must not be treated as refuted/negative: %+v", h)
	}
}

func TestActiveBranchStatusExcludesTerminalStates(t *testing.T) {
	active := []string{model.HypothesisStatusPending, model.HypothesisStatusValidating}
	inactive := []string{model.HypothesisStatusValidated, model.HypothesisStatusRefuted, model.HypothesisStatusSuppressed, model.HypothesisStatusInconclusive}
	for _, status := range active {
		if !hypothesisCountsAsActiveBranch(model.AIHypothesisNode{Status: status}) {
			t.Fatalf("expected %s to count as active branch", status)
		}
	}
	for _, status := range inactive {
		if hypothesisCountsAsActiveBranch(model.AIHypothesisNode{Status: status}) {
			t.Fatalf("expected %s to be excluded from active branch count", status)
		}
	}
}

func TestLowValueSuppressBatchSelectsAtMostConfiguredLowestValue(t *testing.T) {
	hypothesisID := uint(10)
	intents := []model.AIIntent{}
	for i := 0; i < 12; i++ {
		intent := model.AIIntent{
			ID:            uint(i + 1),
			Status:        model.IntentStatusPending,
			PriorityScore: float64(i) / 100,
			CreatedAt:     time.Now().UTC().Add(time.Duration(i) * time.Second),
		}
		intent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &hypothesisID})
		intents = append(intents, intent)
	}
	selected := selectSuppressibleLowValueIntents(intents, ExplorationBudgetConfig{
		LowValueBranchThreshold: 0.2,
		LowValueSuppressBatch:   8,
	})
	if len(selected) != 8 {
		t.Fatalf("expected suppress batch of 8, got %d", len(selected))
	}
	if selected[0].ID != 1 || selected[7].ID != 8 {
		t.Fatalf("expected lowest value intents selected first, got %+v", selected)
	}
}

func TestDynamicCandidateSortingKeepsTopBranchValueCandidates(t *testing.T) {
	drafts := []HypothesisDraft{
		{Title: "coverage-ish", ExpectedCapability: ""},
		{Title: "rce", ExpectedCapability: model.CapCommandExecution},
		{Title: "file", ExpectedCapability: model.CapFileRead},
	}
	sortHypothesisDraftsByExpansionValue(drafts)
	if drafts[0].ExpectedCapability != model.CapCommandExecution {
		t.Fatalf("expected command execution candidate first, got %+v", drafts)
	}
}

func TestDefaultExplorationBudgetConfigValues(t *testing.T) {
	cfg := DefaultExplorationBudgetConfig()
	if cfg.MaxActiveBranchesPerTask != 24 ||
		cfg.MaxPendingHypothesesPerTask != 80 ||
		cfg.MaxPendingValidationIntentsPerTask != 40 ||
		cfg.MaxGeneratedIntentsPerRound != 6 ||
		cfg.BranchDecayRounds != 3 ||
		cfg.LowValueBranchThreshold != 0.24 ||
		cfg.LowValueSuppressBatch != 8 {
		t.Fatalf("unexpected default budget config: %+v", cfg)
	}
}
