package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"shenji/backend/internal/model"
)

func TestHypothesisLifecycle_CreateValidationIntent_Phase3_NormalizesSQLiProbe(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9601)
	bb := NewBlackboardService(db)

	lifecycle := NewHypothesisLifecycleService(db, bb)
	lifecycle.SetClueDrivenPhase(3)

	// Create a hypothesis with SQL injection capability
	h, err := lifecycle.FormHypothesis(ctx, HypothesisDraft{
		TaskID:             taskID,
		HypothesisType:     model.HypothesisTypeInjectionCandidate,
		Title:              "SQL injection in search param",
		Description:        "User input flows to SQL query without parameterization",
		ConfidenceState:    model.ConfidencePlausible,
		TargetEntity:       "GET /search?q=",
		ExpectedCapability: model.CapSQLInjection,
	})
	if err != nil {
		t.Fatalf("FormHypothesis: %v", err)
	}

	// intentTypeForCapability(CapSQLInjection) returns "sqli_probe"
	intentType := intentTypeForCapability(model.CapSQLInjection)
	if intentType != model.IntentSQLiProbe {
		t.Fatalf("expected intentTypeForCapability to return sqli_probe, got %s", intentType)
	}

	// CreateValidationIntent should normalize sqli_probe -> clue_validate at phase 3
	intent, err := lifecycle.CreateValidationIntent(ctx, h, intentType, "test", 0.7)
	if err != nil {
		t.Fatalf("CreateValidationIntent: %v", err)
	}

	// Verify: IntentType must be modern
	if intent.IntentType != model.IntentClueValidate {
		t.Errorf("expected IntentType=%s, got %s", model.IntentClueValidate, intent.IntentType)
	}

	// Verify: legacy_hint preserved in ConstraintsJSON
	var constraints map[string]any
	_ = json.Unmarshal(intent.ConstraintsJSON, &constraints)
	hint, _ := constraints["legacy_hint"].(string)
	if hint != "sqli_probe" {
		t.Errorf("expected legacy_hint=sqli_probe, got %v", constraints["legacy_hint"])
	}

	// Verify in DB
	var dbIntent model.AIIntent
	db.First(&dbIntent, intent.ID)
	if dbIntent.IntentType != model.IntentClueValidate {
		t.Errorf("DB IntentType=%s, expected clue_validate", dbIntent.IntentType)
	}
}

func TestHypothesisLifecycle_CreateValidationIntent_Phase0_KeepsLegacy(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9602)
	bb := NewBlackboardService(db)

	lifecycle := NewHypothesisLifecycleService(db, bb)
	// phase 0 = no normalization

	h, _ := lifecycle.FormHypothesis(ctx, HypothesisDraft{
		TaskID:             taskID,
		HypothesisType:     model.HypothesisTypeInjectionCandidate,
		Title:              "SQL injection test",
		Description:        "test",
		ConfidenceState:    model.ConfidencePlausible,
		TargetEntity:       "GET /search",
		ExpectedCapability: model.CapSQLInjection,
	})

	intent, err := lifecycle.CreateValidationIntent(ctx, h, model.IntentSQLiProbe, "test", 0.7)
	if err != nil {
		t.Fatalf("CreateValidationIntent: %v", err)
	}

	// Phase 0: should keep legacy type
	if intent.IntentType != model.IntentSQLiProbe {
		t.Errorf("phase 0 should keep sqli_probe, got %s", intent.IntentType)
	}
}

func TestDynamicExpander_ExpandFromEvidence_Phase3_ModernIntentOnly(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9603)
	bb := NewBlackboardService(db)

	lifecycle := NewHypothesisLifecycleService(db, bb)
	lifecycle.SetClueDrivenPhase(3)

	// Create evidence that would trigger SQL injection hypothesis
	evidence := []model.AIEvidence{
		{
			ID:           1,
			TaskID:       taskID,
			EvidenceType: "code_snippet",
			Title:        "SQL query construction",
			Summary:      "User input concatenated into SQL query without parameterization",
			Hash:         "test_hash_9603",
			RelationType: "impact_sink_or_security_effect",
			CreatedAt:    time.Now(),
		},
	}

	created, err := lifecycle.ExpandFromEvidence(ctx, taskID, evidence, ExpansionBudget{MaxGeneratedPerRound: 3})
	if err != nil {
		t.Fatalf("ExpandFromEvidence: %v", err)
	}

	// Check all created intents are modern
	var intents []model.AIIntent
	db.Where("task_id = ?", taskID).Find(&intents)

	modernSet := map[string]bool{
		model.IntentClueCollect:      true,
		model.IntentClueValidate:     true,
		model.IntentClueRefute:       true,
		model.IntentClueChainExtend:  true,
		model.IntentScopeObservation: true,
	}

	for _, intent := range intents {
		if !modernSet[intent.IntentType] {
			t.Errorf("ExpandFromEvidence produced legacy intent: %s (title: %s)", intent.IntentType, intent.Title)
		}
	}
	t.Logf("ExpandFromEvidence created %d hypotheses, %d intents in DB (all modern)", len(created), len(intents))
}

func TestWorkerDriver_FollowUpIntent_Phase3_NormalizesLegacyIntent(t *testing.T) {
	// This test verifies that normalizeIntentBeforeCreate is called
	// on the worker follow-up intent path
	intent := model.AIIntent{
		IntentType: "sqli_probe",
		Title:      "Worker suggested SQL injection validation",
		Objective:  "Validate SQL injection hypothesis",
	}

	// Phase 3: should normalize
	normalized, origType, hint := normalizeIntentBeforeCreate(&intent, 3)
	if !normalized {
		t.Fatal("expected normalization at phase 3")
	}
	if intent.IntentType != model.IntentClueValidate {
		t.Errorf("expected clue_validate, got %s", intent.IntentType)
	}
	if origType != "sqli_probe" {
		t.Errorf("expected origType=sqli_probe, got %s", origType)
	}
	if hint != "sqli_probe" {
		t.Errorf("expected hint=sqli_probe, got %s", hint)
	}

	// Verify ConstraintsJSON has legacy_hint
	var constraints map[string]any
	_ = json.Unmarshal(intent.ConstraintsJSON, &constraints)
	if constraints["legacy_hint"] != "sqli_probe" {
		t.Errorf("expected legacy_hint in constraints, got %v", constraints)
	}
}

func TestWorkerDriver_FollowUpIntent_Phase0_KeepsLegacyIntent(t *testing.T) {
	intent := model.AIIntent{
		IntentType: "sqli_probe",
		Title:      "Worker suggested SQL injection validation",
	}

	normalized, _, _ := normalizeIntentBeforeCreate(&intent, 0)
	if normalized {
		t.Error("phase 0 should not normalize")
	}
	if intent.IntentType != "sqli_probe" {
		t.Errorf("phase 0 should keep sqli_probe, got %s", intent.IntentType)
	}
}

func TestPhase3_NoLegacyVulnIntentLeaks(t *testing.T) {
	// Comprehensive test: all known legacy intent types must normalize at phase 3
	legacyTypes := []string{
		"sqli_probe", "idor_probe", "xss_probe", "ssrf_probe",
		"path_traversal_probe", "ssti_probe", "command_injection_probe",
		"sql_injection_validation", "idor_test", "xss_test",
		"ssrf_test", "rce_test", "lfi_test", "xxe_test",
	}

	modernSet := map[string]bool{
		model.IntentClueCollect:      true,
		model.IntentClueValidate:     true,
		model.IntentClueRefute:       true,
		model.IntentClueChainExtend:  true,
		model.IntentScopeObservation: true,
	}

	for _, legacy := range legacyTypes {
		intent := model.AIIntent{IntentType: legacy, Title: "test"}
		normalizeIntentBeforeCreate(&intent, 3)
		if !modernSet[intent.IntentType] {
			t.Errorf("legacy type %q normalized to %q which is NOT in modern set", legacy, intent.IntentType)
		}
	}
}
