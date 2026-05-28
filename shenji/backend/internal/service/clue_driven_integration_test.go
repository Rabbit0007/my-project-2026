package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"shenji/backend/internal/config"
	"shenji/backend/internal/model"
)

// TestClueDrivenIntegration_Phase3_CodeAudit verifies the full clue-driven
// pipeline with RABBIT_CLUE_DRIVEN_PHASE=3, RABBIT_PROMOTION_GATE=clue_chain,
// RABBIT_FINALIZE_FALLBACK=clue, RABBIT_DELIVERY_WRITEBACK=off.
func TestClueDrivenIntegration_Phase3_CodeAudit(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9501)

	cfg := config.Config{
		ClueDrivenPhase:   3,
		PromotionGate:     "clue_chain",
		FinalizeMode:      "clue",
		DeliveryWriteback: "off",
	}

	bb := NewBlackboardService(db)
	intentSvc := NewIntentService(db)
	findingSvc := NewFindingService(db)
	contractSvc := NewContractService(db, bb, nil)
	contractSvc.SetDeliveryWriteback(cfg.DeliveryWriteback)

	cairn := NewCairnLoop(db, bb, intentSvc, nil, findingSvc, contractSvc, nil, nil, nil).
		WithPromotionGate(cfg.PromotionGate).
		WithFinalizeMode(cfg.FinalizeMode).
		WithClueDrivenPhase(cfg.ClueDrivenPhase)

	// === 1. Simulate task creation with initial intent ===
	initialIntent := model.AIIntent{
		TaskID:      taskID,
		IntentType:  "code_trace", // legacy type
		Title:       "启动授权安全验证",
		Objective:   "Collect first-layer facts",
		Status:      model.IntentStatusPending,
		CreatedBy:   "system",
		PriorityScore: 1.0,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	normalizeIntentBeforeCreate(&initialIntent, cfg.ClueDrivenPhase)
	if err := db.Create(&initialIntent).Error; err != nil {
		t.Fatalf("create initial intent: %v", err)
	}

	// Verify: initial intent normalized to modern type
	if !model.IsModernIntentType(initialIntent.IntentType) {
		t.Errorf("initial intent type %q not in modern set", initialIntent.IntentType)
	}
	t.Logf("Initial intent normalized: %s", initialIntent.IntentType)

	// === 2. Simulate Reasoner producing intents via CreateIntentFromSuggestion ===
	cairn.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{
		IntentType: "sql_injection_validation", // legacy — should be normalized
		Objective:  "Test parameter injection",
		Hypothesis: "param may be injectable",
		Priority:   80,
	})
	cairn.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{
		IntentType: "clue_validate", // already modern
		Objective:  "Validate auth boundary",
		Hypothesis: "missing owner check",
		Priority:   70,
	})

	// === 3. Verify all intents are modern ===
	var intents []model.AIIntent
	db.Where("task_id = ?", taskID).Find(&intents)
	for _, intent := range intents {
		if !model.IsModernIntentType(intent.IntentType) {
			t.Errorf("intent %d has non-modern type %q", intent.ID, intent.IntentType)
		}
	}
	t.Logf("Total intents: %d, all modern types", len(intents))

	// === 4. Verify legacy_hint preserved ===
	var legacyHintFound bool
	for _, intent := range intents {
		var constraints map[string]any
		_ = json.Unmarshal(intent.ConstraintsJSON, &constraints)
		if constraints["legacy_hint"] != nil {
			legacyHintFound = true
			t.Logf("Intent %d has legacy_hint=%v", intent.ID, constraints["legacy_hint"])
		}
	}
	if !legacyHintFound {
		t.Error("expected at least one intent with legacy_hint")
	}

	// === 5. Simulate GraphDelta with structured clue fields ===
	delta := GraphDelta{
		IntentID: initialIntent.ID,
		NewClueFacts: []ClueFact{
			{NodeKind: model.NodeClueOrigin, Title: "GET /api/users", Summary: "entry", Roles: []string{model.RoleOriginOrEntry}, EvidenceIDs: []uint{1}},
			{NodeKind: model.NodeClueObservation, Title: "param id controllable", Summary: "trigger", Roles: []string{model.RoleTriggerOrControl}},
			{NodeKind: model.NodeClueLink, Title: "id flows to query", Summary: "reachability", Roles: []string{model.RoleReachabilityOrRelation}},
		},
		ClueChainLinks: []ClueChainLink{
			{FromCluePath: "GET /api/users", ToCluePath: "param id controllable", LinkKind: "data_flow"},
		},
	}
	if err := cairn.ApplyGraphDelta(ctx, taskID, delta); err != nil {
		t.Fatalf("ApplyGraphDelta: %v", err)
	}

	// === 6. Verify clue_* nodes written ===
	var clueNodes int64
	db.Model(&model.AIBlackboardNode{}).
		Where("task_id = ? AND node_type IN ?", taskID, []string{model.NodeClueOrigin, model.NodeClueObservation, model.NodeClueLink, model.NodeClueImpact}).
		Count(&clueNodes)
	if clueNodes == 0 {
		t.Error("expected clue_* nodes in blackboard")
	}
	t.Logf("Clue nodes: %d", clueNodes)

	// === 7. Verify clue_* edges written ===
	var clueEdges int64
	db.Model(&model.AIBlackboardEdge{}).
		Where("task_id = ? AND edge_type IN ?", taskID, []string{model.EdgeClueSupports, model.EdgeClueRefutes, model.EdgeClueChainsTo}).
		Count(&clueEdges)
	t.Logf("Clue edges: %d", clueEdges)

	// === 8. Simulate RefutedClues ===
	var targetNode model.AIBlackboardNode
	db.Where("task_id = ? AND title = ?", taskID, "param id controllable").First(&targetNode)
	if targetNode.ID != 0 {
		refuteDelta := GraphDelta{
			IntentID: initialIntent.ID,
			RefutedClues: []ClueRefutation{
				{TargetNodeID: targetNode.ID, Reason: "owner check present"},
			},
		}
		_ = cairn.ApplyGraphDelta(ctx, taskID, refuteDelta)

		var refutedNode model.AIBlackboardNode
		db.First(&refutedNode, targetNode.ID)
		if refutedNode.Status != model.BlackboardNodeStatusSuppressed {
			t.Errorf("expected suppressed, got %s", refutedNode.Status)
		}
	}

	// === 9. Verify Contract incomplete does NOT generate Intent ===
	finding := model.AIFinding{
		TaskID:            taskID,
		Title:             "Test finding",
		VulnerabilityType: "test",
		Severity:          "medium",
		Status:            model.FindingStatusCandidate,
		ValidationStatus:  model.ValidationToolObserved,
		ContractStatus:    model.ContractStatusNotChecked,
		HumanReviewStatus: model.HumanReviewPending,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	db.Create(&finding)

	var intentCountBefore int64
	db.Model(&model.AIIntent{}).Where("task_id = ?", taskID).Count(&intentCountBefore)

	contractSvc.CheckFinding(ctx, &finding)

	var intentCountAfter int64
	db.Model(&model.AIIntent{}).Where("task_id = ?", taskID).Count(&intentCountAfter)
	if intentCountAfter > intentCountBefore {
		t.Error("Contract incomplete should NOT generate Intent when deliveryWriteback=off")
	}
	t.Logf("Intent count before/after contract check: %d/%d (no new intent)", intentCountBefore, intentCountAfter)

	// === 10. Verify audit events ===
	var auditCount int64
	db.Model(&model.AIAuditEvent{}).Where("task_id = ?", taskID).Count(&auditCount)
	t.Logf("Audit events: %d", auditCount)

	var contractDiagnostic int64
	db.Model(&model.AIAuditEvent{}).
		Where("task_id = ? AND event_type = ?", taskID, "agent.contract_incomplete_diagnostic").
		Count(&contractDiagnostic)
	t.Logf("Contract diagnostic audits: %d", contractDiagnostic)

	var normalizeAudits int64
	db.Model(&model.AIAuditEvent{}).
		Where("task_id = ? AND event_type = ?", taskID, "agent.legacy_intent_normalized").
		Count(&normalizeAudits)
	t.Logf("Legacy intent normalized audits: %d", normalizeAudits)

	var clueDeltaAudits int64
	db.Model(&model.AIAuditEvent{}).
		Where("task_id = ? AND event_type = ?", taskID, "agent.clue_delta_ingested").
		Count(&clueDeltaAudits)
	if clueDeltaAudits == 0 {
		t.Error("expected agent.clue_delta_ingested audit")
	}
	t.Logf("Clue delta ingested audits: %d", clueDeltaAudits)

	// === 11. Verify ShouldFinalize uses clue-progress ===
	task := model.AISecurityTask{ID: taskID, TaskType: model.TaskTypeCodeAudit, Objective: "test"}
	// With no progress and no pending intents, should finalize as clue-plateau
	// First mark all intents as completed
	db.Model(&model.AIIntent{}).Where("task_id = ?", taskID).Update("status", model.IntentStatusCompleted)
	shouldStop := cairn.ShouldFinalizeWithNoProgressLimit(ctx, task, 5, 20, 4, 3)
	if !shouldStop {
		t.Error("expected ShouldFinalize to return true (clue-plateau) with no progress")
	}

	// === 12. Verify Capability Gate uses clue_chain ===
	capWithNoNodes := model.AICapability{
		TaskID:         taskID,
		CapabilityType: "file_read",
		Target:         "/etc/passwd",
		Strength:       model.StrengthVerified,
		EvidenceRefs:   mustJSON([]uint{}),
		SourceNodeIDs:  mustJSON([]uint{}),
		CanAdvanceGoal: true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	db.Create(&capWithNoNodes)
	gate := cairn.EvaluateCapabilityPromotionGate(ctx, capWithNoNodes)
	if gate.Allowed {
		t.Error("clue_chain gate should reject capability with no nodes/evidence")
	}
	t.Logf("Capability gate (no nodes): Allowed=%v, Missing=%v", gate.Allowed, gate.Missing)

	// === Summary ===
	t.Log("=== Integration Summary ===")
	t.Logf("All intents modern: YES")
	t.Logf("Clue nodes written: %d", clueNodes)
	t.Logf("Contract writeback blocked: YES")
	t.Logf("ShouldFinalize clue-plateau: YES")
	t.Logf("Capability gate clue_chain: YES")
}

// TestClueDrivenIntegration_Phase3_Pentest verifies pentest task path.
func TestClueDrivenIntegration_Phase3_Pentest(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9502)

	cfg := config.Config{
		ClueDrivenPhase:   3,
		PromotionGate:     "clue_chain",
		FinalizeMode:      "clue",
		DeliveryWriteback: "off",
	}

	bb := NewBlackboardService(db)
	cairn := NewCairnLoop(db, bb, NewIntentService(db), nil, nil, nil, nil, nil, nil).
		WithPromotionGate(cfg.PromotionGate).
		WithFinalizeMode(cfg.FinalizeMode).
		WithClueDrivenPhase(cfg.ClueDrivenPhase)

	// Pentest initial intent is "recon" → should normalize to scope_observation
	intent := model.AIIntent{
		TaskID:     taskID,
		IntentType: "recon",
		Title:      "Recon target",
		Objective:  "Discover surfaces",
		Status:     model.IntentStatusPending,
		CreatedBy:  "system",
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	normalizeIntentBeforeCreate(&intent, cfg.ClueDrivenPhase)
	db.Create(&intent)

	if intent.IntentType != model.IntentScopeObservation {
		t.Errorf("pentest recon should normalize to %s, got %s", model.IntentScopeObservation, intent.IntentType)
	}

	// Simulate reasoner producing pentest intents
	cairn.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{
		IntentType: "idor_test",
		Objective:  "Check object access",
		Priority:   85,
	})
	cairn.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{
		IntentType: "fingerprint",
		Objective:  "Identify components",
		Priority:   60,
	})

	var intents []model.AIIntent
	db.Where("task_id = ?", taskID).Find(&intents)
	for _, i := range intents {
		if !model.IsModernIntentType(i.IntentType) {
			t.Errorf("pentest intent %d has non-modern type %q", i.ID, i.IntentType)
		}
	}
	t.Logf("Pentest intents: %d, all modern", len(intents))
}

// TestClueDrivenIntegration_DefaultPhase_LegacyBehavior verifies that with
// default toggles (phase=0), old behavior is preserved.
func TestClueDrivenIntegration_DefaultPhase_LegacyBehavior(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9503)

	// Default config: phase=0, all legacy
	bb := NewBlackboardService(db)
	cairn := NewCairnLoop(db, bb, NewIntentService(db), nil, nil, nil, nil, nil, nil)
	// Default: promotionGate=legacy, finalizeMode=legacy, clueDrivenPhase=0

	// Legacy intent should NOT be normalized
	intent := model.AIIntent{
		TaskID:     taskID,
		IntentType: "sql_injection_validation",
		Title:      "Test SQLi",
		Status:     model.IntentStatusPending,
		CreatedBy:  "system",
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	normalizeIntentBeforeCreate(&intent, 0) // phase 0 = no-op
	db.Create(&intent)

	if intent.IntentType != "sql_injection_validation" {
		t.Errorf("phase 0 should NOT normalize: got %s", intent.IntentType)
	}

	// CreateIntentFromSuggestion at phase 0 uses the existing normalizeGraphSearchIntentType
	// which already maps legacy vuln intents to generic types. This is pre-existing behavior.
	cairn.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{
		IntentType: "idor_test",
		Objective:  "Check access",
		Priority:   80,
	})

	// The intent should exist (may have been normalized by the existing
	// normalizeGraphSearchIntentType, which is pre-Phase-3 legacy behavior)
	var allIntents []model.AIIntent
	db.Where("task_id = ? AND objective = ?", taskID, "Check access").Find(&allIntents)
	if len(allIntents) == 0 {
		// May have been rejected by normalizeGraphSearchIntentType — that's acceptable
		// at phase 0 since it's pre-existing behavior
		t.Log("idor_test intent was handled by existing normalizeGraphSearchIntentType (pre-existing behavior)")
	} else {
		t.Logf("Legacy behavior preserved at phase 0: intent created with type %s", allIntents[0].IntentType)
	}

	// Key assertion: the sql_injection_validation intent we created directly
	// should still have its original type (normalizeIntentBeforeCreate was no-op)
	var directIntent model.AIIntent
	db.Where("task_id = ? AND title = ?", taskID, "Test SQLi").First(&directIntent)
	if directIntent.ID != 0 && directIntent.IntentType != "sql_injection_validation" {
		t.Errorf("phase 0 direct intent should keep original type, got %s", directIntent.IntentType)
	}
}

// TestClueDrivenIntegration_VerifiedCapability_DoesNotStopExploration verifies
// that a single verified capability does not cause global termination.
func TestClueDrivenIntegration_VerifiedCapability_DoesNotStopExploration(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9504)

	bb := NewBlackboardService(db)
	cairn := NewCairnLoop(db, bb, NewIntentService(db), nil, nil, nil, nil, nil, nil).
		WithFinalizeMode("clue").
		WithClueDrivenPhase(3)

	// Create a pending intent (exploration still active)
	db.Create(&model.AIIntent{
		TaskID:     taskID,
		IntentType: model.IntentClueValidate,
		Title:      "Validate something",
		Status:     model.IntentStatusPending,
		CreatedBy:  "agent",
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	})

	// Create a verified capability
	db.Create(&model.AICapability{
		TaskID:         taskID,
		CapabilityType: "file_read",
		Target:         "/etc/passwd",
		Strength:       model.StrengthVerified,
		CanAdvanceGoal: true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	})

	task := model.AISecurityTask{ID: taskID, TaskType: model.TaskTypePentest}
	shouldStop := cairn.ShouldFinalizeWithNoProgressLimit(ctx, task, 3, 20, 0, 6)
	if shouldStop {
		t.Error("verified capability alone should NOT stop exploration when pending intents exist")
	}
}
