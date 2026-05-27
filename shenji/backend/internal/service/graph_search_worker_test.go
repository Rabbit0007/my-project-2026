package service

import (
	"context"
	"testing"
	"time"

	"shenji/backend/internal/model"
)

func TestGraphSearchBootstrapCreatesFactsAndIntents(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(8101)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, NewFindingService(db), nil, nil, nil, nil)

	err := loop.ApplyGraphDelta(ctx, taskID, GraphDelta{
		IntentID: 1,
		NewFacts: []GraphFact{{
			NodeType: model.NodeEntrypoint,
			Title:    "POST /upload",
			Summary:  "Upload route accepts multipart input and reaches file handling code.",
		}},
		NewIntents: []IntentSuggestion{{
			IntentType:      model.IntentInspectDataflow,
			Objective:       "Trace whether uploaded filename reaches a filesystem sink.",
			SuccessCriteria: "Evidence-backed source-to-sink path or a NegativeFact.",
			Priority:        90,
		}},
	})
	if err != nil {
		t.Fatalf("apply bootstrap delta: %v", err)
	}
	var factCount int64
	db.Model(&model.AIBlackboardNode{}).Where("task_id = ? AND node_type = ?", taskID, model.NodeEntrypoint).Count(&factCount)
	if factCount != 1 {
		t.Fatalf("expected bootstrap fact, got %d", factCount)
	}
	var intent model.AIIntent
	if err := db.Where("task_id = ? AND intent_type = ?", taskID, model.IntentInspectDataflow).First(&intent).Error; err != nil {
		t.Fatalf("expected bootstrap-generated intent: %v", err)
	}
	if !intentEligibleForNextPending(intent) {
		t.Fatalf("expected generic graph intent to be runtime eligible: %+v", intent)
	}
}

func TestGraphSearchReasonGeneratesEvidenceDrivenIntent(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(8102)
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "reason graph", TaskType: model.TaskTypeCodeAudit, Status: model.TaskStatusRunning, Objective: "Find evidence-backed security impact paths.", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := db.Create(&model.AIEvidence{ID: 6101, TaskID: taskID, EvidenceType: "code", Title: "filename source", Summary: "Request filename is user-controlled.", RelationType: "source", Hash: "reason-evidence", CreatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	blackboard := NewBlackboardService(db)
	_, _ = blackboard.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeCodeFact, Title: "filename source", Summary: "Request filename is user-controlled.", EvidenceRefs: []uint{6101}, SourceType: "test", ImportanceScore: 0.8})
	loop := NewCairnLoop(db, blackboard, NewIntentService(db), nil, NewFindingService(db), nil, nil, nil, nil)
	summary := loop.BuildGraphSummary(ctx, task, 2, 20)
	if len(summary.ConfirmedFacts) == 0 || len(summary.RecentEvidence) == 0 {
		t.Fatalf("expected graph summary to include confirmed facts and evidence: %+v", summary)
	}
	loop.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{
		IntentType:   model.IntentInspectGuard,
		Objective:    "Determine whether the filename path is canonicalized and constrained before write.",
		AllowedTools: []string{"code_slice"},
		Priority:     88,
	})
	var intent model.AIIntent
	if err := db.Where("task_id = ? AND intent_type = ?", taskID, model.IntentInspectGuard).First(&intent).Error; err != nil {
		t.Fatalf("expected reason-generated guard intent: %v", err)
	}
	if intent.Objective == "" || intent.PriorityScore <= 0 {
		t.Fatalf("expected useful reason intent fields: %+v", intent)
	}
}

func TestGraphSearchExploreWritesGraphDelta(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(8103)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, NewFindingService(db), nil, nil, nil, nil)
	evidence := model.AIEvidence{ID: 6201, TaskID: taskID, EvidenceType: "code_slice", Title: "path join", Summary: "filename reaches filepath.Join.", RelationType: "dataflow", FilePath: "upload.go", Hash: "explore-evidence", CreatedAt: time.Now()}
	if err := db.Create(&evidence).Error; err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	if err := loop.ApplyGraphDelta(ctx, taskID, GraphDelta{
		IntentID:    99,
		NewEvidence: []model.AIEvidence{evidence},
		NewFacts: []GraphFact{{
			NodeType: model.NodeDataflow,
			Title:    "filename to file path",
			Summary:  "User-controlled filename participates in final filesystem path construction.",
		}},
	}); err != nil {
		t.Fatalf("apply explore delta: %v", err)
	}
	var evidenceNode, factNode int64
	db.Model(&model.AIBlackboardNode{}).Where("task_id = ? AND node_type = ?", taskID, model.NodeEvidence).Count(&evidenceNode)
	db.Model(&model.AIBlackboardNode{}).Where("task_id = ? AND node_type = ?", taskID, model.NodeDataflow).Count(&factNode)
	if evidenceNode != 1 || factNode != 1 {
		t.Fatalf("expected evidence and fact nodes, evidence=%d fact=%d", evidenceNode, factNode)
	}
}

func TestWorkerOutputAcceptsGraphDeltaPacket(t *testing.T) {
	raw := `{"accepted":true,"graph_delta":{"new_facts":[{"kind":"dataflow","subject":"filename","summary":"filename reaches filepath.Join"}],"new_evidence":[{"type":"code_slice","title":"path join","summary":"filepath.Join(uploadDir, filename)","raw":"filepath.Join(uploadDir, filename)","relation_type":"dataflow"}],"new_intents":[{"title":"Inspect guard","objective":"Determine whether canonical path is constrained.","intent_type":"inspect_guard"}],"new_negative_facts":[],"new_capability_candidates":[],"diagnostics":["delta parsed"]}}`
	parsed, err := parseWorkerAgentOutput(raw)
	if err != nil {
		t.Fatalf("parse graph delta worker output: %v", err)
	}
	if len(parsed.Data.Facts) != 1 || !parsed.Accepted {
		t.Fatalf("expected graph delta fact to normalize into worker data: %+v", parsed)
	}
	if len(parsed.Data.Evidence) != 1 || parsed.Data.Evidence[0].RelationType != "dataflow" {
		t.Fatalf("expected graph delta evidence to normalize, got %+v", parsed.Data.Evidence)
	}
	if len(parsed.Data.NextIntentSuggestions) != 1 || parsed.Data.NextIntentSuggestions[0].IntentType != model.IntentInspectGuard {
		t.Fatalf("expected graph delta intent suggestion, got %+v", parsed.Data.NextIntentSuggestions)
	}
	if err := validateWorkerAgentOutput(raw, parsed); err != nil {
		t.Fatalf("graph delta worker output should validate: %v", err)
	}
}

func TestNegativeFactPreventsRepeatedDeadPath(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(8104)
	intentID := uint(44)
	if err := db.Create(&model.AINegativeFact{TaskID: taskID, Title: "Download endpoint uses server-side lookup", TestedPath: "/download?id=", Reason: "Raw path input is not accepted.", SimilarPatternKey: "download-dead-path", CreatedFromIntentID: &intentID, CreatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("create negative fact: %v", err)
	}
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, NewFindingService(db), nil, nil, nil, nil)
	loop.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{
		IntentType: model.IntentInspectDataflow,
		Objective:  "Retry /download?id= raw path traversal exploration.",
		Priority:   80,
	})
	var count int64
	db.Model(&model.AIIntent{}).Where("task_id = ?", taskID).Count(&count)
	if count != 0 {
		t.Fatalf("negative fact should suppress repeated dead path intent, got %d", count)
	}
}

func TestVerifiedCapabilityPromotionRequiresEvidence(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(8105)
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "gate", TaskType: model.TaskTypePentest, Status: model.TaskStatusRunning}
	_ = db.Create(&task).Error
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, NewFindingService(db), NewContractService(db, NewBlackboardService(db), nil), nil, nil, nil)
	cap, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapCrossUserObjectAccess,
		Target:         "/objects/1",
		Strength:       model.StrengthVerified,
		ProofSummary:   "verified without evidence should not promote",
		CanAdvanceGoal: true,
	}, nil)
	if err != nil {
		t.Fatalf("write capability: %v", err)
	}
	gate := loop.EvaluateCapabilityPromotionGate(ctx, cap)
	if gate.Allowed {
		t.Fatalf("expected gate to reject capability without evidence: %+v", gate)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote capabilities: %v", err)
	}
	var findings int64
	db.Model(&model.AIFinding{}).Where("task_id = ?", taskID).Count(&findings)
	if findings != 0 {
		t.Fatalf("finding must not be created without evidence-backed verified capability")
	}
}

func TestFindingOnlyPromotesFromVerifiedCapability(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(8106)
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "finding promotion", TaskType: model.TaskTypePentest, Status: model.TaskStatusRunning}
	_ = db.Create(&task).Error
	blackboard := NewBlackboardService(db)
	loop := NewCairnLoop(db, blackboard, NewIntentService(db), nil, NewFindingService(db), NewContractService(db, blackboard, nil), nil, nil, nil)
	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapCrossUserObjectAccess,
		Target:         "/objects/1",
		Strength:       model.StrengthObserved,
		ProofSummary:   string(mustJSON(completeDeliveryDetails("/objects/1", model.CapCrossUserObjectAccess, []uint{1}))),
		EvidenceIDs:    []uint{1},
		CanAdvanceGoal: true,
	}, nil); err != nil {
		t.Fatalf("write observed capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote observed: %v", err)
	}
	var count int64
	db.Model(&model.AIFinding{}).Where("task_id = ?", taskID).Count(&count)
	if count != 0 {
		t.Fatalf("observed capability must not promote to finding")
	}
	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapCrossUserObjectAccess,
		Target:         "/objects/1",
		Strength:       model.StrengthVerified,
		ProofSummary:   string(mustJSON(completeDeliveryDetails("/objects/1", model.CapCrossUserObjectAccess, []uint{2}))),
		EvidenceIDs:    []uint{2},
		CanAdvanceGoal: true,
	}, nil); err != nil {
		t.Fatalf("write verified capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote verified: %v", err)
	}
	db.Model(&model.AIFinding{}).Where("task_id = ?", taskID).Count(&count)
	if count != 1 {
		t.Fatalf("expected exactly one finding from verified capability, got %d", count)
	}
}

func TestFixtureRawQueryProducesVerifiedCapability(t *testing.T) {
	assertSyntheticFixtureProducesVerifiedCapability(t, model.CapSQLInjection, "User-controlled sort field reaches raw query fragment.")
}

func TestFixtureFilePathControlProducesVerifiedCapability(t *testing.T) {
	assertSyntheticFixtureProducesVerifiedCapability(t, model.CapFileRead, "User-controlled filename reaches final filesystem path.")
}

func TestFixtureObjectAccessControlProducesVerifiedCapability(t *testing.T) {
	assertSyntheticFixtureProducesVerifiedCapability(t, model.CapCrossUserObjectAccess, "User B receives User A object response.")
}

func assertSyntheticFixtureProducesVerifiedCapability(t *testing.T, capType string, summary string) {
	t.Helper()
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(8200 + len(capType))
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "synthetic fixture", TaskType: model.TaskTypeCodeAudit, Status: model.TaskStatusRunning, Objective: "Find evidence-backed security impact path."}
	_ = db.Create(&task).Error
	blackboard := NewBlackboardService(db)
	loop := NewCairnLoop(db, blackboard, NewIntentService(db), nil, NewFindingService(db), NewContractService(db, blackboard, nil), nil, nil, nil)
	evidenceID := uint(9000 + len(capType))
	if err := db.Create(&model.AIEvidence{ID: evidenceID, TaskID: taskID, EvidenceType: "fixture_trace", Title: summary, Summary: summary, RelationType: "observed_signal", Hash: summary, CreatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("create fixture evidence: %v", err)
	}
	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: capType,
		Target:         summary,
		Strength:       model.StrengthVerified,
		ProofSummary:   string(mustJSON(completeDeliveryDetails(summary, capType, []uint{evidenceID}))),
		EvidenceIDs:    []uint{evidenceID},
		CanAdvanceGoal: true,
	}, nil); err != nil {
		t.Fatalf("write fixture capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote fixture capability: %v", err)
	}
	var cap model.AICapability
	if err := db.Where("task_id = ? AND capability_type = ? AND strength = ?", taskID, capType, model.StrengthVerified).First(&cap).Error; err != nil {
		t.Fatalf("expected verified fixture capability: %v", err)
	}
}
