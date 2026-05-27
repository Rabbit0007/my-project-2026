package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"shenji/backend/internal/config"
	"shenji/backend/internal/model"
)

func TestParseWorkerAgentOutputExtractsStructuredEvidence(t *testing.T) {
	raw := "worker result:\n```json\n{\"accepted\":true,\"data\":{\"summary\":\"observed state change\",\"facts\":[\"object owner differs\"],\"evidence\":[{\"type\":\"response_diff\",\"title\":\"cross user diff\",\"summary\":\"B can read A object\",\"raw\":\"GET /objects/1 => 200\",\"target\":\"/objects/1\",\"relation_type\":\"worker_result\"}],\"next_intent_suggestions\":[{\"title\":\"compare write path\",\"objective\":\"Validate whether write path has same owner boundary\",\"intent_type\":\"auth_boundary_test\"}]}}\n```"
	parsed, err := parseWorkerAgentOutput(raw)
	if err != nil {
		t.Fatalf("expected worker output to parse: %v", err)
	}
	if !parsed.Accepted {
		t.Fatalf("expected accepted worker output")
	}
	if parsed.Data.Summary != "observed state change" {
		t.Fatalf("unexpected summary: %s", parsed.Data.Summary)
	}
	if len(parsed.Data.Evidence) != 1 || parsed.Data.Evidence[0].Type != "response_diff" {
		t.Fatalf("expected one response_diff evidence item, got %+v", parsed.Data.Evidence)
	}
	if len(parsed.Data.NextIntentSuggestions) != 1 || parsed.Data.NextIntentSuggestions[0].IntentType != "auth_boundary_test" {
		t.Fatalf("expected next intent suggestion, got %+v", parsed.Data.NextIntentSuggestions)
	}
}

func TestParseWorkerAgentOutputAcceptsStringSuggestionsAndCapabilityAliases(t *testing.T) {
	raw := `{"accepted":true,"data":{"summary":"observed git metadata","facts":["/.git/HEAD returned a branch ref"],"evidence":[{"type":"http_exchange","title":"git head","summary":"GET .git/HEAD returned 200","raw":"ref: refs/heads/master","target":"http://example.test/.git/HEAD","relation_type":"worker_result"}],"capability_candidates":[{"name":"public_git_metadata_access","summary":"Accessible .git metadata may expose source-control state.","target":"http://example.test/.git/HEAD"}],"next_intent_suggestions":["Enumerate whether additional .git refs are reachable."]}}`
	parsed, err := parseWorkerAgentOutput(raw)
	if err != nil {
		t.Fatalf("expected worker output to parse: %v", err)
	}
	if err := validateWorkerAgentOutput(raw, parsed); err != nil {
		t.Fatalf("expected worker output to validate: %v", err)
	}
	if len(parsed.Data.NextIntentSuggestions) != 1 || parsed.Data.NextIntentSuggestions[0].IntentType != model.IntentBehaviorProbe {
		t.Fatalf("expected string suggestion normalized to behavior probe, got %+v", parsed.Data.NextIntentSuggestions)
	}
	if len(parsed.Data.CapabilityCandidates) != 1 || parsed.Data.CapabilityCandidates[0].Name != "public_git_metadata_access" {
		t.Fatalf("expected capability alias fields preserved, got %+v", parsed.Data.CapabilityCandidates)
	}
}

func TestExtractPiAssistantTextFromJSONLEvents(t *testing.T) {
	stdout := `{"type":"turn_end","message":{"role":"assistant","content":[{"type":"text","text":"{\"accepted\":true,\"data\":{\"summary\":\"ok\"}}"}]}}`
	text := extractPiAssistantText(stdout)
	parsed, err := parseWorkerAgentOutput(text)
	if err != nil {
		t.Fatalf("expected extracted assistant JSON to parse: %v", err)
	}
	if parsed.Data.Summary != "ok" {
		t.Fatalf("unexpected parsed summary: %s", parsed.Data.Summary)
	}
}

func TestNativeWorkerDriverDoesNotHandleIntent(t *testing.T) {
	orchestrator := &AgentOrchestrator{}
	worker := WorkerRuntimeSelection{
		Config: model.AIModelConfig{
			ID:          7,
			Name:        "native-worker",
			Purpose:     model.ModelPurposeWorker,
			Provider:    "openai-compatible",
			Model:       "worker-model",
			OptionsJSON: mustJSON(map[string]any{"workerDriver": "native"}),
		},
		WorkerID: "worker:7:native-worker",
	}
	handled, outcomes, err := orchestrator.runExternalWorkerIntent(context.Background(), &model.AISecurityTask{}, &model.AIIntent{}, &model.AIAgentLoopIteration{}, AgentContext{}, worker)
	if err != nil {
		t.Fatalf("native worker driver should not error: %v", err)
	}
	if handled || len(outcomes) != 0 {
		t.Fatalf("native driver must leave execution to Rabbit runner, handled=%v outcomes=%d", handled, len(outcomes))
	}
}

func TestIngestWorkerGraphOutputKeepsWorkerAsEvidenceProducer(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	blackboard := NewBlackboardService(db)
	orchestrator := &AgentOrchestrator{db: db, blackboard: blackboard}
	taskID := uint(424242)
	toolRunID := uint(9)
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "worker graph ingest", TaskType: model.TaskTypePentest, Status: model.TaskStatusRunning, Objective: "validate object ownership"}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	currentHypothesis, err := lifecycle.FormHypothesis(ctx, HypothesisDraft{
		TaskID:                taskID,
		HypothesisType:        model.HypothesisTypeIDORCandidate,
		Title:                 "User B may read User A object",
		Description:           "Validate cross-user object ownership boundary.",
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: []string{"test"},
		TargetEntity:          "/objects/1",
		ExpectedCapability:    model.CapCrossUserObjectAccess,
	})
	if err != nil {
		t.Fatalf("create hypothesis: %v", err)
	}
	currentIntent, err := lifecycle.CreateValidationIntent(ctx, currentHypothesis, model.IntentIDORProbe, "test_current_worker_intent", 0.7)
	if err != nil {
		t.Fatalf("create current intent: %v", err)
	}
	output := workerAgentOutput{
		Accepted: true,
		Data: workerAgentData{
			Facts: []string{"B can read A object in response diff"},
			CapabilityCandidates: []workerAgentCapability{{
				CapabilityType: model.CapCrossUserObjectAccess,
				Target:         "/objects/1",
				Strength:       model.StrengthVerified,
				ProofSummary:   "Worker observed a 200 response for user B when reading user A object.",
			}},
			NegativeFacts: []workerAgentNegativeFact{{
				Title:   "Write path rejected cross-user update",
				Summary: "PATCH /objects/1 returned 403 for user B.",
				Target:  "/objects/1",
			}},
			UnverifiedRisks: []workerAgentUnverifiedRisk{{
				Title:   "Delete path not tested",
				Summary: "Worker lacked a safe object to delete.",
				Reason:  "safety_block",
				Target:  "/objects/1",
			}},
			NextIntentSuggestions: []SecurityGraphIntentSuggestion{
				{Title: "Compare update path", Objective: "Validate whether update path enforces owner boundary.", IntentType: model.IntentIDORProbe, RequiredEvidence: []string{"response_diff"}},
				{Title: "Removed side path", Objective: "Search external proof packets.", IntentType: "proof_packet_search"},
			},
		},
	}
	evidence := []model.AIEvidence{{ID: 101, TaskID: taskID, EvidenceType: "response_diff", Title: "diff", Summary: "200 vs 403", Hash: "h"}}
	summary, err := orchestrator.ingestWorkerGraphOutput(ctx, taskID, currentIntent.ID, toolRunID, output, evidence)
	if err != nil {
		t.Fatalf("ingest worker graph output: %v", err)
	}
	if summary.FactsCreated != 1 || summary.CapabilitiesCreated != 1 || summary.NegativeFactsCreated != 1 || summary.UnverifiedRisksCreated != 1 || summary.NextIntentsCreated != 1 || summary.NextIntentsSkipped != 1 {
		t.Fatalf("unexpected ingest summary: %+v", summary)
	}
	var cap model.AICapability
	if err := db.Where("task_id = ? AND capability_type = ?", taskID, model.CapCrossUserObjectAccess).First(&cap).Error; err != nil {
		t.Fatalf("expected worker capability candidate to become graph capability: %v", err)
	}
	if cap.Strength != model.StrengthObserved {
		t.Fatalf("worker capability candidates must not self-upgrade to verified, got %s", cap.Strength)
	}
	if cap.CanAdvanceGoal {
		t.Fatalf("worker capability candidates must not directly advance goal before Rabbit validation")
	}
	if cap.ValidatedByHypothesisID != nil {
		t.Fatalf("observed worker capability must not validate a hypothesis directly, got %d", *cap.ValidatedByHypothesisID)
	}
	var currentAfter model.AIHypothesisNode
	if err := db.First(&currentAfter, currentHypothesis.ID).Error; err != nil {
		t.Fatalf("reload current hypothesis: %v", err)
	}
	if currentAfter.Status == model.HypothesisStatusValidated {
		t.Fatalf("worker observed capability must not mark current hypothesis validated")
	}
	var promotionIntent model.AIIntent
	if err := db.Where("task_id = ? AND created_by = ? AND constraints_json LIKE ?", taskID, "dynamic-intent-expander", "%observed_capability_promotion%").First(&promotionIntent).Error; err != nil {
		t.Fatalf("expected observed capability promotion validation intent: %v", err)
	}
	var negative model.AINegativeFact
	if err := db.Where("task_id = ? AND title = ?", taskID, "Write path rejected cross-user update").First(&negative).Error; err != nil {
		t.Fatalf("expected bound negative fact: %v", err)
	}
	if negative.HypothesisID == nil || *negative.HypothesisID != currentHypothesis.ID {
		t.Fatalf("expected negative fact to bind current hypothesis, got %+v", negative.HypothesisID)
	}
	var risk model.AIUnverifiedRisk
	if err := db.Where("task_id = ? AND title = ?", taskID, "Delete path not tested").First(&risk).Error; err != nil {
		t.Fatalf("expected bound unverified risk: %v", err)
	}
	if risk.HypothesisID == nil || *risk.HypothesisID != currentHypothesis.ID {
		t.Fatalf("expected unverified risk to bind current hypothesis, got %+v", risk.HypothesisID)
	}
	var findingCount int64
	db.Model(&model.AIFinding{}).Where("task_id = ?", taskID).Count(&findingCount)
	if findingCount != 0 {
		t.Fatalf("worker graph ingest must not create findings, got %d", findingCount)
	}
	var removedIntentCount int64
	db.Model(&model.AIIntent{}).Where("task_id = ? AND intent_type = ?", taskID, "proof_packet_search").Count(&removedIntentCount)
	if removedIntentCount != 0 {
		t.Fatalf("removed ProofPacket intent must not be created, got %d", removedIntentCount)
	}
	var next model.AIIntent
	if err := db.Where("task_id = ? AND intent_type = ? AND created_by = ?", taskID, model.IntentIDORProbe, "worker-agent").First(&next).Error; err != nil {
		t.Fatalf("expected ordinary next intent from worker evidence: %v", err)
	}
	if next.HypothesisID() == nil {
		t.Fatalf("expected worker next intent to be hypothesis-backed for planner scoring")
	}
	if branch, err := next.BranchValue(); err != nil || branch == nil {
		t.Fatalf("expected worker next intent to be scored by StateExpansionPlanner, branch=%+v err=%v", branch, err)
	}
	if next.CreatedBy != "worker-agent" || !intentEligibleForNextPending(next) {
		t.Fatalf("expected worker next intent to remain pending and NextPending-eligible, got %+v", next)
	}
}

func TestIngestWorkerSQLiSignalPromotesToFinding(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	blackboard := NewBlackboardService(db)
	intents := NewIntentService(db)
	findings := NewFindingService(db)
	contracts := NewContractService(db, blackboard, nil)
	orchestrator := NewAgentOrchestrator(config.Config{}, db, nil, intents, nil, blackboard, findings, contracts, nil, nil, nil, nil)
	taskID := uint(424243)
	toolRunID := uint(10)
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "worker sqli ingest", TaskType: model.TaskTypePentest, Status: model.TaskStatusRunning, Objective: "find high risk bugs", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	intent := model.AIIntent{ID: 778, TaskID: taskID, IntentType: model.IntentBehaviorProbe, Title: "Less-1 diff", Objective: "Validate Less-1 SQL error differential", Status: model.IntentStatusRunning, CreatedBy: "worker-agent", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&intent).Error; err != nil {
		t.Fatalf("create intent: %v", err)
	}
	evidence := model.AIEvidence{
		ID:           7102,
		TaskID:       taskID,
		EvidenceType: "command_output",
		Title:        "Less-1 SQL error differential",
		Summary:      "Baseline response differs from single quote variant; body contains You have an error in your SQL syntax.",
		Target:       "http://target/sqli-labs/Less-1/?id=1%27",
		RelationType: "worker_result",
		Hash:         "worker-sqli-hash",
		CreatedAt:    time.Now(),
	}
	if err := db.Create(&evidence).Error; err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	output := workerAgentOutput{
		Accepted: true,
		Data: workerAgentData{
			Summary: "Less-1 id parameter produced a SQL syntax error with a single quote payload.",
			Evidence: []workerAgentEvidence{{
				Type:    "command_output",
				Title:   evidence.Title,
				Summary: evidence.Summary,
				Raw:     "GET /sqli-labs/Less-1/?id=1%27 -> You have an error in your SQL syntax",
				Target:  evidence.Target,
			}},
			CapabilityCandidates: []workerAgentCapability{{
				Name:    "error_based_sql_injection_signal",
				Target:  evidence.Target,
				Summary: "Less-1 id parameter produced a reproducible SQL syntax error.",
			}},
		},
	}
	summary, err := orchestrator.ingestWorkerGraphOutput(ctx, taskID, intent.ID, toolRunID, output, []model.AIEvidence{evidence})
	if err != nil {
		t.Fatalf("ingest worker graph output: %v", err)
	}
	if summary.CapabilitiesCreated != 1 {
		t.Fatalf("expected one capability, got %+v", summary)
	}
	var cap model.AICapability
	if err := db.Where("task_id = ? AND capability_type = ?", taskID, model.CapSQLInjection).First(&cap).Error; err != nil {
		t.Fatalf("expected normalized SQL injection capability: %v", err)
	}
	if cap.Strength != model.StrengthVerified || !cap.CanAdvanceGoal {
		t.Fatalf("expected verified goal-advancing SQLi capability, got strength=%s canAdvance=%v", cap.Strength, cap.CanAdvanceGoal)
	}
	if err := NewCairnLoop(db, blackboard, intents, nil, findings, contracts, nil, nil, nil).PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote capability: %v", err)
	}
	var finding model.AIFinding
	if err := db.Where("task_id = ? AND vulnerability_type = ?", taskID, model.CapSQLInjection).First(&finding).Error; err != nil {
		t.Fatalf("expected SQL injection finding: %v", err)
	}
}

func TestWorkerCapabilityCandidateRequiresEvidence(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	orchestrator := &AgentOrchestrator{db: db, blackboard: NewBlackboardService(db)}
	taskID := uint(4242)
	output := workerAgentOutput{Accepted: true, Data: workerAgentData{CapabilityCandidates: []workerAgentCapability{{
		CapabilityType: model.CapCrossUserObjectAccess,
		Target:         "/objects/1",
		Strength:       model.StrengthObserved,
		ProofSummary:   "Worker claims cross-user access.",
	}}}}
	summary, err := orchestrator.ingestWorkerGraphOutput(ctx, taskID, 7, 9, output, nil)
	if err != nil {
		t.Fatalf("ingest worker graph output without evidence: %v", err)
	}
	if summary.CapabilitiesCreated != 0 || summary.CapabilitiesSkipped != 1 {
		t.Fatalf("expected capability candidate without evidence to be skipped, got %+v", summary)
	}
	var capCount int64
	db.Model(&model.AICapability{}).Where("task_id = ?", taskID).Count(&capCount)
	if capCount != 0 {
		t.Fatalf("worker capability candidate without evidence must not persist, got %d", capCount)
	}
}

func TestWorkerFactQualityScoresEvidenceBackedFactsHigher(t *testing.T) {
	high := workerAgentOutput{Accepted: true, Data: workerAgentData{
		Summary: "observed object boundary behavior",
		Facts:   []string{"user B received a different authorization result than user A"},
		Evidence: []workerAgentEvidence{{
			Type:    "response_diff",
			Title:   "cross-user read diff",
			Summary: "A received 200 and B received 403 for the same object",
			Raw:     "GET /objects/1 as A => 200\nGET /objects/1 as B => 403",
			Target:  "/objects/1",
		}},
		NegativeFacts: []workerAgentNegativeFact{{
			Title:   "cross-user read blocked",
			Summary: "B could not read A object",
			Target:  "/objects/1",
		}},
		NextIntentSuggestions: []SecurityGraphIntentSuggestion{{
			Title:      "Compare update path",
			Objective:  "Validate whether update path enforces the same owner boundary.",
			IntentType: model.IntentIDORProbe,
		}},
	}}
	low := workerAgentOutput{Accepted: true, Data: workerAgentData{Summary: "looked around but no concrete observation"}}
	highQuality := scoreWorkerAgentOutput(high, []model.AIEvidence{{ID: 1}})
	lowQuality := scoreWorkerAgentOutput(low, nil)
	if highQuality.Score <= lowQuality.Score {
		t.Fatalf("expected evidence-backed worker packet to score higher, high=%+v low=%+v", highQuality, lowQuality)
	}
	if highQuality.Score < 0.70 {
		t.Fatalf("expected high quality worker packet to score at least 0.70, got %+v", highQuality)
	}
	if lowQuality.Score > 0.45 {
		t.Fatalf("expected summary-only worker packet to stay low confidence, got %+v", lowQuality)
	}
}

func TestIngestWorkerGraphOutputStoresFactQualityMetadata(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	blackboard := NewBlackboardService(db)
	orchestrator := &AgentOrchestrator{db: db, blackboard: blackboard}
	taskID := uint(5252)
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "worker fact quality", TaskType: model.TaskTypePentest, Status: model.TaskStatusRunning, Objective: "collect facts"}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	hypothesis, err := lifecycle.FormHypothesis(ctx, HypothesisDraft{
		TaskID:                taskID,
		HypothesisType:        model.HypothesisTypeBusinessLogicCandidate,
		Title:                 "alternate route may reveal state",
		Description:           "Validate the alternate route as a state-space fact.",
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: []string{"test"},
		TargetEntity:          "/objects/1",
		ExpectedCapability:    model.CapInternalServiceAccess,
	})
	if err != nil {
		t.Fatalf("create hypothesis: %v", err)
	}
	intent, err := lifecycle.CreateValidationIntent(ctx, hypothesis, model.IntentBehaviorProbe, "test_quality", 0.7)
	if err != nil {
		t.Fatalf("create intent: %v", err)
	}
	output := workerAgentOutput{Accepted: true, Data: workerAgentData{
		Summary: "observed alternate route behavior",
		Facts:   []string{"alternate route returned a different state marker"},
		Evidence: []workerAgentEvidence{{
			Title:   "state marker diff",
			Summary: "marker changed after alternate route",
			Raw:     "before=locked after=open",
		}},
		NextIntentSuggestions: []SecurityGraphIntentSuggestion{{
			Title:      "Compare neighboring state transition",
			Objective:  "Validate whether a neighboring transition has the same state marker behavior.",
			IntentType: model.IntentBehaviorProbe,
		}},
	}}
	evidence := []model.AIEvidence{{ID: 202, TaskID: taskID, EvidenceType: "response_diff", Title: "state marker diff", Summary: "marker changed", Hash: "quality"}}
	if _, err := orchestrator.ingestWorkerGraphOutput(ctx, taskID, intent.ID, 77, output, evidence); err != nil {
		t.Fatalf("ingest worker output: %v", err)
	}
	var factNode model.AIBlackboardNode
	if err := db.Where("task_id = ? AND source_type = ? AND node_type = ?", taskID, "worker-agent", model.NodeBehaviorFact).First(&factNode).Error; err != nil {
		t.Fatalf("expected worker fact node: %v", err)
	}
	if factNode.ImportanceScore < 0.65 {
		t.Fatalf("expected worker fact importance to reflect evidence quality, got %.3f", factNode.ImportanceScore)
	}
	var next model.AIIntent
	if err := db.Where("task_id = ? AND created_by = ?", taskID, "worker-agent").First(&next).Error; err != nil {
		t.Fatalf("expected worker suggested intent: %v", err)
	}
	constraints := map[string]any{}
	if err := json.Unmarshal(next.ConstraintsJSON, &constraints); err != nil {
		t.Fatalf("unmarshal constraints: %v", err)
	}
	if constraints["workerFactQualityScore"] == nil {
		t.Fatalf("expected worker fact quality score in suggested intent constraints: %+v", constraints)
	}
}

func TestRepairWorkerAgentOutputCreatesObservationOnlyEvidence(t *testing.T) {
	repaired, err := repairWorkerAgentOutput("plain worker notes\nrequest returned 403")
	if err != nil {
		t.Fatalf("repair worker output: %v", err)
	}
	if !repaired.Accepted {
		t.Fatalf("expected repaired output to be accepted as observation-only")
	}
	if len(repaired.Data.Evidence) != 1 || repaired.Data.Evidence[0].Type != "worker_observation" {
		t.Fatalf("expected one worker observation evidence item, got %+v", repaired.Data.Evidence)
	}
	if len(repaired.Data.CapabilityCandidates) != 0 || len(repaired.Data.NextIntentSuggestions) != 0 {
		t.Fatalf("repaired unstructured output must not create capabilities or intents: %+v", repaired.Data)
	}
}

func TestValidateWorkerAgentOutputRejectsDeliveryAndUnsupportedControl(t *testing.T) {
	withFindingField := `{"accepted":true,"data":{"summary":"bad","evidence":[{"title":"e","summary":"s"}],"findings":[{"title":"do not create"}]}}`
	parsed, err := parseWorkerAgentOutput(withFindingField)
	if err != nil {
		t.Fatalf("parse worker output: %v", err)
	}
	if err := validateWorkerAgentOutput(withFindingField, parsed); err == nil {
		t.Fatalf("expected worker delivery fields to be rejected")
	}

	withBrainDecisionField := `{"accepted":true,"data":{"summary":"bad","evidence":[{"title":"e","summary":"s"}],"complete":{"description":"worker must not decide completion"},"hypothesis_status":"validated"}}`
	parsed, err = parseWorkerAgentOutput(withBrainDecisionField)
	if err != nil {
		t.Fatalf("parse worker output with brain decision: %v", err)
	}
	if err := validateWorkerAgentOutput(withBrainDecisionField, parsed); err == nil {
		t.Fatalf("expected worker brain-decision fields to be rejected")
	}

	unsupportedIntent := workerAgentOutput{Accepted: true, Data: workerAgentData{
		Evidence:              []workerAgentEvidence{{Title: "observed", Summary: "ok"}},
		NextIntentSuggestions: []SecurityGraphIntentSuggestion{{Title: "external lookup", Objective: "external lookup", IntentType: "unknown_external_lookup"}},
	}}
	if err := validateWorkerAgentOutput(`{"accepted":true}`, unsupportedIntent); err == nil {
		t.Fatalf("expected unsupported next intent type to be rejected")
	}

	missingEvidenceDetail := workerAgentOutput{Accepted: true, Data: workerAgentData{
		Evidence: []workerAgentEvidence{{}},
	}}
	if err := validateWorkerAgentOutput(`{"accepted":true}`, missingEvidenceDetail); err == nil {
		t.Fatalf("expected empty evidence item to be rejected")
	}
}

func TestValidateWorkerAgentOutputRejectsPhaseBoundaryTextAndNoise(t *testing.T) {
	deliveryText := workerAgentOutput{Accepted: true, Data: workerAgentData{
		Summary:  "confirmed finding: goal complete",
		Evidence: []workerAgentEvidence{{Title: "HTTP observation", Summary: "response changed"}},
	}}
	if err := validateWorkerAgentOutput(`{"accepted":true}`, deliveryText); err == nil {
		t.Fatalf("expected delivery/brain decision text to be rejected")
	}

	externalLookupSuggestion := workerAgentOutput{Accepted: true, Data: workerAgentData{
		Evidence:              []workerAgentEvidence{{Title: "HTTP observation", Summary: "response changed"}},
		NextIntentSuggestions: []SecurityGraphIntentSuggestion{{Title: "CVE Search", Objective: "Search exploit-db for external PoC", IntentType: model.IntentBehaviorProbe}},
	}}
	if err := validateWorkerAgentOutput(`{"accepted":true}`, externalLookupSuggestion); err == nil {
		t.Fatalf("expected external lookup suggestion text to be rejected")
	}

	noisyFacts := make([]string, maxWorkerFacts+1)
	for i := range noisyFacts {
		noisyFacts[i] = "objective observation"
	}
	noisyOutput := workerAgentOutput{Accepted: true, Data: workerAgentData{
		Facts:    noisyFacts,
		Evidence: []workerAgentEvidence{{Title: "HTTP observation", Summary: "response changed"}},
	}}
	if err := validateWorkerAgentOutput(`{"accepted":true}`, noisyOutput); err == nil {
		t.Fatalf("expected noisy oversized worker packet to be rejected")
	}

	rawCanContainSourceText := workerAgentOutput{Accepted: true, Data: workerAgentData{
		Summary: "captured page text as observation",
		Evidence: []workerAgentEvidence{{
			Title:   "Raw response observation",
			Summary: "response body captured",
			Raw:     "This raw page mentions CVE Search in documentation, but worker is only preserving observed text.",
		}},
	}}
	if err := validateWorkerAgentOutput(`{"accepted":true}`, rawCanContainSourceText); err != nil {
		t.Fatalf("raw evidence text should be preservable when title/summary stay within phase boundary: %v", err)
	}
}

func TestPiContainerWorkerPromptUsesKaliRuntimeWithoutGateway(t *testing.T) {
	task := model.AISecurityTask{
		ID:        123,
		TaskType:  model.TaskTypePentest,
		Objective: "validate authorized object ownership behavior",
	}
	intent := model.AIIntent{
		ID:         456,
		TaskID:     task.ID,
		IntentType: model.IntentIDORProbe,
		Title:      "Validate cross-user object read",
		Objective:  "Compare user B reading user A object.",
	}
	worker := WorkerRuntimeSelection{
		Config:     model.AIModelConfig{ID: 9, Name: "pi-a", Model: "worker-model"},
		WorkerID:   "worker:9:pi-a",
		TaskTypes:  []string{"pentest"},
		MaxRunning: 2,
		Running:    1,
	}
	phaseContract := buildWorkerPhaseContract()
	path, err := writePiWorkerRuntimeSnapshot(t.TempDir(), task, intent, AgentContext{
		RecommendedNext: "stay on the current intent",
	}, worker, modelRuntimeOptions{WorkerTools: []string{"bash", "grep"}}, "pi_container_kali", phaseContract)
	if err != nil {
		t.Fatalf("write pi container snapshot: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pi container snapshot: %v", err)
	}
	var snapshot map[string]any
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("snapshot must be JSON: %v", err)
	}
	if snapshot["tool_gateway"] != nil {
		t.Fatalf("pi_container_kali snapshot must not expose controlled gateway: %+v", snapshot["tool_gateway"])
	}
	runtimeInfo, _ := snapshot["runtime"].(map[string]any)
	if runtimeInfo["driver"] != "pi_container_kali" {
		t.Fatalf("expected pi_container_kali runtime, got %+v", runtimeInfo)
	}
	if !strings.Contains(fmt.Sprint(runtimeInfo["turn_policy"]), fmt.Sprintf("at most %d tool calls", defaultPiWorkerMaxToolCalls)) {
		t.Fatalf("expected snapshot to carry bounded worker turn policy, got %+v", runtimeInfo)
	}
	prompt := buildPiContainerWorkerPrompt(task, intent, "/workspace/work/pi-workers/9/context/intent-456-context.json", phaseContract)
	for _, mustContain := range []string{
		"task-scoped Kali-capable worker container",
		"bash, and installed tools",
		"not limited to a fixed Rabbit gateway action list",
		fmt.Sprintf("Use at most %d tool calls before returning", defaultPiWorkerMaxToolCalls),
		"must include its own timeout of 60 seconds or less",
		"final assistant message must be exactly one compact raw JSON object",
		"artifact_path",
		"Do not create Findings",
		"Do not turn this into external CVE/PoC repository lookup",
	} {
		if !strings.Contains(prompt, mustContain) {
			t.Fatalf("expected prompt to contain %q", mustContain)
		}
	}
	if strings.Contains(prompt, "Controlled Tool Gateway") || strings.Contains(prompt, "rabbit-worker-tool") {
		t.Fatalf("pi_container_kali prompt should not use gateway language: %s", prompt)
	}
}

func TestPiWorkerTimeoutAndLeaseAreLongerThanGenericToolRun(t *testing.T) {
	orchestrator := NewAgentOrchestrator(config.Config{
		ToolTimeout:     180 * time.Second,
		PiWorkerTimeout: 360 * time.Second,
		WorkerLease:     120 * time.Second,
	}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if got := orchestrator.piWorkerTimeout(); got != 360*time.Second {
		t.Fatalf("expected configured pi worker timeout, got %s", got)
	}
	lease := orchestrator.intentClaimLease(&WorkerRuntimeSelection{WorkerID: "worker:1:pi"})
	if lease < 390*time.Second {
		t.Fatalf("expected worker claim lease to cover pi worker runtime plus buffer, got %s", lease)
	}
	nativeLease := orchestrator.intentClaimLease(nil)
	if nativeLease != 120*time.Second {
		t.Fatalf("expected native claim lease to keep configured value, got %s", nativeLease)
	}
}
