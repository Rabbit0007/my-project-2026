package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

func TestGraphSearchKernelRunsWithoutFindingContext(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9201)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "query_flow", "GET /search", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)

	summary := loop.BuildGraphSummary(ctx, task, 1, 10)
	if summary.CoverageState.UnresolvedHighPrioritySurfaces != 1 || !summary.GoalState.ShouldContinue {
		t.Fatalf("kernel should run from graph and coverage state without delivery services: %+v", summary.GoalState)
	}
}

func TestWorkerPromptDoesNotIncludeOpenFindings(t *testing.T) {
	task := model.AISecurityTask{ID: 9202, TaskType: model.TaskTypeCodeAudit, Objective: "coverage discovery"}
	ctx := AgentContext{
		GraphSummary: &GraphSummary{
			GoalState: GraphGoalSummary{GoalType: "scope_bounded_security_discovery", ShouldContinue: true},
			CoverageState: GraphCoverageState{
				UnresolvedHighPrioritySurfaces: 1,
				SurfaceCoverage:                []GraphSurfaceCoverage{{Entrypoint: "GET /admin/export", Status: model.CoverageStatusUnexplored, Priority: model.CoveragePriorityHigh}},
			},
		},
	}
	systemPrompt, userPrompt := buildPlannerPrompt(task, &model.AIIntent{IntentType: model.IntentInspectDataflow}, ctx)
	combined := strings.ToLower(systemPrompt + "\n" + userPrompt)
	if strings.Contains(combined, "openfinding") || strings.Contains(combined, "open finding") || strings.Contains(combined, "reportcontract") {
		t.Fatalf("worker planner prompt must not include delivery-layer finding/report context: %s", combined)
	}
	rawContext, _ := json.Marshal(ctx)
	if strings.Contains(strings.ToLower(string(rawContext)), "openfindings") {
		t.Fatalf("agent context must not expose OpenFindings to worker planning: %s", rawContext)
	}
	if !strings.Contains(combined, "verified capability is an output item, not a global stop condition") {
		t.Fatalf("planner prompt must state capability is not global stop condition: %s", combined)
	}
}

func TestFindingReportDoesNotDriveCoreExploration(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9203)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, NewFindingService(db), NewContractService(db, nil, nil), nil, nil, nil)
	createCoverageItem(t, db, task.ID, "admin_flow", "GET /admin/export", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	if err := db.Create(&model.AIFinding{TaskID: task.ID, VulnerabilityType: "delivery_only", Title: "Existing delivery item", AffectedTarget: "GET /search", AffectedComponent: "GET /search", CreatedAt: time.Now(), UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("create finding: %v", err)
	}

	if loop.ShouldFinalize(ctx, task, 6, 20, 0) {
		t.Fatal("finding/report delivery artifacts must not stop core exploration while coverage remains")
	}
	summary := loop.BuildGraphSummary(ctx, task, 6, 20)
	raw, _ := json.Marshal(summary)
	if strings.Contains(strings.ToLower(string(raw)), "existing delivery item") {
		t.Fatalf("GraphSummary must not use open findings as core planning input: %s", raw)
	}
}

func TestDeliveryLayerOnlyConsumesVerifiedCapability(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9204)
	blackboard := NewBlackboardService(db)
	loop := NewCairnLoop(db, blackboard, NewIntentService(db), nil, NewFindingService(db), NewContractService(db, blackboard, nil), nil, nil, nil).WithPromotionGate("legacy")
	ids := createStructuredGateEvidenceSet(t, db, task.ID)

	if _, err := loop.WriteCapability(ctx, task.ID, CapabilityDraft{CapabilityType: model.CapFileWrite, Target: "POST /upload", Strength: model.StrengthObserved, ProofSummary: string(mustJSON(completeDeliveryDetails("POST /upload", model.CapFileWrite, ids))), EvidenceIDs: ids, CanAdvanceGoal: true}, nil); err != nil {
		t.Fatalf("write observed capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote observed capability: %v", err)
	}
	assertFindingCount(t, db, task.ID, 1)
}

func TestVerifiedCapabilityDoesNotStopDiscoveryWhenSurfacesRemain(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9205)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, NewFindingService(db), nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "query_flow", "GET /user/search", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	createCoverageItem(t, db, task.ID, "admin_flow", "GET /admin/export", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	ids := createStructuredGateEvidenceSet(t, db, task.ID)
	if _, err := loop.WriteCapability(ctx, task.ID, CapabilityDraft{CapabilityType: model.CapSQLInjection, Target: "GET /user/search orderBy", Strength: model.StrengthVerified, ProofSummary: string(mustJSON(completeDeliveryDetails("GET /user/search", model.CapSQLInjection, ids))), EvidenceIDs: ids, CanAdvanceGoal: true}, nil); err != nil {
		t.Fatalf("write verified capability: %v", err)
	}

	summary := loop.BuildGraphSummary(ctx, task, 6, 20)
	if summary.CoverageState.UnresolvedHighPrioritySurfaces != 1 {
		t.Fatalf("expected one unresolved high-priority surface after first capability, got %+v", summary.CoverageState)
	}
	if loop.ShouldFinalize(ctx, task, 6, 20, 0) {
		t.Fatal("verified capability must not finalize while unresolved high-priority surface remains")
	}
}

func TestDiscoveryStopsWhenCoverageSufficientAndNoHighPriorityIntents(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9206)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "query_flow", "GET /search", model.CoveragePriorityHigh, model.CoverageStatusResolvedVerified)
	createCoverageItem(t, db, task.ID, "admin_flow", "GET /admin/export", model.CoveragePriorityHigh, model.CoverageStatusResolvedRefuted)

	if !loop.ShouldFinalize(ctx, task, 3, 20, 0) {
		t.Fatal("expected finalize when coverage is sufficient and no high-priority intents remain")
	}
}

func TestDiscoveryStopsWhenBudgetExhausted(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9207)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "query_flow", "GET /search", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	if !loop.ShouldFinalize(ctx, task, 10, 10, 0) {
		t.Fatal("budget exhaustion must stop discovery")
	}
}

func TestDiscoveryStopsOnCoveragePlateau(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9208)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	if !loop.ShouldFinalizeWithNoProgressLimit(ctx, task, 6, 20, 3, 3) {
		t.Fatal("expected plateau/no-progress stop without coverage or pending intents")
	}
}

func TestCoverageStateTracksResolvedVerifiedSurface(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9209)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "query_flow", "GET /user/search", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	ids := createStructuredGateEvidenceSet(t, db, task.ID)
	if _, err := loop.WriteCapability(ctx, task.ID, CapabilityDraft{CapabilityType: model.CapSQLInjection, Target: "GET /user/search", Strength: model.StrengthVerified, ProofSummary: string(mustJSON(completeDeliveryDetails("GET /user/search", model.CapSQLInjection, ids))), EvidenceIDs: ids, CanAdvanceGoal: true}, nil); err != nil {
		t.Fatalf("write verified capability: %v", err)
	}
	state := loop.BuildCoverageState(ctx, task, 2)
	if len(state.SurfaceCoverage) != 1 || state.SurfaceCoverage[0].Status != model.CoverageStatusResolvedVerified || state.VerifiedCapabilityCount != 1 {
		t.Fatalf("expected resolved verified surface, got %+v", state)
	}
}

func TestCoverageStateTracksBlockedAndInconclusiveSurface(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9210)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "object_access", "GET /documents/:id", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	createCoverageItem(t, db, task.ID, "external_request", "POST /import", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	blocked := model.AINegativeFact{TaskID: task.ID, Title: "auth_required for GET /documents/:id", TestedPath: "GET /documents/:id", Reason: "auth_required missing credentials", CreatedAt: time.Now()}
	if err := db.Create(&blocked).Error; err != nil {
		t.Fatalf("create blocked negative fact: %v", err)
	}
	if err := loop.ApplyCoverageResolutionFromNegativeFact(ctx, blocked); err != nil {
		t.Fatalf("apply blocked coverage: %v", err)
	}
	inconclusive := model.AINegativeFact{TaskID: task.ID, Title: "POST /import inconclusive", TestedPath: "POST /import", Reason: "inconclusive evidence after timeout", CreatedAt: time.Now()}
	if err := db.Create(&inconclusive).Error; err != nil {
		t.Fatalf("create inconclusive negative fact: %v", err)
	}
	if err := loop.ApplyCoverageResolutionFromNegativeFact(ctx, inconclusive); err != nil {
		t.Fatalf("apply inconclusive coverage: %v", err)
	}
	state := loop.BuildCoverageState(ctx, task, 2)
	if state.BlockedPathCount != 1 || state.InconclusivePathCount != 1 {
		t.Fatalf("expected blocked and inconclusive coverage, got %+v", state)
	}
}

func TestGraphSummaryIncludesCoverageState(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9211)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "admin_flow", "GET /admin/export", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	summary := loop.BuildGraphSummary(ctx, task, 1, 10)
	if summary.GoalState.GoalType != "scope_bounded_security_discovery" || summary.CoverageState.ScopeSummary.SurfaceCount != 1 {
		t.Fatalf("expected coverage-oriented GraphSummary, got %+v", summary)
	}
}

func TestReasonPrioritizesUnexploredHighPrioritySurface(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9212)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "admin_flow", "GET /admin/export", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	loop.CreateIntentFromSuggestion(ctx, task.ID, IntentSuggestion{IntentType: model.IntentInspectAuthBoundary, Objective: "Inspect GET /admin/export authorization boundary", Priority: 50})
	var intent model.AIIntent
	if err := db.Where("task_id = ?", task.ID).First(&intent).Error; err != nil {
		t.Fatalf("load intent: %v", err)
	}
	var constraints map[string]any
	_ = json.Unmarshal(intent.ConstraintsJSON, &constraints)
	if intent.PriorityScore <= 0.5 || !stringSliceAnyContains(constraints["priority_reasons"], "covers_unexplored_surface") {
		t.Fatalf("expected coverage priority boost, score=%f constraints=%+v", intent.PriorityScore, constraints)
	}
}

func TestIntentPriorityPenalizesNegativeFactCoveredPath(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9213)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	nf := model.AINegativeFact{TaskID: task.ID, Title: "GET /download refuted", TestedPath: "GET /download", Reason: "server-side lookup blocks path", SimilarPatternKey: "download", CreatedAt: time.Now()}
	if err := db.Create(&nf).Error; err != nil {
		t.Fatalf("create negative fact: %v", err)
	}
	loop.CreateIntentFromSuggestion(ctx, task.ID, IntentSuggestion{IntentType: model.IntentInspectDataflow, Objective: "Recheck GET /download dataflow", Priority: 70})
	var count int64
	db.Model(&model.AIIntent{}).Where("task_id = ?", task.ID).Count(&count)
	if count != 0 {
		t.Fatalf("negative fact covered path should suppress duplicate intent, count=%d", count)
	}
}

func TestNegativeFactMarksSurfaceRefutedOrBlocked(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9214)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "download_flow", "GET /files/download", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	nf := model.AINegativeFact{TaskID: task.ID, Title: "GET /files/download path_refuted", TestedPath: "GET /files/download", Reason: "source not controlled", CreatedAt: time.Now()}
	if err := db.Create(&nf).Error; err != nil {
		t.Fatalf("create negative fact: %v", err)
	}
	if err := loop.ApplyCoverageResolutionFromNegativeFact(ctx, nf); err != nil {
		t.Fatalf("apply negative fact: %v", err)
	}
	state := loop.BuildCoverageState(ctx, task, 1)
	if state.RefutedPathCount != 1 || state.SurfaceCoverage[0].Status != model.CoverageStatusResolvedRefuted {
		t.Fatalf("expected refuted surface, got %+v", state)
	}
}

func TestNegativeFactSuppressesDuplicateIntent(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9215)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	intentID := uint(7)
	if err := db.Create(&model.AINegativeFact{TaskID: task.ID, Title: "Upload extension guard effective", TestedPath: "POST /upload", Reason: "guard effective", CreatedFromIntentID: &intentID, CreatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("create negative fact: %v", err)
	}
	if !loop.intentMatchesNegativeFact(ctx, task.ID, "Recheck POST /upload extension guard") {
		t.Fatal("expected duplicate intent to be covered by NegativeFact")
	}
}

func TestGraphSearchContinuesAfterFirstVerifiedCapability(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9216)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, NewFindingService(db), NewContractService(db, NewBlackboardService(db), nil), nil, nil, nil)
	createCoverageItem(t, db, task.ID, "query_flow", "GET /user/search", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	createCoverageItem(t, db, task.ID, "admin_flow", "GET /admin/export", model.CoveragePriorityHigh, model.CoverageStatusUnexplored)
	ids := createStructuredGateEvidenceSet(t, db, task.ID)
	if _, err := loop.WriteCapability(ctx, task.ID, CapabilityDraft{CapabilityType: model.CapSQLInjection, Target: "GET /user/search", Strength: model.StrengthVerified, ProofSummary: string(mustJSON(completeDeliveryDetails("GET /user/search", model.CapSQLInjection, ids))), EvidenceIDs: ids, CanAdvanceGoal: true}, nil); err != nil {
		t.Fatalf("write capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote finding: %v", err)
	}
	assertFindingCount(t, db, task.ID, 1)
	loop.CreateIntentFromSuggestion(ctx, task.ID, IntentSuggestion{IntentType: model.IntentInspectGuard, Objective: "Inspect GET /admin/export authorization guard", Priority: 60})
	if loop.ShouldFinalize(ctx, task, 7, 20, 0) {
		t.Fatal("loop must continue after first finding while admin export surface is unresolved")
	}
}

func TestGraphSearchFixtureProducesMultipleSurfaceCoverage(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9217)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	if err := loop.ApplyCoverageUpdate(ctx, task.ID, CoverageUpdate{SurfaceType: "query_flow", Entrypoint: "GET /user/search", Status: model.CoverageStatusUnexplored, Priority: model.CoveragePriorityHigh}); err != nil {
		t.Fatalf("apply search coverage: %v", err)
	}
	if err := loop.ApplyCoverageUpdate(ctx, task.ID, CoverageUpdate{SurfaceType: "admin_flow", Entrypoint: "GET /admin/export", Status: model.CoverageStatusUnexplored, Priority: model.CoveragePriorityHigh}); err != nil {
		t.Fatalf("apply export coverage: %v", err)
	}
	state := loop.BuildCoverageState(ctx, task, 1)
	if state.ScopeSummary.SurfaceCount != 2 || state.UnresolvedHighPrioritySurfaces != 2 {
		t.Fatalf("expected multiple fixture surfaces, got %+v", state)
	}
}

func TestGraphSearchFixtureDoesNotFinalizeAfterSingleFinding(t *testing.T) {
	TestGraphSearchContinuesAfterFirstVerifiedCapability(t)
}

func TestGraphSearchStopsOnlyAfterCoverageOrBudgetOrPlateau(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	task := createCoverageTask(t, db, 9218)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	createCoverageItem(t, db, task.ID, "query_flow", "GET /search", model.CoveragePriorityHigh, model.CoverageStatusResolvedVerified)
	if !loop.ShouldFinalize(ctx, task, 2, 20, 0) {
		t.Fatal("expected stop after coverage sufficiency")
	}
	if !loop.ShouldFinalize(ctx, task, 20, 20, 0) {
		t.Fatal("expected stop after budget exhaustion")
	}
}

func createCoverageTask(t *testing.T, db *gorm.DB, taskID uint) model.AISecurityTask {
	t.Helper()
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "coverage task", TaskType: model.TaskTypeCodeAudit, Status: model.TaskStatusRunning, Objective: "Discover evidence-backed security impact paths across authorized scope.", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	return task
}

func createCoverageItem(t *testing.T, db *gorm.DB, taskID uint, category string, target string, priority string, status string) model.AICoverageItem {
	t.Helper()
	item := model.AICoverageItem{TaskID: taskID, Category: category, Name: target, TargetRef: target, RiskHint: priority, Status: status, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&item).Error; err != nil {
		t.Fatalf("create coverage item: %v", err)
	}
	return item
}

func createStructuredGateEvidenceSet(t *testing.T, db *gorm.DB, taskID uint) []uint {
	t.Helper()
	ids := []uint{}
	for _, relation := range []string{
		"entrypoint_or_exposure",
		"impact_sink_or_security_effect",
		"reachability_or_trigger_path",
		"guard_or_control_analysis",
		"reproduction_or_recheck_path",
		"validation_or_observed_signal",
	} {
		item := createGateEvidence(t, db, taskID, relation)
		ids = append(ids, item.ID)
	}
	return ids
}

func assertFindingCount(t *testing.T, db *gorm.DB, taskID uint, expected int64) {
	t.Helper()
	var count int64
	db.Model(&model.AIFinding{}).Where("task_id = ?", taskID).Count(&count)
	if count != expected {
		t.Fatalf("expected %d findings, got %d", expected, count)
	}
}

func stringSliceAnyContains(value any, expected string) bool {
	switch typed := value.(type) {
	case []string:
		for _, item := range typed {
			if item == expected {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if item == expected {
				return true
			}
		}
	}
	return false
}
