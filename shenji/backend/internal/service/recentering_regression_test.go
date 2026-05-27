package service

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"shenji/backend/internal/config"
	"shenji/backend/internal/database"
	"shenji/backend/internal/model"
	"shenji/backend/internal/runner"
	"shenji/backend/internal/safety"
	"shenji/backend/internal/storage"
	"shenji/backend/internal/tools"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newRegressionTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := gorm.Open(sqlite.Open("file:"+dbName+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate test db: %v", err)
	}
	return db
}

func removedIntentTypes() []string {
	return []string{
		"proof" + "_packet" + "_search",
		"proof" + "_packet" + "_normalize",
		"safe" + "_packet" + "_validate",
	}
}

func TestFingerprintEvidenceDoesNotTriggerExternalRepositorySideProbe(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7001)

	expander := NewHypothesisLifecycleService(db, NewBlackboardService(db))
	created, err := expander.ExpandFromEvidence(ctx, taskID, []model.AIEvidence{{
		ID:           1,
		TaskID:       taskID,
		EvidenceType: "fingerprint",
		Title:        "Strong fingerprint for Apache Struts",
		Summary:      "confirmed technology fingerprint with version context",
		RelationType: "fingerprint",
	}}, ExpansionBudget{MaxGeneratedPerRound: 3})
	if err != nil {
		t.Fatalf("expand from fingerprint evidence: %v", err)
	}
	if len(created) != 0 {
		t.Fatalf("fingerprint evidence should not create external repository side-probe hypotheses, got %+v", created)
	}

	var intents []model.AIIntent
	if err := db.Where("task_id = ?", taskID).Find(&intents).Error; err != nil {
		t.Fatalf("load intents: %v", err)
	}
	assertNoRemovedRepositoryIntents(t, intents)
}

func TestDynamicIntentExpanderCreatesOnlyMainLoopValidationIntent(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7002)

	expander := NewHypothesisLifecycleService(db, NewBlackboardService(db))
	created, err := expander.ExpandFromEvidence(ctx, taskID, []model.AIEvidence{{
		ID:           2,
		TaskID:       taskID,
		EvidenceType: "code_snippet",
		Title:        "SQL template sink",
		Summary:      "matched dynamic_sql and database_query_sink",
		FilePath:     "app/user.go",
		RelationType: "code_sink",
	}}, ExpansionBudget{MaxGeneratedPerRound: 3})
	if err != nil {
		t.Fatalf("expand from SQL evidence: %v", err)
	}
	if len(created) == 0 {
		t.Fatal("expected normal hypothesis-driven expansion to create a hypothesis")
	}

	var intents []model.AIIntent
	if err := db.Where("task_id = ?", taskID).Find(&intents).Error; err != nil {
		t.Fatalf("load intents: %v", err)
	}
	if len(intents) == 0 {
		t.Fatal("expected normal validation intent to be created")
	}
	assertNoRemovedRepositoryIntents(t, intents)
}

func TestNextPendingSkipsRemovedExternalRepositoryIntentRows(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7003)
	now := time.Now().UTC()
	removed := removedIntentTypes()
	rows := []model.AIIntent{
		{TaskID: taskID, IntentType: removed[0], Title: "legacy removed row", PriorityScore: 1.0, Status: model.IntentStatusPending, CreatedAt: now},
		{TaskID: taskID, IntentType: removed[1], Title: "legacy removed row", PriorityScore: 0.99, Status: model.IntentStatusPending, CreatedAt: now.Add(time.Second)},
		{TaskID: taskID, IntentType: removed[2], Title: "legacy removed row", PriorityScore: 0.98, Status: model.IntentStatusPending, CreatedAt: now.Add(2 * time.Second)},
		{TaskID: taskID, IntentType: model.IntentBehaviorProbe, Title: "normal validation", PriorityScore: 0.1, Status: model.IntentStatusPending, CreatedAt: now.Add(3 * time.Second)},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed intents: %v", err)
	}

	next, err := NewIntentService(db).NextPending(ctx, taskID)
	if err != nil {
		t.Fatalf("next pending: %v", err)
	}
	if next == nil {
		t.Fatal("expected normal pending intent")
	}
	if next.IntentType != model.IntentBehaviorProbe {
		t.Fatalf("expected normal intent, got %s", next.IntentType)
	}
}

func TestBehaviorProbeIntentDispatchesToRunner(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7031)
	target := "http://example.test"
	task := model.AISecurityTask{
		ID:                taskID,
		WorkspaceID:       1,
		Name:              "behavior probe regression",
		TaskType:          model.TaskTypePentest,
		Status:            model.TaskStatusRunning,
		Objective:         "Validate an authorized behavioral difference.",
		ScopeJSON:         mustJSON(map[string]any{"targets": []string{target}, "level": 1}),
		AuthorizationJSON: mustJSON(map[string]any{"level": 1}),
		SafePolicyJSON:    mustJSON(safety.DefaultPolicy([]string{target}, 1)),
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := db.Create(&model.AITaskTarget{TaskID: taskID, TargetType: "url", Value: target, ScopeStatus: "in_scope", CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatalf("create target: %v", err)
	}
	intent := model.AIIntent{
		TaskID:     taskID,
		IntentType: model.IntentBehaviorProbe,
		Title:      "Probe variant behavior",
		Objective:  "Compare baseline and variant response behavior.",
		ConstraintsJSON: mustJSON(map[string]any{
			"baselineUrl": target + "/baseline",
			"variantUrl":  target + "/variant",
			"method":      "GET",
			"hypothesis":  "variant response should differ",
		}),
		PriorityScore: 0.9,
		Status:        model.IntentStatusRunning,
		CreatedBy:     "test",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := db.Create(&intent).Error; err != nil {
		t.Fatalf("create intent: %v", err)
	}
	loop := model.AIAgentLoop{TaskID: taskID, Status: "running", Goal: task.Objective, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}
	if err := db.Create(&loop).Error; err != nil {
		t.Fatalf("create loop: %v", err)
	}

	registry := tools.NewRegistry()
	registry.Register(regressionFakeTool{name: "behavior_probe"})
	store, err := storage.NewLocalStore(t.TempDir(), "")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	blackboard := NewBlackboardService(db)
	models := NewModelRuntimeService(db, time.Second)
	orchestrator := NewAgentOrchestrator(
		config.Config{MaxToolRuns: 4},
		db,
		registry,
		NewIntentService(db),
		NewToolRunService(db, store, registry, NewEvidenceService(db, store)),
		blackboard,
		NewFindingService(db),
		NewContractService(db, blackboard, models),
		NewContextBuilder(db),
		NewBlackboardCompactor(db, blackboard),
		NewReportService(db, store),
		models,
	)

	if err := orchestrator.runSingleIteration(ctx, &task, &loop, &intent, 1, nil); err != nil {
		t.Fatalf("behavior_probe should dispatch to a registered runner instead of failing unsupported: %v", err)
	}
	var run model.AIToolRun
	if err := db.Where("task_id = ? AND intent_id = ? AND tool_name = ?", taskID, intent.ID, "behavior_probe").First(&run).Error; err != nil {
		t.Fatalf("expected persisted behavior_probe ToolRun: %v", err)
	}
	if run.Status != model.ToolRunStatusSuccess {
		t.Fatalf("expected successful behavior_probe ToolRun, got %s", run.Status)
	}
	var reloaded model.AIIntent
	if err := db.First(&reloaded, intent.ID).Error; err != nil {
		t.Fatalf("reload intent: %v", err)
	}
	if reloaded.Status != model.IntentStatusCompleted {
		t.Fatalf("expected behavior_probe intent completed, got %s", reloaded.Status)
	}
}

func TestSQLiLabSurfaceLinksBecomeInjectableCandidates(t *testing.T) {
	raw := `{"baseUrl":"http://target/","links":[{"url":"http://target/Less-1","source":"html"},{"url":"http://target/Less-2","source":"html"},{"url":"http://target/Less-3","source":"html"},{"url":"http://target/index.html_files/freemind2html.js","source":"html"}],"forms":[],"parameters":[]}`
	candidates := httpSurfaceValidationCandidates("http://target/", &tools.ToolResult{Stdout: raw}, validationProbeSQLi)
	found := false
	less3FirstVariant := -1
	firstUnion := -1
	for _, candidate := range candidates {
		if strings.Contains(candidate.URL, "/Less-1/?id=1") && candidate.Param == "id" && strings.Contains(strings.ToLower(candidate.Payload), "union select") {
			found = true
		}
		if strings.Contains(candidate.URL, "/Less-3/?id=1") && candidate.Payload == "1'" && less3FirstVariant == -1 {
			less3FirstVariant = len(candidates)
		}
		if strings.Contains(strings.ToLower(candidate.Payload), "union select") && firstUnion == -1 {
			firstUnion = len(candidates)
		}
	}
	if !found {
		t.Fatalf("expected Less-1 image-map link to produce SQLi id candidates, got %+v", candidates)
	}
	for i, candidate := range candidates {
		if strings.Contains(candidate.URL, "/Less-3/?id=1") && candidate.Payload == "1'" {
			less3FirstVariant = i
		}
		if strings.Contains(strings.ToLower(candidate.Payload), "union select") {
			firstUnion = i
			break
		}
	}
	if less3FirstVariant == -1 || firstUnion == -1 || less3FirstVariant > firstUnion {
		t.Fatalf("expected SQLi candidates to cover discovered routes breadth-first before deeper variants, got %+v", candidates)
	}
}

func TestHTTPSurfaceEvidenceExpandsIntoEndpointSpecificIntents(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7037)
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	surface := map[string]any{
		"baseUrl": "http://target/",
		"links": []map[string]any{
			{"url": "http://target/Less-1", "source": "html"},
			{"url": "http://target/Less-2", "source": "html"},
			{"url": "http://target/Less-3", "source": "html"},
		},
		"forms":      []any{},
		"parameters": []any{},
	}
	evidence := model.AIEvidence{
		ID:               301,
		TaskID:           taskID,
		EvidenceType:     "tool_output",
		Title:            "HTTP input surface discovery",
		Summary:          "HTTP surface discovery found endpoint-level inputs",
		Target:           "http://target/",
		ResponseSnapshot: model.JSONValue(surface),
		Hash:             "surface-301",
		CreatedAt:        time.Now(),
	}
	created, err := lifecycle.ExpandFromEvidence(ctx, taskID, []model.AIEvidence{evidence}, ExpansionBudget{MaxGeneratedPerRound: 4})
	if err != nil {
		t.Fatalf("expand from HTTP surface evidence: %v", err)
	}
	if len(created) != 3 {
		t.Fatalf("expected one hypothesis per discovered endpoint clue, got %d: %+v", len(created), created)
	}
	var intents []model.AIIntent
	if err := db.Where("task_id = ? AND intent_type = ?", taskID, model.IntentSQLiProbe).Order("id asc").Find(&intents).Error; err != nil {
		t.Fatalf("load SQLi intents: %v", err)
	}
	if len(intents) != 3 {
		t.Fatalf("expected endpoint-specific validation intents, got %d", len(intents))
	}
	seenBranches := map[string]bool{}
	for _, intent := range intents {
		var constraints map[string]any
		if err := json.Unmarshal(intent.ConstraintsJSON, &constraints); err != nil {
			t.Fatalf("decode constraints: %v", err)
		}
		branch, _ := constraints["branch_key"].(string)
		seenBranches[branch] = true
		rawCandidates, _ := constraints["validation_candidates"].([]any)
		if branch == "" || len(rawCandidates) == 0 {
			t.Fatalf("intent should carry endpoint-local validation candidates: %+v", constraints)
		}
		if hid := intent.HypothesisID(); hid == nil {
			t.Fatalf("endpoint-specific intent should preserve hypothesis lineage: %+v", intent)
		}
	}
	for _, expected := range []string{
		"GET|http://target/Less-1/?id=|query|id",
		"GET|http://target/Less-2/?id=|query|id",
		"GET|http://target/Less-3/?id=|query|id",
	} {
		if !seenBranches[expected] {
			t.Fatalf("missing endpoint branch %s in %+v", expected, seenBranches)
		}
	}
	next, err := NewIntentService(db).NextPending(ctx, taskID)
	if err != nil {
		t.Fatalf("next pending endpoint intent: %v", err)
	}
	if next == nil || next.IntentType != model.IntentSQLiProbe {
		t.Fatalf("expected endpoint validation intent eligible for worker claim, got %+v", next)
	}
}

func TestHTTPSurfaceFrontierReplenishesWithoutGraphExplosion(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7039)
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	links := []map[string]any{}
	for i := 1; i <= 8; i++ {
		links = append(links, map[string]any{"url": "http://target/Less-" + strconv.Itoa(i), "source": "html"})
	}
	evidence := model.AIEvidence{
		TaskID:           taskID,
		EvidenceType:     "tool_output",
		Title:            "HTTP input surface discovery",
		Summary:          "HTTP surface discovery found many endpoint-level inputs",
		Target:           "http://target/",
		ResponseSnapshot: model.JSONValue(map[string]any{"baseUrl": "http://target/", "links": links, "forms": []any{}, "parameters": []any{}}),
		Hash:             "surface-frontier",
		CreatedAt:        time.Now(),
	}
	if err := db.Create(&evidence).Error; err != nil {
		t.Fatalf("create surface evidence: %v", err)
	}
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, blackboard, NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	created, err := orchestrator.replenishHTTPInputSurfaceFrontier(ctx, taskID, lifecycle)
	if err != nil {
		t.Fatalf("initial frontier replenish: %v", err)
	}
	if len(created) != httpInputSurfaceFrontierWindow {
		t.Fatalf("expected initial frontier window of %d, got %d", httpInputSurfaceFrontierWindow, len(created))
	}
	pending, err := pendingHTTPInputSurfaceValidationCount(ctx, db, taskID)
	if err != nil || pending != httpInputSurfaceFrontierWindow {
		t.Fatalf("expected bounded pending frontier, pending=%d err=%v", pending, err)
	}
	var first model.AIIntent
	if err := db.Where("task_id = ? AND status = ?", taskID, model.IntentStatusPending).Order("id asc").First(&first).Error; err != nil {
		t.Fatalf("load first frontier intent: %v", err)
	}
	first.Status = model.IntentStatusCompleted
	if err := db.Save(&first).Error; err != nil {
		t.Fatalf("complete first frontier intent: %v", err)
	}
	created, err = orchestrator.replenishHTTPInputSurfaceFrontier(ctx, taskID, lifecycle)
	if err != nil {
		t.Fatalf("second frontier replenish: %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("expected exactly one replenished branch after one completion, got %d", len(created))
	}
	pending, err = pendingHTTPInputSurfaceValidationCount(ctx, db, taskID)
	if err != nil || pending != httpInputSurfaceFrontierWindow {
		t.Fatalf("expected frontier window to remain bounded, pending=%d err=%v", pending, err)
	}
	var intents []model.AIIntent
	if err := db.Where("task_id = ?", taskID).Find(&intents).Error; err != nil {
		t.Fatalf("load frontier intents: %v", err)
	}
	total := 0
	for _, intent := range intents {
		var constraints map[string]any
		if json.Unmarshal(intent.ConstraintsJSON, &constraints) == nil && constraints["branch_kind"] == "http_input_surface" {
			total++
		}
	}
	if total != httpInputSurfaceFrontierWindow+1 {
		t.Fatalf("expected one completed plus bounded pending frontier, total=%d", total)
	}
}

func TestCairnLoopDoesNotFinalizeWithPendingActionableIntent(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7040)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)
	task := model.AISecurityTask{ID: taskID}
	capability := model.AICapability{
		TaskID:         taskID,
		CapabilityType: model.CapSQLInjection,
		Target:         "http://target/Less-1/?id=",
		Strength:       model.StrengthVerified,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := db.Create(&capability).Error; err != nil {
		t.Fatalf("create capability: %v", err)
	}
	pending := model.AIIntent{
		TaskID:     taskID,
		IntentType: model.IntentSQLiProbe,
		Title:      "Validate remaining endpoint",
		Objective:  "Collect evidence for a remaining surface branch.",
		Status:     model.IntentStatusPending,
		CreatedBy:  "test",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := db.Create(&pending).Error; err != nil {
		t.Fatalf("create pending intent: %v", err)
	}
	if loop.ShouldFinalize(ctx, task, 8, 30, 0) {
		t.Fatal("must not finalize while evidence-capable runtime intents are still pending")
	}
	if err := db.Model(&model.AIIntent{}).Where("id = ?", pending.ID).Update("status", model.IntentStatusCompleted).Error; err != nil {
		t.Fatalf("complete pending intent: %v", err)
	}
	if !loop.ShouldFinalize(ctx, task, 8, 30, 0) {
		t.Fatal("expected finalize once verified capabilities exist and no actionable intents remain")
	}
}

func TestNoObservableDiffCreatesUnverifiedRiskInsteadOfCapability(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7033)
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	h, intent := createRegressionHypothesisIntent(t, ctx, lifecycle, taskID, "SQLi marker produced no diff")
	intent.IntentType = model.IntentSQLiProbe
	intent.WithValidationMetadata(model.ValidationIntentMetadata{
		HypothesisID:       &h.ID,
		ExpectedCapability: model.CapSQLInjection,
	})
	if err := db.Save(&intent).Error; err != nil {
		t.Fatalf("save SQLi intent: %v", err)
	}
	evidence := model.AIEvidence{
		ID:           99,
		TaskID:       taskID,
		EvidenceType: "response_diff",
		Title:        "HTTP response diff evidence",
		Summary:      "no observable diff detected",
		RelationType: "poc_result",
	}
	outcomes := []ToolRunOutcome{{
		ToolRun:  model.AIToolRun{TaskID: taskID, ToolName: "response_diff", Status: model.ToolRunStatusSuccess, InputJSON: mustJSON(map[string]any{"validationUrl": "http://target/?id=marker"})},
		Evidence: []model.AIEvidence{evidence},
		Result:   &tools.ToolResult{Status: "success", Summary: "no observable diff detected", Stdout: "summary: no observable diff detected"},
	}}
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, blackboard, NewFindingService(db), NewContractService(db, blackboard, nil), NewContextBuilder(db), NewBlackboardCompactor(db, blackboard), nil, nil)
	supporting, failed, reason := orchestrator.supportingEvidenceForIntent(ctx, &intent, []model.AIEvidence{evidence}, outcomes)
	if len(supporting) != 0 || !failed || !strings.Contains(reason, model.UnverifiedReasonMethodNotObservable) {
		t.Fatalf("expected no-diff SQLi validation to fail, supporting=%v failed=%v reason=%q", supporting, failed, reason)
	}
	if err := lifecycle.ResolveIntentResult(ctx, taskID, intent, HypothesisResolution{IntentID: intent.ID, EvidenceIDs: []uint{evidence.ID}, ValidationFailed: true, Reason: reason}); err != nil {
		t.Fatalf("resolve failed validation: %v", err)
	}
	var negativeCount, riskCount, capabilityCount int64
	db.Model(&model.AINegativeFact{}).Where("task_id = ? AND hypothesis_id = ?", taskID, h.ID).Count(&negativeCount)
	db.Model(&model.AIUnverifiedRisk{}).Where("task_id = ? AND hypothesis_id = ?", taskID, h.ID).Count(&riskCount)
	db.Model(&model.AICapability{}).Where("task_id = ?", taskID).Count(&capabilityCount)
	if riskCount != 1 || negativeCount != 0 || capabilityCount != 0 {
		t.Fatalf("expected UnverifiedRisk and no capability/negative fact, risk=%d negative=%d capability=%d", riskCount, negativeCount, capabilityCount)
	}
}

func TestPlannerNextIntentSuggestionsEnterGraphAsHypothesisBackedIntents(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7041)
	task := model.AISecurityTask{ID: taskID, TaskType: model.TaskTypePentest, Objective: "collect authorized behavioral facts", Status: model.TaskStatusRunning, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	h, parent := createRegressionHypothesisIntent(t, ctx, lifecycle, taskID, "current method needs alternate context")
	parent.Status = model.IntentStatusRunning
	parent.IntentType = model.IntentBehaviorProbe
	parent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &h.ID, ExpectedCapability: model.CapInternalServiceAccess})
	if err := db.Save(&parent).Error; err != nil {
		t.Fatalf("save parent intent: %v", err)
	}
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, blackboard, NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	created := orchestrator.ingestPlannerNextIntents(ctx, &task, &parent, IterationPlan{NextIntents: []SecurityGraphIntentSuggestion{{
		Title:            "Compare alternate ownership path",
		Objective:        "Use response_diff to compare whether the alternate route enforces object ownership.",
		IntentType:       model.IntentIDORProbe,
		RequiredEvidence: []string{"response_diff"},
	}}}, []uint{99})
	if created != 1 {
		t.Fatalf("expected one planner follow-up intent, got %d", created)
	}
	var intent model.AIIntent
	if err := db.Where("task_id = ? AND created_by = ?", taskID, "model-planner").First(&intent).Error; err != nil {
		t.Fatalf("load planner intent: %v", err)
	}
	if intent.Status != model.IntentStatusPending || intent.IntentType != model.IntentIDORProbe || intent.HypothesisID() == nil {
		t.Fatalf("expected pending hypothesis-backed IDOR intent, got %+v", intent)
	}
	next, err := NewIntentService(db).NextPending(ctx, taskID)
	if err != nil {
		t.Fatalf("next pending: %v", err)
	}
	if next == nil || next.ID != intent.ID {
		t.Fatalf("expected planner intent to be eligible for NextPending, got %+v", next)
	}
	var hypotheses int64
	db.Model(&model.AIHypothesisNode{}).Where("task_id = ? AND id = ?", taskID, *intent.HypothesisID()).Count(&hypotheses)
	if hypotheses != 1 {
		t.Fatalf("expected planner suggestion to create a backing hypothesis")
	}
}

func TestGraphReasonerComposesMultipleFactNodesIntoHypothesisBackedIntent(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(70412)
	task := model.AISecurityTask{ID: taskID, TaskType: model.TaskTypePentest, Objective: "探索授权范围内的认证状态空间", Status: model.TaskStatusRunning, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	blackboard := NewBlackboardService(db)
	loginNode, err := blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeSurfaceFact,
		Title:           "Login endpoint discovered",
		Summary:         "GET /admin/login returns a login form in authorized scope.",
		Content:         map[string]any{"path": "/admin/login"},
		DedupSeed:       "login-endpoint",
		ImportanceScore: 0.86,
		SourceType:      "test",
		SourceID:        "login",
	})
	if err != nil {
		t.Fatalf("create login node: %v", err)
	}
	credentialNode, err := blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeCredentialFact,
		Title:           "Credential candidate observed",
		Summary:         "A credential candidate was observed in task evidence; secret material is intentionally not repeated in the title.",
		Content:         map[string]any{"credential_ref": "evidence:credential-candidate"},
		DedupSeed:       "credential-candidate",
		ImportanceScore: 0.84,
		SourceType:      "test",
		SourceID:        "credential",
	})
	if err != nil {
		t.Fatalf("create credential node: %v", err)
	}
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, blackboard, NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	orchestrator.applyGraphDecision(ctx, &task, &model.AIIntent{ID: 9001, TaskID: taskID, IntentType: "reason", Title: "Graph reason", Objective: "compose facts"}, SecurityGraphDecision{
		NextIntents: []SecurityGraphIntentSuggestion{{
			Title:            "Validate credential against discovered login endpoint",
			Objective:        "Perform one authorized non-destructive authentication check and record request/response evidence.",
			IntentType:       model.IntentAuthProbe,
			SourceNodeIDs:    []uint{loginNode.ID, credentialNode.ID},
			Hypothesis:       "The credential candidate may authenticate to the discovered login endpoint.",
			SuccessCriteria:  "A session indicator or authenticated response is observed.",
			FailureCriteria:  "The endpoint rejects the credential without session state.",
			AllowedTools:     []string{"http_request", "response_diff"},
			RequiredEvidence: []string{"http_exchange", "session_indicator", "negative_auth_result"},
			RiskLevel:        "low",
			Priority:         87,
		}},
	}, nil)
	var intent model.AIIntent
	if err := db.Where("task_id = ? AND created_by = ?", taskID, "graph-reasoner").First(&intent).Error; err != nil {
		t.Fatalf("expected graph reasoner intent: %v", err)
	}
	if intent.IntentType != model.IntentAuthProbe || intent.Status != model.IntentStatusPending || intent.HypothesisID() == nil {
		t.Fatalf("expected pending hypothesis-backed auth_probe, got %+v", intent)
	}
	values := map[string]any{}
	if err := json.Unmarshal(intent.ConstraintsJSON, &values); err != nil {
		t.Fatalf("unmarshal constraints: %v", err)
	}
	sourceIDs := normalizeUintListAny(values["source_node_ids"])
	if len(sourceIDs) != 2 || sourceIDs[0] != loginNode.ID || sourceIDs[1] != credentialNode.ID {
		t.Fatalf("expected both source nodes in constraints, got %+v", values)
	}
	if values["source"] != "graph_reasoner" || values["hypothesis"] == "" {
		t.Fatalf("expected graph reasoner source and hypothesis in constraints, got %+v", values)
	}
	next, err := NewIntentService(db).NextPending(ctx, taskID)
	if err != nil {
		t.Fatalf("next pending: %v", err)
	}
	if next == nil || next.ID != intent.ID {
		t.Fatalf("expected composed intent to be NextPending-eligible, got %+v", next)
	}
	var findingCount int64
	db.Model(&model.AIFinding{}).Where("task_id = ?", taskID).Count(&findingCount)
	if findingCount != 0 {
		t.Fatalf("fact composition must not create findings, got %d", findingCount)
	}
	var sourceEdges int64
	db.Model(&model.AIBlackboardEdge{}).
		Where("task_id = ? AND edge_type = ? AND from_id IN ?", taskID, model.EdgeSpawnedIntent, []uint{loginNode.ID, credentialNode.ID}).
		Count(&sourceEdges)
	if sourceEdges < 2 {
		t.Fatalf("expected both source nodes to point at the composed intent, got %d edges", sourceEdges)
	}
}

func TestGraphReasonerSkipsIntentWithoutSourceNodes(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(70413)
	task := model.AISecurityTask{ID: taskID, TaskType: model.TaskTypePentest, Objective: "探索授权范围内的状态空间", Status: model.TaskStatusRunning, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	blackboard := NewBlackboardService(db)
	reasonNode, err := blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeIntent,
		Title:           "Graph reason",
		Summary:         "Reason pass",
		Content:         map[string]any{"reason": true},
		DedupSeed:       "reason-node",
		ImportanceScore: 0.7,
		SourceType:      "test",
		SourceID:        "reason",
	})
	if err != nil {
		t.Fatalf("create reason node: %v", err)
	}
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, blackboard, NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	orchestrator.applyGraphDecision(ctx, &task, &model.AIIntent{ID: 9002, TaskID: taskID, ParentNodeID: &reasonNode.ID, IntentType: "reason", Title: "Graph reason", Objective: "compose facts"}, SecurityGraphDecision{
		NextIntents: []SecurityGraphIntentSuggestion{{
			Title:      "Source-less idea",
			Objective:  "This should not become an intent because it cites no concrete fact node.",
			IntentType: model.IntentBehaviorProbe,
		}},
	}, nil)
	var count int64
	db.Model(&model.AIIntent{}).Where("task_id = ? AND created_by = ?", taskID, "graph-reasoner").Count(&count)
	if count != 0 {
		t.Fatalf("source-less graph reasoner output must not create intents, got %d", count)
	}
}

func TestPlannerNextIntentLimitIsConfigurable(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(70411)
	task := model.AISecurityTask{ID: taskID, TaskType: model.TaskTypePentest, Objective: "collect bounded facts", Status: model.TaskStatusRunning, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	h, parent := createRegressionHypothesisIntent(t, ctx, lifecycle, taskID, "current path needs bounded fanout")
	parent.Status = model.IntentStatusRunning
	parent.IntentType = model.IntentBehaviorProbe
	parent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &h.ID, ExpectedCapability: model.CapInternalServiceAccess})
	if err := db.Save(&parent).Error; err != nil {
		t.Fatalf("save parent intent: %v", err)
	}
	orchestrator := NewAgentOrchestrator(config.Config{PlannerNextIntentLimit: 2}, db, tools.NewRegistry(), NewIntentService(db), nil, blackboard, NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	plan := IterationPlan{NextIntents: []SecurityGraphIntentSuggestion{
		{Title: "Compare route A", Objective: "Validate route A state behavior.", IntentType: model.IntentBehaviorProbe},
		{Title: "Compare route B", Objective: "Validate route B state behavior.", IntentType: model.IntentBehaviorProbe},
		{Title: "Compare route C", Objective: "Validate route C state behavior.", IntentType: model.IntentBehaviorProbe},
		{Title: "Compare route D", Objective: "Validate route D state behavior.", IntentType: model.IntentBehaviorProbe},
	}}
	created := orchestrator.ingestPlannerNextIntents(ctx, &task, &parent, plan, []uint{99})
	if created != 2 {
		t.Fatalf("expected planner limit to create exactly two intents, got %d", created)
	}
	var count int64
	db.Model(&model.AIIntent{}).Where("task_id = ? AND created_by = ?", taskID, "model-planner").Count(&count)
	if count != 2 {
		t.Fatalf("expected two persisted planner intents, got %d", count)
	}
}

func TestCairnCadenceUsesConfigurableBudgets(t *testing.T) {
	orchestrator := NewAgentOrchestrator(config.Config{ReasonNoOpPassBudget: 2, NoProgressFinalizeRounds: 8, PlannerNextIntentLimit: 4}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if orchestrator.reasonNoOpPassBudget() != 2 {
		t.Fatalf("expected configured reason budget, got %d", orchestrator.reasonNoOpPassBudget())
	}
	if orchestrator.noProgressFinalizeRounds() != 8 {
		t.Fatalf("expected configured no-progress limit, got %d", orchestrator.noProgressFinalizeRounds())
	}
	if orchestrator.plannerNextIntentLimit() != 4 {
		t.Fatalf("expected configured planner intent limit, got %d", orchestrator.plannerNextIntentLimit())
	}
	defaults := NewAgentOrchestrator(config.Config{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if defaults.reasonNoOpPassBudget() != defaultReasonNoOpPassBudget ||
		defaults.noProgressFinalizeRounds() != defaultNoProgressFinalizeRounds ||
		defaults.plannerNextIntentLimit() != defaultPlannerNextIntentLimit {
		t.Fatalf("expected default cadence budgets, got reason=%d noProgress=%d planner=%d",
			defaults.reasonNoOpPassBudget(), defaults.noProgressFinalizeRounds(), defaults.plannerNextIntentLimit())
	}
}

func TestValidationWritesTestedPathFact(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7042)
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	_, intent := createRegressionHypothesisIntent(t, ctx, lifecycle, taskID, "tested behavior path")
	intent.Status = model.IntentStatusRunning
	if err := db.Save(&intent).Error; err != nil {
		t.Fatalf("save intent: %v", err)
	}
	_, _ = blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:     taskID,
		NodeType:   model.NodeIntent,
		Title:      intent.Title,
		Summary:    intent.Objective,
		Content:    intent,
		DedupSeed:  "intent-node-tested-path",
		SourceType: "test",
		SourceID:   strconv.Itoa(int(intent.ID)),
	})
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, blackboard, NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	orchestrator.writeTestedPathFact(ctx, taskID, &intent, []ToolRunOutcome{{
		ToolRun: model.AIToolRun{TaskID: taskID, ToolName: "response_diff", Status: model.ToolRunStatusSuccess},
	}}, []uint{123}, true, model.UnverifiedReasonMethodNotObservable+": current method did not resolve the branch")
	var count int64
	db.Model(&model.AIBlackboardNode{}).Where("task_id = ? AND node_type = ?", taskID, model.NodeTestedPath).Count(&count)
	if count != 1 {
		t.Fatalf("expected tested_path fact node, got %d", count)
	}
}

func TestRepairedWorkerOutputIsObservationOnlyNotHypothesisValidation(t *testing.T) {
	orchestrator := NewAgentOrchestrator(config.Config{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	hypothesisID := uint(77)
	intent := model.AIIntent{
		ID:         88,
		TaskID:     1,
		IntentType: model.IntentBehaviorProbe,
		Title:      "Validate behavior",
		Status:     model.IntentStatusRunning,
		CreatedBy:  "test",
	}
	intent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &hypothesisID, ExpectedCapability: model.CapInternalServiceAccess})
	evidence := []model.AIEvidence{{ID: 909, TaskID: 1, EvidenceType: "worker_observation", Title: "Observation only", Summary: "unstructured worker note"}}
	outcomes := []ToolRunOutcome{{
		ToolRun:  model.AIToolRun{ID: 12, TaskID: 1, RunnerType: "worker_agent", ToolName: "pi_worker", Status: model.ToolRunStatusSuccess},
		Result:   &tools.ToolResult{Status: "success", Metadata: map[string]any{"workerOutputRepaired": true}},
		Evidence: evidence,
	}}
	supporting, validationFailed, reason := orchestrator.supportingEvidenceForIntent(context.Background(), &intent, evidence, outcomes)
	if !validationFailed {
		t.Fatalf("expected repaired worker output to remain observation-only")
	}
	if len(supporting) != 1 || supporting[0] != evidence[0].ID {
		t.Fatalf("expected observation evidence to be retained for context, got %+v", supporting)
	}
	if !strings.Contains(reason, model.UnverifiedReasonMethodNotObservable) {
		t.Fatalf("expected inconclusive method reason, got %q", reason)
	}
}

func TestSQLiProofSignalSupportsCapability(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7034)
	h := uint(1)
	intent := model.AIIntent{TaskID: taskID, IntentType: model.IntentSQLiProbe, Title: "SQLi", Status: model.IntentStatusRunning}
	intent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &h, ExpectedCapability: model.CapSQLInjection})
	evidence := model.AIEvidence{ID: 100, TaskID: taskID, EvidenceType: "http_exchange", Summary: "SQL error response"}
	outcome := ToolRunOutcome{
		ToolRun:  model.AIToolRun{TaskID: taskID, ToolName: "http_request", Status: model.ToolRunStatusSuccess, InputJSON: mustJSON(map[string]any{"url": "http://target/Less-1/?id=1%27"})},
		Evidence: []model.AIEvidence{evidence},
		Result:   &tools.ToolResult{Status: "success", Summary: "GET returned SQL error", Stdout: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"},
	}
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, NewBlackboardService(db), NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	supporting, failed, reason := orchestrator.supportingEvidenceForIntent(ctx, &intent, []model.AIEvidence{evidence}, []ToolRunOutcome{outcome})
	if failed || len(supporting) != 1 || supporting[0] != evidence.ID {
		t.Fatalf("expected SQLi proof signal to support capability, supporting=%v failed=%v reason=%q", supporting, failed, reason)
	}
}

func TestSQLiCapabilityEvidenceGroupsByEndpoint(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7036)
	req1 := mustJSON(map[string]any{"method": "GET", "url": "http://target/Less-1/?id=1%27"})
	req2 := mustJSON(map[string]any{"method": "GET", "url": "http://target/Less-1/?id=-1%27"})
	req3 := mustJSON(map[string]any{"method": "GET", "url": "http://target/Less-2/?id=1%27"})
	items := []model.AIEvidence{
		{ID: 201, TaskID: taskID, EvidenceType: "http_exchange", Title: "one", Summary: "SQL syntax", RequestSnapshot: req1, Hash: "h201", CreatedAt: time.Now()},
		{ID: 202, TaskID: taskID, EvidenceType: "response_diff", Title: "two", Summary: "SQL syntax", RequestSnapshot: req2, Hash: "h202", CreatedAt: time.Now()},
		{ID: 203, TaskID: taskID, EvidenceType: "http_exchange", Title: "three", Summary: "SQL syntax", RequestSnapshot: req3, Hash: "h203", CreatedAt: time.Now()},
	}
	if err := db.Create(&items).Error; err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, NewBlackboardService(db), NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	groups := orchestrator.capabilityEvidenceGroups(ctx, model.CapSQLInjection, []uint{201, 202, 203}, &model.AIIntent{Title: "SQLi"})
	if len(groups) != 2 {
		t.Fatalf("expected SQLi evidence split by endpoint, got %+v", groups)
	}
	if groups[0].Target != "http://target/Less-1/?id=" || groups[1].Target != "http://target/Less-2/?id=" {
		t.Fatalf("unexpected endpoint grouping: %+v", groups)
	}
	if len(groups[0].EvidenceIDs) != 2 || len(groups[1].EvidenceIDs) != 1 {
		t.Fatalf("unexpected evidence grouping counts: %+v", groups)
	}
}

func TestSQLiCapabilityExpandsIntoStateValidationIntent(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7038)
	lifecycle := NewHypothesisLifecycleService(db, NewBlackboardService(db))
	capability := model.AICapability{
		ID:             401,
		TaskID:         taskID,
		CapabilityType: model.CapSQLInjection,
		Target:         "http://target/Less-1/?id=",
		Strength:       model.StrengthVerified,
		ProofSummary:   "endpoint-local SQL injection behavior was validated by response evidence",
		EvidenceRefs:   mustJSON([]uint{201}),
		CanAdvanceGoal: true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := db.Create(&capability).Error; err != nil {
		t.Fatalf("create capability: %v", err)
	}
	created, err := lifecycle.ExpandFromCapability(ctx, capability, ExpansionBudget{MaxGeneratedPerRound: 2})
	if err != nil {
		t.Fatalf("expand SQLi capability: %v", err)
	}
	if len(created) != 1 || created[0].ExpectedCapability != model.CapDatabaseRead {
		t.Fatalf("expected SQLi capability to create state-expansion hypothesis, got %+v", created)
	}
	var intent model.AIIntent
	if err := db.Where("task_id = ? AND intent_type = ?", taskID, model.IntentCapabilityExpand).First(&intent).Error; err != nil {
		t.Fatalf("expected capability expansion intent: %v", err)
	}
	if intent.ExpectedCapability() != model.CapDatabaseRead {
		t.Fatalf("expected database-state validation intent, got %s", intent.ExpectedCapability())
	}
	if strings.Contains(strings.ToLower(intent.Objective), "cve") || strings.Contains(strings.ToLower(intent.Objective), "poc") {
		t.Fatalf("capability expansion must stay state-space driven, got objective %q", intent.Objective)
	}
}

func TestRedirectOnlySQLiDiffDoesNotSupportCapability(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7035)
	h := uint(1)
	intent := model.AIIntent{TaskID: taskID, IntentType: model.IntentSQLiProbe, Title: "SQLi", Status: model.IntentStatusRunning}
	intent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &h, ExpectedCapability: model.CapSQLInjection})
	evidence := model.AIEvidence{ID: 101, TaskID: taskID, EvidenceType: "response_diff", Summary: "body length changed 328 -> 357"}
	outcome := ToolRunOutcome{
		ToolRun:  model.AIToolRun{TaskID: taskID, ToolName: "response_diff", Status: model.ToolRunStatusSuccess, InputJSON: mustJSON(map[string]any{"validationUrl": "http://target/Less-1?id=-1%27+UNION+SELECT+1%2C2%2C3--"})},
		Evidence: []model.AIEvidence{evidence},
		Result: &tools.ToolResult{Status: "success", Summary: "body length changed 328 -> 357", Stdout: "301 Moved Permanently redirect page only", Metadata: map[string]any{
			"statusChanged":    false,
			"bodyChanged":      true,
			"reflectedMarker":  false,
			"baselineStatus":   301,
			"validationStatus": 301,
		}},
	}
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, NewBlackboardService(db), NewFindingService(db), nil, NewContextBuilder(db), nil, nil, nil)
	supporting, failed, reason := orchestrator.supportingEvidenceForIntent(ctx, &intent, []model.AIEvidence{evidence}, []ToolRunOutcome{outcome})
	if len(supporting) != 0 || !failed || !strings.Contains(reason, model.UnverifiedReasonMethodNotObservable) {
		t.Fatalf("expected redirect-only diff to remain method-level unresolved, supporting=%v failed=%v reason=%q", supporting, failed, reason)
	}
}

func TestTaskCreationStillBootstrapsGoalHypothesisAndIntent(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	workspace := runner.NewWorkspaceManager(t.TempDir())
	tasks := NewTaskService(config.Config{}, db, workspace, NewBlackboardService(db))

	task, err := tasks.Create(ctx, CreateTaskInput{
		Name:               "regression task",
		TaskType:           model.TaskTypeCodeAudit,
		Objective:          "audit authorized source",
		AuthorizationLevel: 1,
		IsTestTask:         true,
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	var goals int64
	if err := db.Model(&model.AIGoalProfile{}).Where("task_id = ?", task.ID).Count(&goals).Error; err != nil {
		t.Fatalf("count goal profiles: %v", err)
	}
	var hypotheses int64
	if err := db.Model(&model.AIHypothesisNode{}).Where("task_id = ?", task.ID).Count(&hypotheses).Error; err != nil {
		t.Fatalf("count hypotheses: %v", err)
	}
	next, err := NewIntentService(db).NextPending(ctx, task.ID)
	if err != nil {
		t.Fatalf("next pending bootstrap intent: %v", err)
	}
	if goals != 1 || hypotheses == 0 || next == nil {
		t.Fatalf("expected goal profile, initial hypothesis, and pending intent; goals=%d hypotheses=%d next=%+v", goals, hypotheses, next)
	}
}

func TestEvidenceLifecycleStillProducesCapabilityNegativeFactAndUnverifiedRisk(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7004)
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)

	validatedHypothesis, validatedIntent := createRegressionHypothesisIntent(t, ctx, lifecycle, taskID, "validated branch")
	if err := lifecycle.ResolveIntentResult(ctx, taskID, validatedIntent, HypothesisResolution{
		IntentID:    validatedIntent.ID,
		EvidenceIDs: []uint{11},
	}); err != nil {
		t.Fatalf("validate hypothesis from evidence: %v", err)
	}
	loop := NewCairnLoop(db, blackboard, nil, nil, nil, nil, nil, nil, nil)
	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapSQLInjection,
		Target:         validatedHypothesis.TargetEntity,
		Strength:       model.StrengthVerified,
		ProofSummary:   "validated by normal evidence lifecycle",
		EvidenceIDs:    []uint{11},
		CanAdvanceGoal: true,
	}, &validatedIntent.ID); err != nil {
		t.Fatalf("write capability: %v", err)
	}

	refutedHypothesis, refutedIntent := createRegressionHypothesisIntent(t, ctx, lifecycle, taskID, "refuted branch")
	if err := lifecycle.ResolveIntentResult(ctx, taskID, refutedIntent, HypothesisResolution{
		IntentID: refutedIntent.ID,
		Reason:   "normal validation produced no supporting evidence",
	}); err != nil {
		t.Fatalf("refute hypothesis from empty evidence: %v", err)
	}

	blockedHypothesis, blockedIntent := createRegressionHypothesisIntent(t, ctx, lifecycle, taskID, "blocked branch")
	if err := lifecycle.ResolveIntentResult(ctx, taskID, blockedIntent, HypothesisResolution{
		IntentID:    blockedIntent.ID,
		ToolBlocked: true,
		Reason:      "authorized non-destructive safety gate blocked validation",
	}); err != nil {
		t.Fatalf("mark hypothesis inconclusive: %v", err)
	}

	var capCount, negativeCount, riskCount int64
	db.Model(&model.AICapability{}).Where("task_id = ? AND capability_type = ?", taskID, model.CapSQLInjection).Count(&capCount)
	db.Model(&model.AINegativeFact{}).Where("hypothesis_id = ?", refutedHypothesis.ID).Count(&negativeCount)
	db.Model(&model.AIUnverifiedRisk{}).Where("hypothesis_id = ?", blockedHypothesis.ID).Count(&riskCount)
	if capCount != 1 || negativeCount != 1 || riskCount != 1 {
		t.Fatalf("expected capability/negative/risk lifecycle rows, got capability=%d negative=%d risk=%d", capCount, negativeCount, riskCount)
	}
}

func TestFindingIsDeliveryArtifactOnlyAfterValidatedCapability(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7005)
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)

	_, err := lifecycle.ExpandFromEvidence(ctx, taskID, []model.AIEvidence{{
		ID:           21,
		TaskID:       taskID,
		EvidenceType: "code_snippet",
		Title:        "Pattern hit",
		Summary:      "matched input_source and database_query_sink",
		FilePath:     "app/user.go",
		RelationType: "code_observation",
	}}, ExpansionBudget{MaxGeneratedPerRound: 3})
	if err != nil {
		t.Fatalf("expand pattern hit: %v", err)
	}
	assertNoFindings(t, db, taskID, "pattern hit must not directly create a finding")

	_, err = lifecycle.ExpandFromEvidence(ctx, taskID, []model.AIEvidence{{
		ID:           22,
		TaskID:       taskID,
		EvidenceType: "fingerprint",
		Title:        "Fingerprint signal",
		Summary:      "identified framework and version",
		RelationType: "fingerprint",
	}}, ExpansionBudget{MaxGeneratedPerRound: 3})
	if err != nil {
		t.Fatalf("expand fingerprint: %v", err)
	}
	assertNoFindings(t, db, taskID, "fingerprint must not directly create a finding")

	task := model.AISecurityTask{ID: taskID, Objective: "state-space regression"}
	loop := NewCairnLoop(db, blackboard, NewIntentService(db), nil, NewFindingService(db), NewContractService(db, blackboard, nil), nil, nil, nil)
	h, intent := createRegressionHypothesisIntent(t, ctx, lifecycle, taskID, "validated delivery path")
	if err := lifecycle.ResolveIntentResult(ctx, taskID, intent, HypothesisResolution{IntentID: intent.ID, EvidenceIDs: []uint{31}}); err != nil {
		t.Fatalf("resolve validated hypothesis: %v", err)
	}
	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapSQLInjection,
		Target:         h.TargetEntity,
		Strength:       model.StrengthVerified,
		ProofSummary:   "validated path produced evidence",
		EvidenceIDs:    []uint{31},
		CanAdvanceGoal: true,
	}, &intent.ID); err != nil {
		t.Fatalf("write capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote capability to finding: %v", err)
	}
	assertNoFindings(t, db, taskID, "generic capability proof summary must not be promoted to a delivery finding")

	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapInternalServiceAccess,
		Target:         "bootstrap origin collection",
		Strength:       model.StrengthVerified,
		ProofSummary:   string(mustJSON(completeDeliveryDetails("bootstrap origin collection", model.CapInternalServiceAccess, []uint{32}))),
		EvidenceIDs:    []uint{32},
		CanAdvanceGoal: true,
	}, &intent.ID); err != nil {
		t.Fatalf("write bootstrap capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote bootstrap capability: %v", err)
	}
	assertNoFindings(t, db, taskID, "bootstrap capability must remain graph state, not a report finding")

	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapSQLInjection,
		Target:         "complete delivery path",
		Strength:       model.StrengthVerified,
		ProofSummary:   string(mustJSON(completeDeliveryDetails("complete delivery path", model.CapSQLInjection, []uint{33}))),
		EvidenceIDs:    []uint{33},
		CanAdvanceGoal: true,
	}, &intent.ID); err != nil {
		t.Fatalf("write delivery-ready capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote delivery-ready capability to finding: %v", err)
	}
	var finding model.AIFinding
	if err := db.Where("task_id = ? AND vulnerability_type = ? AND affected_target = ?", taskID, model.CapSQLInjection, "complete delivery path").First(&finding).Error; err != nil {
		t.Fatalf("expected evidence-backed finding: %v", err)
	}
	if finding.ValidationStatus != model.ValidationDynamicallyValidated || finding.ContractStatus != model.ContractStatusPassed {
		t.Fatalf("expected validated contract-passed finding status, got validation=%s contract=%s", finding.ValidationStatus, finding.ContractStatus)
	}
}

func TestRuntimeCapabilityProofSummaryPromotesToFinding(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7040)
	task := model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "runtime proof", TaskType: "pentest", Status: model.TaskStatusRunning, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := db.Create(&model.AITaskTarget{TaskID: taskID, TargetType: "url", Value: "http://target/", ScopeStatus: "in_scope", CreatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("create target: %v", err)
	}
	hypothesisID := uint(1)
	intent := model.AIIntent{ID: 77, TaskID: taskID, IntentType: model.IntentSQLiProbe, Title: "SQLi validation", Objective: "Validate SQLi", Status: model.IntentStatusRunning, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	intent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &hypothesisID, ExpectedCapability: model.CapSQLInjection})
	if err := db.Create(&intent).Error; err != nil {
		t.Fatalf("create intent: %v", err)
	}
	req := mustJSON(map[string]any{"method": "GET", "url": "http://target/Less-1/?id=1%27"})
	resp := mustJSON(map[string]any{"status": 200, "body": "You have an error in your SQL syntax"})
	evidence := model.AIEvidence{
		ID:               7101,
		TaskID:           taskID,
		EvidenceType:     "response_diff",
		Title:            "HTTP response diff evidence",
		Summary:          "SQL syntax error observed",
		Target:           "http://target/Less-1/?id=1%27",
		RequestSnapshot:  req,
		ResponseSnapshot: resp,
		RelationType:     "poc_result",
		Hash:             "runtime-proof-hash",
		CreatedAt:        time.Now(),
	}
	if err := db.Create(&evidence).Error; err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	blackboard := NewBlackboardService(db)
	loop := NewCairnLoop(db, blackboard, NewIntentService(db), nil, NewFindingService(db), NewContractService(db, blackboard, nil), nil, nil, nil)
	orchestrator := NewAgentOrchestrator(config.Config{}, db, tools.NewRegistry(), NewIntentService(db), nil, blackboard, NewFindingService(db), NewContractService(db, blackboard, nil), NewContextBuilder(db), nil, nil, nil)
	proof := orchestrator.deliveryProofSummaryForCapability(ctx, task, intent, model.CapSQLInjection, []uint{evidence.ID})
	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapSQLInjection,
		Target:         orchestrator.capabilityTargetFromEvidence(ctx, []uint{evidence.ID}, &intent),
		Strength:       model.StrengthVerified,
		ProofSummary:   proof,
		EvidenceIDs:    []uint{evidence.ID},
		CanAdvanceGoal: true,
	}, &intent.ID); err != nil {
		t.Fatalf("write runtime capability: %v", err)
	}
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote runtime capability: %v", err)
	}
	var finding model.AIFinding
	if err := db.Where("task_id = ? AND vulnerability_type = ?", taskID, model.CapSQLInjection).First(&finding).Error; err != nil {
		t.Fatalf("expected runtime capability finding: %v", err)
	}
	if finding.ContractStatus != model.ContractStatusPassed {
		t.Fatalf("expected contract-passed runtime finding, got %s", finding.ContractStatus)
	}
}

func TestReportHidesContractIncompleteFindingsFromDeliveryBody(t *testing.T) {
	ctx := context.Background()
	taskID := uint(7010)
	incomplete := model.AIFinding{
		ID:                1,
		TaskID:            taskID,
		Title:             "Incomplete internal capability",
		VulnerabilityType: model.CapInternalServiceAccess,
		AffectedTarget:    "bootstrap origin collection",
		Severity:          "medium",
		Status:            model.FindingStatusContractIncomplete,
		ValidationStatus:  model.ValidationContractIncomplete,
		ContractStatus:    model.ContractStatusIncomplete,
		RichDetails:       mustJSON(map[string]any{"entrypoint": "bootstrap origin collection"}),
	}
	snapshot := reportSnapshot{
		Task: model.AISecurityTask{
			ID:                taskID,
			Name:              "delivery report",
			TaskType:          model.TaskTypePentest,
			Status:            model.TaskStatusCompleted,
			ScopeJSON:         mustJSON(map[string]any{"targets": []string{"https://example.test"}}),
			AuthorizationJSON: mustJSON(map[string]any{"level": 1}),
		},
		Findings: []model.AIFinding{incomplete},
		ContractChecks: []model.AIContractCheckResult{{
			FindingID:       incomplete.ID,
			TaskID:          taskID,
			ContractType:    "generic_security_finding",
			Status:          model.ContractStatusIncomplete,
			DowngradeReason: "Finding remains incomplete because required delivery evidence is missing",
			CheckedAt:       time.Now().UTC(),
		}},
	}

	view := buildReportView(ctx, snapshot, ReportNarrative{}, nil)
	if len(view.Findings) != 0 {
		t.Fatalf("contract-incomplete findings must not enter delivery body: %+v", view.Findings)
	}
	markdown := renderMarkdownReport(view)
	if strings.Contains(markdown, incomplete.Title) || strings.Contains(markdown, "未形成可交付证据") || strings.Contains(markdown, "Finding remains incomplete") {
		t.Fatalf("report leaked incomplete finding details:\n%s", markdown)
	}
}

func TestReportUsesDeliveryTemplateWithProofAndPackets(t *testing.T) {
	taskID := uint(7011)
	details := completeDeliveryDetails("GET /erp/system/user", model.CapSQLInjection, []uint{1})
	details["vulnerability_description"] = "user.js list 函数将用户可控参数拼接进 SQL 查询。"
	details["proof_endpoint"] = "/erp/system/user"
	details["proof_payload"] = "userName=' OR '1'='1"
	details["response_packet"] = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"code\":200,\"rows\":[]}"
	view := reportView{
		Task: model.AISecurityTask{
			ID:                taskID,
			Name:              "SQL 注入验证",
			TaskType:          model.TaskTypeCodeAudit,
			Status:            model.TaskStatusCompleted,
			ScopeJSON:         mustJSON(map[string]any{"targets": []string{"repo.zip"}}),
			AuthorizationJSON: mustJSON(map[string]any{"level": 1}),
		},
		ExecutiveFacts: []string{"任务类型：code_audit"},
		Findings: []reportFindingView{{
			ID:                1,
			Title:             "user.js list SQL注入漏洞",
			VulnerabilityType: model.CapSQLInjection,
			Severity:          "high",
			AffectedTarget:    "/erp/system/user",
			Status:            model.FindingStatusDynamicallyValidated,
			ValidationStatus:  model.ValidationDynamicallyValidated,
			ContractStatus:    model.ContractStatusPassed,
			Narrative:         "SQL 注入已由代码证据和验证材料支撑。",
			Remediation:       "使用参数化查询并关闭调试模式。",
			RetestSteps:       "重复发送验证请求，确认响应不再返回异常数据。",
			Details:           details,
			HTTPPackets:       buildHTTPPackets(details, nil),
		}},
	}

	markdown := renderMarkdownReport(view)
	for _, required := range []string{"**漏洞名称**", "**漏洞等级**", "#### 漏洞证明", "详细数据包", "请求包", "响应包", "#### 修复建议"} {
		if !strings.Contains(markdown, required) {
			t.Fatalf("report missing required delivery section %q:\n%s", required, markdown)
		}
	}
	if strings.Contains(markdown, "Contract 检查摘要") || strings.Contains(markdown, "未形成可交付证据") {
		t.Fatalf("report should not expose internal contract noise or placeholders:\n%s", markdown)
	}
}

func TestContractDowngradesIncompleteFindingWithoutConfirmingIt(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7006)
	finding, err := NewFindingService(db).CreateCandidate(ctx, taskID, "Incomplete delivery artifact", "candidate", "/target", "component", "medium", map[string]any{
		"entrypoint": "/target",
	}, []uint{44})
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	finding.ValidationStatus = model.ValidationDynamicallyValidated
	if err := db.Save(&finding).Error; err != nil {
		t.Fatalf("mark candidate dynamic before contract: %v", err)
	}

	check, err := NewContractService(db, NewBlackboardService(db), nil).CheckFinding(ctx, &finding)
	if err != nil {
		t.Fatalf("contract check: %v", err)
	}
	if check.Status != model.ContractStatusIncomplete {
		t.Fatalf("expected incomplete contract, got %s", check.Status)
	}
	if finding.Status == model.FindingStatusDynamicallyValidated {
		t.Fatal("contract incomplete must downgrade instead of force-confirming finding")
	}
}

func TestLogicVulnerabilityStateExplorationSmoke(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7007)
	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	loop := NewCairnLoop(db, blackboard, NewIntentService(db), nil, NewFindingService(db), NewContractService(db, blackboard, nil), nil, nil, nil)

	h, err := lifecycle.FormHypothesis(ctx, HypothesisDraft{
		TaskID:                taskID,
		HypothesisType:        model.HypothesisTypeIDORCandidate,
		Title:                 "User B may access User A object",
		Description:           "Validate object ownership by comparing two authorized sessions against the same object.",
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: []string{"observation:user-a-object"},
		TargetEntity:          "/objects/123",
		ExpectedCapability:    model.CapCrossUserObjectAccess,
	})
	if err != nil {
		t.Fatalf("form logic hypothesis: %v", err)
	}
	intent, err := lifecycle.CreateValidationIntent(ctx, h, model.IntentIDORProbe, "multi_session_object_ownership_validation", 0.91)
	if err != nil {
		t.Fatalf("create logic validation intent: %v", err)
	}
	evidence := model.AIEvidence{
		TaskID:       taskID,
		EvidenceType: "response_diff",
		Title:        "User B accessed User A object",
		Summary:      "baseline denied for unauthenticated request; User B received 200 with User A object marker",
		Target:       "/objects/123",
		RelationType: "object_ownership_diff",
		CreatedAt:    time.Now().UTC(),
	}
	if err := db.Create(&evidence).Error; err != nil {
		t.Fatalf("create response diff evidence: %v", err)
	}
	if err := lifecycle.ResolveIntentResult(ctx, taskID, intent, HypothesisResolution{IntentID: intent.ID, EvidenceIDs: []uint{evidence.ID}}); err != nil {
		t.Fatalf("resolve logic hypothesis: %v", err)
	}
	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapCrossUserObjectAccess,
		Target:         "/objects/123",
		Strength:       model.StrengthVerified,
		ProofSummary:   "multi-session response diff showed cross-user object access",
		EvidenceIDs:    []uint{evidence.ID},
		CanAdvanceGoal: true,
	}, &intent.ID); err != nil {
		t.Fatalf("write logic capability: %v", err)
	}

	var capCount, nextIntentCount int64
	db.Model(&model.AICapability{}).Where("task_id = ? AND capability_type = ?", taskID, model.CapCrossUserObjectAccess).Count(&capCount)
	db.Model(&model.AIIntent{}).Where("task_id = ? AND status = ? AND id <> ?", taskID, model.IntentStatusPending, intent.ID).Count(&nextIntentCount)
	if capCount != 1 || nextIntentCount == 0 {
		t.Fatalf("expected logic capability and follow-up state-space intent, got cap=%d next=%d", capCount, nextIntentCount)
	}
}

func TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(7008)
	target := "https://example.test/owner-check/objects/123"
	policy := safety.DefaultPolicy([]string{"https://example.test"}, 1)
	task := model.AISecurityTask{
		ID:                taskID,
		Name:              "runtime proof task",
		TaskType:          model.TaskTypePentest,
		Objective:         "prove Fact to Intent to Explore to Fact loop",
		ScopeJSON:         mustJSON(map[string]any{"targets": []string{"https://example.test"}, "level": 1}),
		AuthorizationJSON: mustJSON(map[string]any{"level": 1}),
		SafePolicyJSON:    mustJSON(policy),
		Status:            model.TaskStatusRunning,
		CreatedAt:         time.Now().UTC(),
	}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}

	blackboard := NewBlackboardService(db)
	lifecycle := NewHypothesisLifecycleService(db, blackboard)
	h, err := lifecycle.FormHypothesis(ctx, HypothesisDraft{
		TaskID:                taskID,
		HypothesisType:        model.HypothesisTypeIDORCandidate,
		Title:                 "Object owner check may be bypassed",
		Description:           "Validate owner check behavior with a response difference produced by the runner.",
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: []string{"fact:authorized-object"},
		TargetEntity:          target,
		ExpectedCapability:    model.CapCrossUserObjectAccess,
	})
	if err != nil {
		t.Fatalf("form hypothesis: %v", err)
	}
	intent, err := lifecycle.CreateValidationIntent(ctx, h, model.IntentIDORProbe, "runtime_response_diff_validation", 0.93)
	if err != nil {
		t.Fatalf("create validation intent: %v", err)
	}

	registry := tools.NewRegistry()
	registry.Register(tools.ResponseDiffTool{})
	store, err := storage.NewLocalStore(t.TempDir(), "")
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}
	toolRuns := NewToolRunService(db, store, registry, NewEvidenceService(db, store))
	outcome, err := toolRuns.Execute(ctx, ToolRunRequest{
		Task:      task,
		IntentID:  &intent.ID,
		ToolName:  "response_diff",
		ImageName: "runner-http-validation",
		Input: map[string]any{
			"target":           target,
			"marker":           "owner check",
			"baselineUrl":      target,
			"validationUrl":    target + "?as=user-b",
			"baselineStatus":   403,
			"validationStatus": 200,
			"baselineBody":     "forbidden",
			"validationBody":   "owner check bypassed for user A object",
		},
	})
	if err != nil {
		t.Fatalf("execute response_diff toolrun: %v", err)
	}
	if outcome.ToolRun.ID == 0 || outcome.ToolRun.Status != model.ToolRunStatusSuccess {
		t.Fatalf("expected successful persisted ToolRun, got %+v", outcome.ToolRun)
	}
	if len(outcome.Evidence) != 1 || outcome.Evidence[0].Hash == "" || outcome.Evidence[0].RawRef == "" {
		t.Fatalf("expected persisted evidence with hash/raw ref, got %+v", outcome.Evidence)
	}

	evidence := outcome.Evidence[0]
	evidenceNode, err := blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeEvidence,
		Title:           evidence.Title,
		Summary:         evidence.Summary,
		Content:         evidence,
		DedupSeed:       "runtime-proof-evidence",
		ImportanceScore: 0.9,
		SourceType:      "tool",
		SourceID:        "response_diff",
		EvidenceRefs:    []uint{evidence.ID},
	})
	if err != nil || evidenceNode.ID == 0 {
		t.Fatalf("write evidence node: node=%+v err=%v", evidenceNode, err)
	}
	created, err := lifecycle.ExpandFromEvidence(ctx, taskID, outcome.Evidence, ExpansionBudget{MaxGeneratedPerRound: 2})
	if err != nil {
		t.Fatalf("expand from real evidence: %v", err)
	}
	if len(created) == 0 {
		t.Fatal("expected response_diff evidence to generate at least one follow-up hypothesis")
	}
	if err := lifecycle.ResolveIntentResult(ctx, taskID, intent, HypothesisResolution{IntentID: intent.ID, EvidenceIDs: []uint{evidence.ID}}); err != nil {
		t.Fatalf("resolve hypothesis from real evidence: %v", err)
	}
	loop := NewCairnLoop(db, blackboard, NewIntentService(db), toolRuns, NewFindingService(db), NewContractService(db, blackboard, nil), nil, nil, nil)
	if _, err := loop.WriteCapability(ctx, taskID, CapabilityDraft{
		CapabilityType: model.CapCrossUserObjectAccess,
		Target:         target,
		Strength:       model.StrengthVerified,
		ProofSummary:   "response_diff ToolRun showed cross-user object access signal",
		EvidenceIDs:    []uint{evidence.ID},
		CanAdvanceGoal: true,
	}, &intent.ID); err != nil {
		t.Fatalf("write capability: %v", err)
	}
	if err := NewStateExpansionPlannerService(db).ScorePendingValidationIntents(ctx, task); err != nil {
		t.Fatalf("score pending intents: %v", err)
	}
	next, err := NewIntentService(db).NextPending(ctx, taskID)
	if err != nil {
		t.Fatalf("next pending: %v", err)
	}
	if next == nil || next.ID == intent.ID {
		t.Fatalf("expected follow-up pending intent eligible for NextPending, got %+v", next)
	}
}

func createRegressionHypothesisIntent(t *testing.T, ctx context.Context, lifecycle *HypothesisLifecycleService, taskID uint, title string) (model.AIHypothesisNode, model.AIIntent) {
	t.Helper()
	h, err := lifecycle.FormHypothesis(ctx, HypothesisDraft{
		TaskID:                taskID,
		HypothesisType:        model.HypothesisTypeInjectionCandidate,
		Title:                 title,
		Description:           "normal hypothesis-driven validation branch",
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: []string{"evidence:1"},
		TargetEntity:          title,
		ExpectedCapability:    model.CapSQLInjection,
	})
	if err != nil {
		t.Fatalf("form hypothesis: %v", err)
	}
	intent, err := lifecycle.CreateValidationIntent(ctx, h, model.IntentBehaviorProbe, "normal_validation", 0.7)
	if err != nil {
		t.Fatalf("create validation intent: %v", err)
	}
	return h, intent
}

func assertNoRemovedRepositoryIntents(t *testing.T, intents []model.AIIntent) {
	t.Helper()
	removed := map[string]bool{}
	for _, value := range removedIntentTypes() {
		removed[value] = true
	}
	for _, intent := range intents {
		if removed[intent.IntentType] {
			t.Fatalf("removed external repository intent was created: %+v", intent)
		}
	}
}

type regressionFakeTool struct {
	name string
}

func (t regressionFakeTool) Name() string { return t.name }
func (t regressionFakeTool) Kind() string { return "pentest" }
func (t regressionFakeTool) Schema() tools.ToolSchema {
	return tools.ToolSchema{Description: "regression fake tool"}
}
func (t regressionFakeTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	return nil
}
func (t regressionFakeTool) Run(ctx context.Context, input json.RawMessage) (*tools.ToolResult, error) {
	now := time.Now().UTC()
	return &tools.ToolResult{
		StartedAt:   now,
		FinishedAt:  now,
		Status:      "success",
		Summary:     "fake behavior probe executed",
		Stdout:      `{"statusDiff":true}`,
		Metadata:    map[string]any{"statusDiff": true},
		CommandHint: t.name,
	}, nil
}
func (t regressionFakeTool) ExtractEvidence(ctx context.Context, result *tools.ToolResult) ([]tools.EvidenceDraft, error) {
	return []tools.EvidenceDraft{{
		Type:         "http_exchange",
		Title:        "Behavior probe evidence",
		Summary:      result.Summary,
		Raw:          result.Stdout,
		RelationType: "poc_result",
	}}, nil
}

func assertNoFindings(t *testing.T, db *gorm.DB, taskID uint, reason string) {
	t.Helper()
	var count int64
	if err := db.Model(&model.AIFinding{}).Where("task_id = ?", taskID).Count(&count).Error; err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if count != 0 {
		t.Fatalf("%s: got %d findings", reason, count)
	}
}

func completeDeliveryDetails(entrypoint, capability string, evidenceIDs []uint) map[string]any {
	return map[string]any{
		"entrypoint":                 entrypoint,
		"controlled_input":           "authorized validation input",
		"propagation_path":           "request parameter reaches validated behavior",
		"sensitive_sink_or_behavior": capability,
		"trigger_payload_or_action":  "send non-destructive validation request",
		"baseline_evidence":          "baseline request denied or unchanged",
		"validation_evidence":        "validation request produced the expected differential signal",
		"observed_result":            "validated differential response",
		"impact_explanation":         "validated capability can affect protected state inside scope",
		"scope_statement":            "authorized test scope only",
		"safety_statement":           "non-destructive proof-only validation",
		"remediation":                "enforce server-side validation and authorization on the affected path",
		"retest_steps":               "repeat baseline and validation requests and confirm the differential signal is gone",
		"evidence_mapping":           evidenceIDs,
		"request_packet":             "GET /validate HTTP/1.1\nHost: example.test",
		"bash_poc":                   "curl -i https://example.test/validate",
		"python_poc":                 "import requests\nrequests.get('https://example.test/validate')",
		"success_criteria":           "validation response no longer differs from the baseline",
		"root_cause":                 "missing server-side authorization or validation on the affected path",
	}
}

func metadataContains(raw []byte, key string) bool {
	var values map[string]any
	_ = json.Unmarshal(raw, &values)
	_, ok := values[key]
	return ok
}
