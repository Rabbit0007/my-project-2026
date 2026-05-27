package service

import (
	"context"
	"testing"
	"time"

	"shenji/backend/internal/config"
	"shenji/backend/internal/model"
)

func TestParsePlannerOutput(t *testing.T) {
	raw := "```json\n{\"thought_summary\":\"collect authorized HTTP facts\",\"planned_action\":\"run http_request and persist evidence\"}\n```"
	parsed, err := parsePlannerOutput(raw)
	if err != nil {
		t.Fatalf("expected planner output to parse, got error: %v", err)
	}
	if parsed.ThoughtSummary == "" || parsed.PlannedAction == "" {
		t.Fatalf("expected both planner fields to be populated, got %+v", parsed)
	}
}

func TestParsePlannerOutputWithNextIntents(t *testing.T) {
	raw := `{
		"thought_summary":"current method was inconclusive; pivot to an observable behavior comparison",
		"planned_action":"record the current method result and schedule one follow-up validation intent",
		"next_intents":[{"title":"Compare alternate object access path","objective":"Use response_diff to compare ownership behavior on the alternate object route.","intent_type":"idor_probe","required_evidence":["response_diff","http_exchange"]}]
	}`
	parsed, err := parsePlannerOutput(raw)
	if err != nil {
		t.Fatalf("expected planner output with next_intents to parse, got error: %v", err)
	}
	intents := normalizeSecurityGraphIntents(parsed.NextIntents)
	if len(intents) != 1 || intents[0].IntentType != model.IntentIDORProbe || len(intents[0].RequiredEvidence) != 2 {
		t.Fatalf("expected one normalized follow-up intent, got %+v", intents)
	}
}

func TestParseSecurityGraphDecisionAcceptsSelectedIntentsWithSourceNodes(t *testing.T) {
	raw := `{
		"analysis_summary":"login and credential facts can be composed into one validation direction",
		"goal_progress":"needs validation evidence",
		"selected_intents":[{
			"title":"Validate credential against discovered login endpoint",
			"objective":"Attempt one authorized non-destructive login check and record request/response evidence.",
			"intent_type":"auth_probe",
			"source_node_ids":[12,"node:18",12],
			"hypothesis":"The credential candidate may authenticate to the discovered login endpoint.",
			"success_criteria":"A session indicator or authenticated response is observed.",
			"failure_criteria":"The endpoint rejects the credential without session state.",
			"allowed_tools":["http_request","response_diff"],
			"required_evidence":["http_exchange","session_indicator"],
			"risk_level":"low",
			"priority":87
		}]
	}`
	decision, err := parseSecurityGraphDecisionOutput(raw)
	if err != nil {
		t.Fatalf("parse security graph decision: %v", err)
	}
	if len(decision.NextIntents) != 1 {
		t.Fatalf("expected one selected intent to normalize into NextIntents, got %+v", decision.NextIntents)
	}
	intent := decision.NextIntents[0]
	if intent.IntentType != model.IntentAuthProbe || len(intent.SourceNodeIDs) != 2 || intent.SourceNodeIDs[0] != 12 || intent.SourceNodeIDs[1] != 18 {
		t.Fatalf("expected auth_probe with compact source node ids, got %+v", intent)
	}
	if intent.Hypothesis == "" || intent.SuccessCriteria == "" || len(intent.AllowedTools) != 2 || intent.Priority != 87 {
		t.Fatalf("expected structured Cairn reason fields to survive parsing, got %+v", intent)
	}
}

func TestJoinAPIURL(t *testing.T) {
	got := joinAPIURL("http://103.18.229.74:8080/v1", "/responses")
	want := "http://103.18.229.74:8080/v1/responses"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestParseEvidenceIntentOutput(t *testing.T) {
	raw := "{\"title\":\"补充验证证据\",\"objective\":\"Collect validation evidence for candidate risk.\",\"intent_type\":\"validate\"}"
	parsed, err := parseEvidenceIntentOutput(raw)
	if err != nil {
		t.Fatalf("expected evidence intent output to parse, got error: %v", err)
	}
	if parsed.IntentType != "validate" {
		t.Fatalf("expected intent_type validate, got %s", parsed.IntentType)
	}
}

func TestEnforceFindingNarrativeGuardrail(t *testing.T) {
	finding := model.AIFinding{Status: model.FindingStatusContractIncomplete}
	got := enforceFindingNarrativeGuardrail(finding, "This issue is confirmed and successfully exploited.")
	if got == "This issue is confirmed and successfully exploited." {
		t.Fatalf("expected unsafe narrative to be downgraded")
	}
}

func TestDeliveryEvidenceKeepsCommandExecutionPoC(t *testing.T) {
	item := model.AIEvidence{
		EvidenceType: "command_output",
		Title:        "Command execution PoC proof",
		Summary:      "命令执行漏洞验证产生回显：command=whoami, output=www-data",
		RelationType: "poc_result",
	}
	if !isDeliveryEvidence(item) {
		t.Fatalf("expected whoami command output from exploit context to be delivery evidence")
	}
	environmentCheck := model.AIEvidence{
		EvidenceType: "command_output",
		Title:        "Evidence proof command output",
		Summary:      "Sandbox command `whoami` finished with status success",
		RelationType: "command_output",
	}
	if isDeliveryEvidence(environmentCheck) {
		t.Fatalf("expected plain runner environment command output to remain backend-only")
	}
}

func TestSelectWorkerForIntentUsesWorkerPool(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	if err := db.Where("1 = 1").Delete(&model.AIModelConfig{}).Error; err != nil {
		t.Fatalf("clear model configs: %v", err)
	}
	brain := model.AIModelConfig{Name: "brain", Purpose: model.ModelPurposeBrain, Provider: "openai-compatible", Model: "brain-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{})}
	workerA := model.AIModelConfig{Name: "worker-a", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "worker-a-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority":   5,
		"workerMaxRunning": 1,
		"workerTaskTypes":  []string{"pentest"},
		"workerDriver":     "pi_container_kali",
	})}
	workerB := model.AIModelConfig{Name: "worker-b", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "worker-b-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority":   1,
		"workerMaxRunning": 2,
		"workerTaskTypes":  []string{"pentest"},
		"workerDriver":     "pi_container_kali",
	})}
	if err := db.Create(&brain).Error; err != nil {
		t.Fatalf("create brain: %v", err)
	}
	if err := db.Create(&workerA).Error; err != nil {
		t.Fatalf("create worker a: %v", err)
	}
	if err := db.Create(&workerB).Error; err != nil {
		t.Fatalf("create worker b: %v", err)
	}
	runtime := NewModelRuntimeService(db, 0)
	intent := model.AIIntent{TaskID: 1, IntentType: model.IntentSQLiProbe, Title: "SQLi", Status: model.IntentStatusPending, CreatedBy: "test"}
	selected, ok, err := runtime.SelectWorkerForIntent(ctx, 1, &intent)
	if err != nil {
		t.Fatalf("select worker: %v", err)
	}
	if !ok || selected.Config.ID != workerB.ID || selected.WorkerID == "" {
		t.Fatalf("expected lower-priority worker-b to be selected, ok=%v selected=%+v", ok, selected)
	}
	claimed := model.AIIntent{TaskID: 1, IntentType: model.IntentSQLiProbe, Title: "claimed", Status: model.IntentStatusClaimed, ClaimedBy: selected.WorkerID, CreatedBy: "test"}
	if err := db.Create(&claimed).Error; err != nil {
		t.Fatalf("create claimed intent: %v", err)
	}
	selectedAgain, ok, err := runtime.SelectWorkerForIntent(ctx, 1, &intent)
	if err != nil {
		t.Fatalf("select worker again: %v", err)
	}
	if !ok || selectedAgain.Config.ID != workerB.ID || selectedAgain.Running != 1 {
		t.Fatalf("expected worker-b to accept second concurrent run, ok=%v selected=%+v", ok, selectedAgain)
	}
	secondClaim := model.AIIntent{TaskID: 1, IntentType: model.IntentSQLiProbe, Title: "claimed 2", Status: model.IntentStatusRunning, ClaimedBy: selected.WorkerID, CreatedBy: "test"}
	if err := db.Create(&secondClaim).Error; err != nil {
		t.Fatalf("create second claimed intent: %v", err)
	}
	fallback, ok, err := runtime.SelectWorkerForIntent(ctx, 1, &intent)
	if err != nil {
		t.Fatalf("select fallback worker: %v", err)
	}
	if !ok || fallback.Config.ID != workerA.ID {
		t.Fatalf("expected worker-a after worker-b reaches max concurrency, ok=%v selected=%+v", ok, fallback)
	}
}

func TestSelectWorkerForIntentSkipsNativeDriverPoolRows(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	if err := db.Where("1 = 1").Delete(&model.AIModelConfig{}).Error; err != nil {
		t.Fatalf("clear model configs: %v", err)
	}
	native := model.AIModelConfig{Name: "native", Purpose: model.ModelPurposeBoth, Provider: "openai-compatible", Model: "native-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority": 0,
		"workerDriver":   "native",
	})}
	pi := model.AIModelConfig{Name: "pi", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "pi-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority": 10,
		"workerDriver":   "pi_container_kali",
	})}
	if err := db.Create(&native).Error; err != nil {
		t.Fatalf("create native worker: %v", err)
	}
	if err := db.Create(&pi).Error; err != nil {
		t.Fatalf("create pi worker: %v", err)
	}
	selected, ok, err := NewModelRuntimeService(db, 0).SelectWorkerForIntent(ctx, 1, &model.AIIntent{TaskID: 1, IntentType: model.IntentBehaviorProbe})
	if err != nil {
		t.Fatalf("select worker: %v", err)
	}
	if !ok || selected.Config.ID != pi.ID {
		t.Fatalf("expected external pi worker to be selected while native remains built-in fallback, ok=%v selected=%+v", ok, selected)
	}
	if selected.MaxRunning != defaultExternalWorkerMaxRunning {
		t.Fatalf("expected default external worker concurrency %d, got %d", defaultExternalWorkerMaxRunning, selected.MaxRunning)
	}
}

func TestSelectWorkerForIntentSkipsLegacyBothPurposeRows(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	if err := db.Where("1 = 1").Delete(&model.AIModelConfig{}).Error; err != nil {
		t.Fatalf("clear model configs: %v", err)
	}
	legacyBoth := model.AIModelConfig{Name: "legacy-both", Purpose: model.ModelPurposeBoth, Provider: "openai-compatible", Model: "legacy-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority": 0,
		"workerDriver":   "pi_container_kali",
	})}
	worker := model.AIModelConfig{Name: "worker", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "worker-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority": 10,
		"workerDriver":   "pi_container_kali",
	})}
	if err := db.Create(&legacyBoth).Error; err != nil {
		t.Fatalf("create legacy both config: %v", err)
	}
	if err := db.Create(&worker).Error; err != nil {
		t.Fatalf("create worker config: %v", err)
	}
	selected, ok, err := NewModelRuntimeService(db, 0).SelectWorkerForIntent(ctx, 1, &model.AIIntent{TaskID: 1, IntentType: model.IntentBehaviorProbe})
	if err != nil {
		t.Fatalf("select worker: %v", err)
	}
	if !ok || selected.Config.ID != worker.ID {
		t.Fatalf("expected worker-only config to be selected, ok=%v selected=%+v", ok, selected)
	}
}

func TestSelectWorkerForIntentAcceptsPiContainerKaliDriver(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	if err := db.Where("1 = 1").Delete(&model.AIModelConfig{}).Error; err != nil {
		t.Fatalf("clear model configs: %v", err)
	}
	worker := model.AIModelConfig{Name: "pi-kali", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "pi-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority":   0,
		"workerDriver":     "pi_container_kali",
		"workerMaxRunning": 2,
	})}
	if err := db.Create(&worker).Error; err != nil {
		t.Fatalf("create pi container worker: %v", err)
	}
	selected, ok, err := NewModelRuntimeService(db, 0).SelectWorkerForIntent(ctx, 1, &model.AIIntent{TaskID: 1, IntentType: model.IntentBehaviorProbe})
	if err != nil {
		t.Fatalf("select worker: %v", err)
	}
	if !ok || selected.Config.ID != worker.ID || selected.MaxRunning != 2 {
		t.Fatalf("expected pi_container_kali worker to be selectable, ok=%v selected=%+v", ok, selected)
	}
}

func TestNormalizeLegacyPiCLIWorkerDriverToContainerKali(t *testing.T) {
	if got := normalizeWorkerDriver("pi_cli"); got != "pi_container_kali" {
		t.Fatalf("expected legacy pi_cli to normalize to pi_container_kali, got %q", got)
	}
	if !isExternalWorkerDriver("pi_cli") {
		t.Fatalf("expected legacy pi_cli configs to remain selectable as container workers")
	}
}

func TestSelectWorkerForIntentPrefersTaskSelectedWorker(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	if err := db.Where("1 = 1").Delete(&model.AIModelConfig{}).Error; err != nil {
		t.Fatalf("clear model configs: %v", err)
	}
	lowPriority := model.AIModelConfig{Name: "pool-default", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "pool-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority": 0,
		"workerDriver":   "pi_container_kali",
	})}
	selectedWorker := model.AIModelConfig{Name: "task-selected", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "selected-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority": 10,
		"workerDriver":   "pi_container_kali",
	})}
	if err := db.Create(&lowPriority).Error; err != nil {
		t.Fatalf("create pool default: %v", err)
	}
	if err := db.Create(&selectedWorker).Error; err != nil {
		t.Fatalf("create selected worker: %v", err)
	}
	task := model.AISecurityTask{ID: 909, WorkspaceID: 1, Name: "selected worker task", TaskType: model.TaskTypePentest, Status: model.TaskStatusPending, WorkerModelConfigID: &selectedWorker.ID}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	selected, ok, err := NewModelRuntimeService(db, 0).SelectWorkerForIntent(ctx, task.ID, &model.AIIntent{TaskID: task.ID, IntentType: model.IntentBehaviorProbe})
	if err != nil {
		t.Fatalf("select worker: %v", err)
	}
	if !ok || selected.Config.ID != selectedWorker.ID {
		t.Fatalf("expected task-selected worker despite lower pool priority, ok=%v selected=%+v", ok, selected)
	}
}

func TestWorkerPoolSkipsWorkerOnlyModelForTaskDefault(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	if err := db.Where("1 = 1").Delete(&model.AIModelConfig{}).Error; err != nil {
		t.Fatalf("clear model configs: %v", err)
	}
	worker := model.AIModelConfig{Name: "worker", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "worker-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{})}
	brain := model.AIModelConfig{Name: "brain", Purpose: model.ModelPurposeBrain, Provider: "openai-compatible", Model: "brain-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{})}
	if err := db.Create(&worker).Error; err != nil {
		t.Fatalf("create worker: %v", err)
	}
	if err := db.Create(&brain).Error; err != nil {
		t.Fatalf("create brain: %v", err)
	}
	tasks := NewTaskService(config.Config{}, db, nil, nil)
	id, err := tasks.defaultModelConfigID(ctx)
	if err != nil {
		t.Fatalf("default model config: %v", err)
	}
	if id == nil || *id != brain.ID {
		t.Fatalf("expected default task model to skip worker-only config and pick brain, got %v", id)
	}
}

func TestWorkerPoolDistributesMultiplePendingIntentsByCapacity(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	if err := db.Where("1 = 1").Delete(&model.AIModelConfig{}).Error; err != nil {
		t.Fatalf("clear model configs: %v", err)
	}
	workerA := model.AIModelConfig{Name: "worker-a", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "worker-a-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority":   1,
		"workerMaxRunning": 1,
		"workerTaskTypes":  []string{"pentest"},
		"workerDriver":     "pi_container_kali",
	})}
	workerB := model.AIModelConfig{Name: "worker-b", Purpose: model.ModelPurposeWorker, Provider: "openai-compatible", Model: "worker-b-model", Enabled: true, OptionsJSON: mustJSON(map[string]any{
		"workerPriority":   1,
		"workerMaxRunning": 2,
		"workerTaskTypes":  []string{"pentest"},
		"workerDriver":     "pi_container_kali",
	})}
	if err := db.Create(&workerA).Error; err != nil {
		t.Fatalf("create worker a: %v", err)
	}
	if err := db.Create(&workerB).Error; err != nil {
		t.Fatalf("create worker b: %v", err)
	}
	runtime := NewModelRuntimeService(db, 0)
	intents := NewIntentService(db)
	selectedIDs := []uint{}
	for i := 0; i < 3; i++ {
		intent := model.AIIntent{TaskID: 777, IntentType: model.IntentIDORProbe, Title: "intent", Objective: "validate", Status: model.IntentStatusPending, CreatedBy: "test"}
		if err := db.Create(&intent).Error; err != nil {
			t.Fatalf("create intent %d: %v", i, err)
		}
		selected, ok, err := runtime.SelectWorkerForIntent(ctx, 777, &intent)
		if err != nil {
			t.Fatalf("select worker %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("expected worker selection for intent %d", i)
		}
		selectedIDs = append(selectedIDs, selected.Config.ID)
		if err := intents.Claim(ctx, &intent, selected.WorkerID, time.Minute); err != nil {
			t.Fatalf("claim intent %d: %v", i, err)
		}
	}
	if len(selectedIDs) != 3 || selectedIDs[0] != workerA.ID || selectedIDs[1] != workerB.ID || selectedIDs[2] != workerB.ID {
		t.Fatalf("expected capacity-aware worker distribution A,B,B; got %+v", selectedIDs)
	}
}

func TestIntentClaimAllowsOnlyOneWorkerPerClue(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	intents := NewIntentService(db)
	intent := model.AIIntent{
		TaskID:        9090,
		IntentType:    model.IntentIDORProbe,
		Title:         "single clue validation",
		Objective:     "validate one clue once",
		Status:        model.IntentStatusPending,
		PriorityScore: 0.9,
		CreatedBy:     "test",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := db.Create(&intent).Error; err != nil {
		t.Fatalf("create intent: %v", err)
	}
	firstCopy := intent
	secondCopy := intent
	if err := intents.Claim(ctx, &firstCopy, "worker:1:pi-a", time.Minute); err != nil {
		t.Fatalf("first worker should claim clue: %v", err)
	}
	if err := intents.Claim(ctx, &secondCopy, "worker:2:pi-b", time.Minute); err == nil {
		t.Fatalf("second worker must not claim the same clue")
	}
	var reloaded model.AIIntent
	if err := db.First(&reloaded, intent.ID).Error; err != nil {
		t.Fatalf("reload intent: %v", err)
	}
	if reloaded.ClaimedBy != "worker:1:pi-a" || reloaded.Status != model.IntentStatusRunning {
		t.Fatalf("expected first worker claim to remain authoritative, got %+v", reloaded)
	}
}
