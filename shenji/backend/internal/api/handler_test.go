package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shenji/backend/internal/config"
	"shenji/backend/internal/database"
	"shenji/backend/internal/model"
	"shenji/backend/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newHandlerTestServices(t *testing.T) *service.Services {
	t.Helper()
	dbName := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := gorm.Open(sqlite.Open("file:"+dbName+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate test db: %v", err)
	}
	cfg := config.Config{
		WorkspaceRoot: t.TempDir(),
		ArtifactRoot:  t.TempDir(),
	}
	return service.NewServices(cfg, db, nil, nil, nil)
}

func TestDeleteTaskHardDeletesGraphData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	services := newHandlerTestServices(t)
	db := services.DB
	now := time.Now()
	taskID := uint(77)
	taskIDPtr := taskID

	records := []any{
		&model.AIWorkspace{ID: 1, Name: "workspace", RootPath: "/tmp/workspace", CreatedAt: now, UpdatedAt: now},
		&model.AISecurityTask{ID: taskID, WorkspaceID: 1, Name: "finished task", TaskType: model.TaskTypePentest, Status: model.TaskStatusCompleted, Archived: true, CreatedAt: now, UpdatedAt: now},
		&model.AITaskTarget{TaskID: taskID, TargetType: "url", Value: "http://target", ScopeStatus: "in_scope", CreatedAt: now},
		&model.AIAgentLoop{ID: 1, TaskID: taskID, Status: "completed", Goal: "goal", StartedAt: now, CreatedAt: now},
		&model.AIAgentLoopIteration{LoopID: 1, TaskID: taskID, IterationNo: 1, Status: "completed", StartedAt: now},
		&model.AIBlackboardNode{ID: 1, TaskID: taskID, NodeType: "fact", Title: "fact", DedupKey: "dedup-a", Status: "active", SourceType: "test", FirstSeenAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now},
		&model.AIBlackboardNode{ID: 2, TaskID: taskID, NodeType: "fact", Title: "fact 2", DedupKey: "dedup-b", Status: "active", SourceType: "test", FirstSeenAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now},
		&model.AIBlackboardEdge{TaskID: taskID, FromID: 1, ToID: 2, EdgeType: "supports", CreatedAt: now},
		&model.AIIntent{ID: 1, TaskID: taskID, IntentType: model.IntentBehaviorProbe, Title: "intent", Status: model.IntentStatusCompleted, CreatedBy: "test", CreatedAt: now, UpdatedAt: now},
		&model.AIToolRun{ID: 1, TaskID: taskID, RunnerType: "worker", ToolName: "bash", Status: model.ToolRunStatusSuccess, StartedAt: now, CreatedAt: now},
		&model.AIEvidence{ID: 1, TaskID: taskID, ToolRunID: uintPtr(1), EvidenceType: "command_output", Title: "evidence", Hash: "hash", CreatedAt: now},
		&model.AIFinding{ID: 1, TaskID: taskID, Title: "finding", VulnerabilityType: model.CapSQLInjection, Severity: "high", Status: "open", ValidationStatus: "validated", ContractStatus: model.ContractStatusPassed, HumanReviewStatus: "pending", CreatedAt: now, UpdatedAt: now},
		&model.AIContractCheckResult{TaskID: taskID, FindingID: 1, ContractType: "finding_quality", Status: model.ContractStatusPassed, CheckedAt: now},
		&model.AIReport{TaskID: taskID, Title: "report", Status: "ready", Format: "markdown", CreatedAt: now, UpdatedAt: now},
		&model.AIHumanReview{TaskID: taskID, FindingID: 1, Status: "pending", CreatedAt: now},
		&model.AIModelCallLog{TaskID: &taskIDPtr, ModelName: "gpt-test", Purpose: "test", Status: "success", CalledAt: now},
		&model.AIAuditEvent{TaskID: &taskIDPtr, EventType: "task.test", Actor: "test", Summary: "summary", OccurredAt: now},
		&model.AICapability{TaskID: taskID, CapabilityType: model.CapSQLInjection, Strength: model.StrengthVerified, CreatedAt: now, UpdatedAt: now},
		&model.AIGoalProfile{TaskID: taskID, GoalType: model.GoalTypeCoverage, Name: "goal", Mode: model.GoalModeWebPentest, CreatedAt: now, UpdatedAt: now},
		&model.AIHypothesisNode{TaskID: taskID, HypothesisType: model.HypothesisTypeInjectionCandidate, Title: "hypothesis", ConfidenceState: model.ConfidencePlausible, Status: model.HypothesisStatusPending, CreatedAt: now, UpdatedAt: now},
		&model.AINegativeFact{TaskID: taskID, Title: "negative", CreatedAt: now},
		&model.AIUnverifiedRisk{TaskID: taskID, Title: "risk", Reason: model.UnverifiedReasonInconclusiveEvidence, CreatedAt: now},
		&model.AICoverageItem{TaskID: taskID, Category: "endpoint", Name: "coverage", Status: "discovered", CreatedAt: now, UpdatedAt: now},
		&model.AIEnvironmentModel{TaskID: taskID, UpdatedFrom: "test", CreatedAt: now, UpdatedAt: now},
		&model.AIObjectiveLadder{TaskID: taskID, Level: 1, Name: "ladder", Status: "pending", CreatedAt: now, UpdatedAt: now},
	}
	for _, record := range records {
		if err := db.Create(record).Error; err != nil {
			t.Fatalf("create %T: %v", record, err)
		}
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/tasks/77", nil)
	c.Params = gin.Params{{Key: "id", Value: "77"}}
	NewHandler(services).DeleteTask(c)

	if w.Code != http.StatusOK {
		t.Fatalf("delete task returned %d: %s", w.Code, w.Body.String())
	}
	assertTaskRowsGone(t, db, taskID)
	var workspaceCount int64
	db.Model(&model.AIWorkspace{}).Where("id = ?", 1).Count(&workspaceCount)
	if workspaceCount != 0 {
		t.Fatalf("unused workspace should be deleted, got %d rows", workspaceCount)
	}
}

func TestTaskListIncludesLegacyArchivedTasks(t *testing.T) {
	services := newHandlerTestServices(t)
	now := time.Now()
	if err := services.DB.Create(&model.AIWorkspace{ID: 1, Name: "workspace", RootPath: "/tmp/workspace", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	for _, task := range []model.AISecurityTask{
		{ID: 1, WorkspaceID: 1, Name: "visible archived", TaskType: model.TaskTypePentest, Status: model.TaskStatusCompleted, Archived: true, CreatedAt: now, UpdatedAt: now},
		{ID: 2, WorkspaceID: 1, Name: "visible normal", TaskType: model.TaskTypePentest, Status: model.TaskStatusCompleted, CreatedAt: now, UpdatedAt: now},
	} {
		if err := services.DB.Create(&task).Error; err != nil {
			t.Fatalf("create task: %v", err)
		}
	}

	tasks, err := services.Task.List(context.Background(), false)
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("legacy archived tasks should remain visible for hard delete, got %d tasks", len(tasks))
	}
}

func assertTaskRowsGone(t *testing.T, db *gorm.DB, taskID uint) {
	t.Helper()
	checks := []struct {
		name  string
		model any
		query string
		args  []any
	}{
		{"tasks", &model.AISecurityTask{}, "id = ?", []any{taskID}},
		{"targets", &model.AITaskTarget{}, "task_id = ?", []any{taskID}},
		{"loops", &model.AIAgentLoop{}, "task_id = ?", []any{taskID}},
		{"iterations", &model.AIAgentLoopIteration{}, "task_id = ?", []any{taskID}},
		{"blackboard_nodes", &model.AIBlackboardNode{}, "task_id = ?", []any{taskID}},
		{"blackboard_edges", &model.AIBlackboardEdge{}, "task_id = ?", []any{taskID}},
		{"intents", &model.AIIntent{}, "task_id = ?", []any{taskID}},
		{"tool_runs", &model.AIToolRun{}, "task_id = ?", []any{taskID}},
		{"evidence", &model.AIEvidence{}, "task_id = ?", []any{taskID}},
		{"findings", &model.AIFinding{}, "task_id = ?", []any{taskID}},
		{"contract_checks", &model.AIContractCheckResult{}, "task_id = ?", []any{taskID}},
		{"reports", &model.AIReport{}, "task_id = ?", []any{taskID}},
		{"human_reviews", &model.AIHumanReview{}, "task_id = ?", []any{taskID}},
		{"model_call_logs", &model.AIModelCallLog{}, "task_id = ?", []any{taskID}},
		{"audit_events", &model.AIAuditEvent{}, "task_id = ?", []any{taskID}},
		{"capabilities", &model.AICapability{}, "task_id = ?", []any{taskID}},
		{"goal_profiles", &model.AIGoalProfile{}, "task_id = ?", []any{taskID}},
		{"hypotheses", &model.AIHypothesisNode{}, "task_id = ?", []any{taskID}},
		{"negative_facts", &model.AINegativeFact{}, "task_id = ?", []any{taskID}},
		{"unverified_risks", &model.AIUnverifiedRisk{}, "task_id = ?", []any{taskID}},
		{"coverage_items", &model.AICoverageItem{}, "task_id = ?", []any{taskID}},
		{"environment_models", &model.AIEnvironmentModel{}, "task_id = ?", []any{taskID}},
		{"objective_ladders", &model.AIObjectiveLadder{}, "task_id = ?", []any{taskID}},
	}
	for _, check := range checks {
		var count int64
		if err := db.Model(check.model).Where(check.query, check.args...).Count(&count).Error; err != nil {
			t.Fatalf("count %s: %v", check.name, err)
		}
		if count != 0 {
			t.Fatalf("%s still has %d rows for task %d", check.name, count, taskID)
		}
	}
}

func uintPtr(value uint) *uint {
	return &value
}
