package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"shenji/backend/internal/config"
	"shenji/backend/internal/model"
	"shenji/backend/internal/runner"
	"shenji/backend/internal/safety"
	"shenji/backend/internal/storage"
	"shenji/backend/internal/tools"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Services struct {
	Config       config.Config
	DB           *gorm.DB
	Store        storage.ArtifactStore
	Workspace    *runner.WorkspaceManager
	Registry     *tools.ToolRegistry
	Auth         *AuthService
	Chat         *ChatService
	Task         *TaskService
	ModelConfig  *ModelConfigService
	ModelRuntime *ModelRuntimeService
	Blackboard   *BlackboardService
	Hypothesis   *HypothesisLifecycleService
	Intent       *IntentService
	ToolRun      *ToolRunService
	Evidence     *EvidenceService
	Finding      *FindingService
	Contract     *ContractService
	Context      *ContextBuilder
	Compactor    *BlackboardCompactor
	Report       *ReportService
	Orchestrator *AgentOrchestrator
}

func NewServices(cfg config.Config, db *gorm.DB, store storage.ArtifactStore, workspace *runner.WorkspaceManager, registry *tools.ToolRegistry) *Services {
	services := &Services{Config: cfg, DB: db, Store: store, Workspace: workspace, Registry: registry}
	services.Auth = NewAuthService(db)
	services.Chat = NewChatService(db)
	services.Blackboard = NewBlackboardService(db)
	services.Hypothesis = NewHypothesisLifecycleService(db, services.Blackboard)
	services.Intent = NewIntentService(db)
	services.ModelConfig = NewModelConfigService(db)
	services.ModelRuntime = NewModelRuntimeService(db, cfg.ModelTimeout)
	services.Evidence = NewEvidenceService(db, store)
	services.ToolRun = NewToolRunService(db, store, registry, services.Evidence)
	services.Finding = NewFindingService(db)
	services.Contract = NewContractService(db, services.Blackboard, services.ModelRuntime)
	services.Context = NewContextBuilder(db)
	services.Compactor = NewBlackboardCompactor(db, services.Blackboard)
	services.Report = NewReportService(db, store)
	services.Task = NewTaskService(cfg, db, workspace, services.Blackboard)
	services.Orchestrator = NewAgentOrchestrator(cfg, db, registry, services.Intent, services.ToolRun, services.Blackboard, services.Finding, services.Contract, services.Context, services.Compactor, services.Report, services.ModelRuntime)
	return services
}

func marshalJSON(value any) datatypes.JSON {
	raw, err := json.Marshal(value)
	if err != nil {
		return datatypes.JSON([]byte("{}"))
	}
	return datatypes.JSON(raw)
}

func unmarshalJSON(raw datatypes.JSON, out any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func mustJSON(value any) datatypes.JSON {
	return model.JSONValue(value)
}

// sanitizeUTF8 removes invalid UTF-8 byte sequences that would cause PostgreSQL errors.
func sanitizeUTF8(s string) string {
	if s == "" {
		return s
	}
	// Fast path: if already valid, return as-is
	valid := true
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			valid = false
			break
		}
	}
	if valid && utf8.ValidString(s) {
		return s
	}
	// Slow path: rebuild string removing invalid bytes and null chars
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		_ = i
		if r == utf8.RuneError {
			continue
		}
		if r == 0 {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func stringListJSON(values []string) datatypes.JSON {
	raw, _ := json.Marshal(values)
	return datatypes.JSON(raw)
}

func appendAuditEvent(ctx context.Context, db *gorm.DB, taskID *uint, eventType, actor, summary string, metadata any) {
	_ = ctx
	event := model.AIAuditEvent{
		TaskID:     taskID,
		EventType:  eventType,
		Actor:      actor,
		Summary:    summary,
		Metadata:   mustJSON(metadata),
		OccurredAt: time.Now().UTC(),
	}
	_ = db.Create(&event).Error
}

func safePolicyFromTask(task model.AISecurityTask) safety.SafePolicy {
	var policy safety.SafePolicy
	if err := unmarshalJSON(task.SafePolicyJSON, &policy); err != nil || policy.NetworkPolicy == "" {
		var scope struct {
			Targets     []string `json:"targets"`
			Level       int      `json:"level"`
			LegacyLevel int      `json:"legacyLevel"`
		}
		_ = unmarshalJSON(task.ScopeJSON, &scope)
		level := scope.Level
		if level == 0 && scope.LegacyLevel != 0 {
			level = scope.LegacyLevel
		}
		if level == 0 {
			var auth struct {
				Level       int `json:"level"`
				LegacyLevel int `json:"legacyLevel"`
			}
			_ = unmarshalJSON(task.AuthorizationJSON, &auth)
			level = auth.Level
			if level == 0 && auth.LegacyLevel != 0 {
				level = auth.LegacyLevel
			}
		}
		policy = safety.DefaultPolicy(scope.Targets, level)
	}
	policy.AllowEvidenceProofCommands = true
	policy.AllowReadOnlyCommands = true
	policy.AllowSandboxVerification = true
	return policy
}

func errNotFound(kind string, id any) error {
	return fmt.Errorf("%s not found: %v", kind, id)
}
