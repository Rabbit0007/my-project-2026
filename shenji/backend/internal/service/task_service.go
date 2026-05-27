package service

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"shenji/backend/internal/config"
	"shenji/backend/internal/model"
	"shenji/backend/internal/runner"
	"shenji/backend/internal/safety"

	"gorm.io/gorm"
)

type TaskService struct {
	cfg        config.Config
	db         *gorm.DB
	workspace  *runner.WorkspaceManager
	blackboard *BlackboardService
}

type CreateTaskInput struct {
	Name                       string   `json:"name"`
	TaskType                   string   `json:"taskType"`
	Objective                  string   `json:"objective"`
	Targets                    []string `json:"targets"`
	IncludePaths               []string `json:"includePaths"`
	ExcludePaths               []string `json:"excludePaths"`
	AuthorizationLevel         int      `json:"authorizationLevel"`
	AllowChainExploration      bool     `json:"allowChainExploration"`
	AllowReadOnlyCommands      bool     `json:"allowReadOnlyCommands"`
	AllowEvidenceProofCommands bool     `json:"allowEvidenceProofCommands"`
	ModelConfigID              *uint    `json:"modelConfigId"`
	WorkerModelConfigID        *uint    `json:"workerModelConfigId"`
	IsTestTask                 bool     `json:"isTestTask"`
}

func NewTaskService(cfg config.Config, db *gorm.DB, workspace *runner.WorkspaceManager, blackboard *BlackboardService) *TaskService {
	return &TaskService{cfg: cfg, db: db, workspace: workspace, blackboard: blackboard}
}

func (s *TaskService) RecoverInterrupted(ctx context.Context) error {
	now := time.Now().UTC()
	var tasks []model.AISecurityTask
	if err := s.db.WithContext(ctx).
		Where("status = ?", model.TaskStatusRunning).
		Find(&tasks).Error; err != nil {
		return err
	}
	for _, task := range tasks {
		task.Status = model.TaskStatusFailed
		task.ProgressStage = "执行中断：服务重启后 fail-closed 恢复"
		task.FinishedAt = &now
		if err := s.db.WithContext(ctx).Save(&task).Error; err != nil {
			return err
		}
		appendAuditEvent(ctx, s.db, &task.ID, "agent.recovered_interrupted", "agent-runtime", "Running task was marked failed during startup recovery to avoid an infinite running state.", map[string]any{"recoveredAt": now})
	}
	_ = s.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("status = ?", model.IntentStatusRunning).
		Updates(map[string]any{"status": model.IntentStatusFailed, "updated_at": now, "finished_at": now}).Error
	_ = s.db.WithContext(ctx).Model(&model.AIToolRun{}).
		Where("status = ?", model.ToolRunStatusRunning).
		Updates(map[string]any{"status": model.ToolRunStatusFailed, "finished_at": now, "block_reason": "service restarted before tool completion"}).Error
	return nil
}

func (s *TaskService) Create(ctx context.Context, input CreateTaskInput) (model.AISecurityTask, error) {
	taskType := strings.TrimSpace(input.TaskType)
	if taskType == "" {
		taskType = model.TaskTypeCodeAudit
	}
	if taskType != model.TaskTypeCodeAudit && taskType != model.TaskTypePentest && taskType != model.TaskTypeInternalPentest && taskType != model.TaskTypeTerminalProof && taskType != model.TaskTypeHybrid {
		return model.AISecurityTask{}, fmt.Errorf("unsupported task type: %s", taskType)
	}
	if (taskType == model.TaskTypePentest || taskType == model.TaskTypeInternalPentest || taskType == model.TaskTypeTerminalProof || taskType == model.TaskTypeHybrid) && len(input.Targets) == 0 {
		return model.AISecurityTask{}, fmt.Errorf("at least one authorized target is required for pentest or hybrid tasks")
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = "AI Security Validation Task"
	}
	if input.AuthorizationLevel < 0 || input.AuthorizationLevel > 3 {
		return model.AISecurityTask{}, fmt.Errorf("authorization level must be between 0 and 3")
	}
	input.AllowEvidenceProofCommands = true
	input.AllowReadOnlyCommands = true
	input.AllowChainExploration = true
	if input.ModelConfigID == nil {
		defaultModelID, err := s.defaultModelConfigID(ctx)
		if err != nil {
			return model.AISecurityTask{}, err
		}
		if defaultModelID != nil {
			input.ModelConfigID = defaultModelID
		}
	}
	if input.ModelConfigID != nil {
		var count int64
		if err := s.db.WithContext(ctx).Model(&model.AIModelConfig{}).
			Where("id = ? AND enabled = ? AND (purpose = ? OR purpose = '')", *input.ModelConfigID, true, model.ModelPurposeBrain).
			Count(&count).Error; err != nil {
			return model.AISecurityTask{}, err
		}
		if count == 0 {
			return model.AISecurityTask{}, fmt.Errorf("所选 Brain 模型配置不存在、未启用或不是 brain 用途")
		}
	}
	if input.WorkerModelConfigID != nil {
		var count int64
		if err := s.db.WithContext(ctx).Model(&model.AIModelConfig{}).
			Where("id = ? AND enabled = ? AND purpose = ?", *input.WorkerModelConfigID, true, model.ModelPurposeWorker).
			Count(&count).Error; err != nil {
			return model.AISecurityTask{}, err
		}
		if count == 0 {
			return model.AISecurityTask{}, fmt.Errorf("所选 Worker 模型配置不存在、未启用或不是 worker 用途")
		}
	}
	scope := map[string]any{
		"targets":             input.Targets,
		"includePaths":        input.IncludePaths,
		"excludePaths":        input.ExcludePaths,
		"legacyLevel":         input.AuthorizationLevel,
		"evidenceProofPolicy": "non_destructive_authorized_scope",
	}
	auth := map[string]any{
		"legacyLevel":                input.AuthorizationLevel,
		"allowChainExploration":      input.AllowChainExploration,
		"allowReadOnlyCommands":      input.AllowReadOnlyCommands,
		"allowEvidenceProofCommands": input.AllowEvidenceProofCommands,
		"evidenceProofPolicy":        "non_destructive_authorized_scope",
		"blockedActions":             []string{"destructive_delete", "process_kill", "download_execute", "persistence", "log_cleanup", "resource_destruction", "out_of_scope_access"},
	}
	policy := safety.DefaultPolicy(input.Targets, input.AuthorizationLevel)
	policy.AllowChainExploration = true
	policy.AllowReadOnlyCommands = true
	policy.AllowEvidenceProofCommands = true

	workspace := model.AIWorkspace{
		Name:        name + " Workspace",
		Description: "Isolated workspace for " + taskType,
		RootPath:    "",
		StorageRef:  "",
		CreatedBy:   0,
	}
	if err := s.db.WithContext(ctx).Create(&workspace).Error; err != nil {
		return model.AISecurityTask{}, err
	}
	objective := strings.TrimSpace(input.Objective)
	if objective == "" {
		objective = "Collect authorized security facts, validate evidence safely, and generate a delivery-ready report."
	}
	task := model.AISecurityTask{
		WorkspaceID:         workspace.ID,
		Name:                name,
		TaskType:            taskType,
		Status:              model.TaskStatusPending,
		Objective:           objective,
		ScopeJSON:           mustJSON(scope),
		AuthorizationJSON:   mustJSON(auth),
		SafePolicyJSON:      mustJSON(policy),
		ModelConfigID:       input.ModelConfigID,
		WorkerModelConfigID: input.WorkerModelConfigID,
		IsTestTask:          input.IsTestTask,
		Archived:            false,
		ProgressStage:       "等待启动",
		ProgressPercent:     0,
		CreatedBy:           0,
	}
	if err := s.db.WithContext(ctx).Create(&task).Error; err != nil {
		return model.AISecurityTask{}, err
	}
	root, err := s.workspace.PrepareTask(ctx, task.ID)
	if err != nil {
		return model.AISecurityTask{}, err
	}
	workspace.RootPath = root
	if err := s.db.WithContext(ctx).Save(&workspace).Error; err != nil {
		return model.AISecurityTask{}, err
	}
	for _, target := range input.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		targetType := inferTargetType(target, taskType)
		row := model.AITaskTarget{
			TaskID:      task.ID,
			TargetType:  targetType,
			Value:       target,
			ScopeStatus: "in_scope",
			Metadata:    mustJSON(map[string]any{}),
			CreatedAt:   time.Now().UTC(),
		}
		if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
			return task, err
		}
	}
	originNode, err := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          task.ID,
		NodeType:        "origin",
		Title:           "Authorized task origin",
		Summary:         "Task created from user-provided authorized scope.",
		Content:         scope,
		DedupSeed:       "origin",
		ImportanceScore: 1.0,
		SourceType:      "human",
		SourceID:        "task-create",
	})
	if err != nil {
		return task, err
	}
	if _, err := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          task.ID,
		NodeType:        "goal",
		Title:           "Delivery-ready evidence report",
		Summary:         objective,
		Content:         map[string]any{"objective": objective},
		DedupSeed:       "goal",
		ImportanceScore: 1.0,
		SourceType:      "human",
		SourceID:        "task-create",
	}); err != nil {
		return task, err
	}
	hypotheses := NewHypothesisLifecycleService(s.db, s.blackboard)
	_, _ = hypotheses.EnsureDefaultGoalProfile(ctx, task)
	expectedCapability := model.CapSourceCodeRead
	if taskType == model.TaskTypePentest || taskType == model.TaskTypeInternalPentest {
		expectedCapability = model.CapInternalServiceAccess
	}
	bootstrapHypothesis, _ := hypotheses.FormHypothesis(ctx, HypothesisDraft{
		TaskID:                task.ID,
		HypothesisType:        model.HypothesisTypeInfoDisclosureCandidate,
		Title:                 "Authorized task surface can yield security-relevant observations",
		Description:           "Validate the initial authorized surface to collect evidence-backed observations that can form more precise security hypotheses.",
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: []string{fmt.Sprintf("node:%d", originNode.ID)},
		TargetEntity:          "authorized task origin",
		ExpectedCapability:    expectedCapability,
	})
	initialIntent := model.AIIntent{
		TaskID:           task.ID,
		IntentType:       initialIntentType(taskType),
		Title:            "启动授权安全验证",
		Objective:        "Collect first-layer facts and evidence from the authorized task origin.",
		ConstraintsJSON:  mustJSON(map[string]any{"policy": policy.NetworkPolicy, "evidenceProofPolicy": "non_destructive_authorized_scope"}),
		RequiredEvidence: mustJSON([]string{"baseline_evidence", "scope_statement", "safety_statement"}),
		PriorityScore:    1.0,
		Status:           model.IntentStatusPending,
		CreatedBy:        "system",
		CreatedReason:    "initial task bootstrap",
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	if bootstrapHypothesis.ID != 0 {
		initialIntent.WithValidationMetadata(model.ValidationIntentMetadata{
			HypothesisID:       &bootstrapHypothesis.ID,
			ValidationMethod:   "bootstrap_surface_observation",
			ExpectedEvidence:   "first-layer authorized observations and evidence",
			ExpectedCapability: expectedCapability,
			SuccessCondition:   "Runner produces evidence that expands the graph from the task origin.",
			FailureCondition:   "Runner cannot collect useful observations from the authorized surface.",
			SafetyLevel:        "authorized_non_destructive",
		})
	}
	if err := s.db.WithContext(ctx).Create(&initialIntent).Error; err != nil {
		return task, err
	}
	if bootstrapHypothesis.ID != 0 {
		_ = hypotheses.appendHypothesisIntentRef(ctx, bootstrapHypothesis.ID, initialIntent.ID)
		intentNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          task.ID,
			NodeType:        model.NodeIntent,
			Title:           initialIntent.Title,
			Summary:         initialIntent.Objective,
			Content:         initialIntent,
			DedupSeed:       fmt.Sprintf("intent-%d", initialIntent.ID),
			ImportanceScore: 1.0,
			SourceType:      initialIntent.CreatedBy,
			SourceID:        fmt.Sprintf("%d", initialIntent.ID),
		})
		hypothesisNode, _ := s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          task.ID,
			NodeType:        model.NodeHypothesis,
			Title:           bootstrapHypothesis.Title,
			Summary:         bootstrapHypothesis.Description,
			Content:         bootstrapHypothesis,
			DedupSeed:       fmt.Sprintf("hypothesis-%d", bootstrapHypothesis.ID),
			ImportanceScore: 0.78,
			SourceType:      "hypothesis-lifecycle",
			SourceID:        fmt.Sprintf("%d", bootstrapHypothesis.ID),
		})
		if hypothesisNode.ID != 0 && intentNode.ID != 0 {
			_ = s.blackboard.AddEdge(ctx, task.ID, hypothesisNode.ID, intentNode.ID, model.EdgeGenerates, 0.86, map[string]any{"hypothesisId": bootstrapHypothesis.ID, "intentId": initialIntent.ID})
		}
	}
	appendAuditEvent(ctx, s.db, &task.ID, "task.created", "user", "Task created with authorized scope.", map[string]any{"taskType": taskType})
	return task, nil
}

func (s *TaskService) defaultModelConfigID(ctx context.Context) (*uint, error) {
	var config model.AIModelConfig
	err := s.db.WithContext(ctx).
		Where("enabled = ? AND lower(name) NOT LIKE ? AND (purpose = ? OR purpose = '')", true, "%fallback%", model.ModelPurposeBrain).
		Order("id asc").
		First(&config).Error
	if err == nil {
		id := config.ID
		return &id, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}
	err = s.db.WithContext(ctx).
		Where("enabled = ? AND (purpose = ? OR purpose = '')", true, model.ModelPurposeBrain).
		Order("id asc").
		First(&config).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	id := config.ID
	return &id, nil
}

func (s *TaskService) UploadZip(ctx context.Context, taskID uint, fileName string, reader io.Reader) (runner.ExtractManifest, error) {
	var task model.AISecurityTask
	if err := s.db.WithContext(ctx).First(&task, taskID).Error; err != nil {
		return runner.ExtractManifest{}, err
	}
	previousStage := task.ProgressStage
	if task.TaskType != model.TaskTypeCodeAudit && task.TaskType != model.TaskTypeHybrid {
		return runner.ExtractManifest{}, fmt.Errorf("zip upload is only available for code audit or hybrid tasks")
	}
	zipPath, err := s.workspace.SaveUpload(ctx, taskID, fileName, reader)
	if err != nil {
		return runner.ExtractManifest{}, err
	}
	manifest, err := s.workspace.ExtractZip(ctx, taskID, zipPath, runner.DefaultExtractLimits())
	if err != nil {
		return manifest, err
	}
	_, err = s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        "fact",
		Title:           "Source archive extracted safely",
		Summary:         fmt.Sprintf("%d files extracted into isolated workspace; %d entries skipped.", len(manifest.Files), len(manifest.Skipped)),
		Content:         manifest,
		DedupSeed:       "source-extracted-" + filepath.Base(zipPath),
		ImportanceScore: 0.9,
		SourceType:      "system",
		SourceID:        "workspace",
	})
	if err != nil {
		return manifest, err
	}
	task.ProgressStage = "代码已上传，等待审计"
	task.ProgressPercent = 12
	if task.Status == model.TaskStatusFailed && strings.Contains(previousStage, "source archive has not been uploaded") {
		task.Status = model.TaskStatusPending
		task.FinishedAt = nil
		task.StartedAt = nil
		intent := model.AIIntent{
			TaskID:           task.ID,
			IntentType:       initialIntentType(task.TaskType),
			Title:            "上传代码后重新启动授权安全验证",
			Objective:        "Collect first-layer facts and evidence from the uploaded source archive.",
			ConstraintsJSON:  mustJSON(map[string]any{"sourceUploaded": true}),
			RequiredEvidence: mustJSON([]string{"baseline_evidence", "scope_statement", "safety_statement"}),
			PriorityScore:    1.0,
			Status:           model.IntentStatusPending,
			CreatedBy:        "system",
			CreatedReason:    "source archive uploaded after an earlier fail-closed start",
			CreatedAt:        time.Now().UTC(),
			UpdatedAt:        time.Now().UTC(),
		}
		_ = s.db.WithContext(ctx).Create(&intent).Error
	}
	if err := s.db.WithContext(ctx).Save(&task).Error; err != nil {
		return manifest, err
	}
	appendAuditEvent(ctx, s.db, &task.ID, "workspace.zip_extracted", "system", "ZIP extracted with traversal and size checks.", manifest)
	return manifest, nil
}

func (s *TaskService) List(ctx context.Context, includeTests bool) ([]model.AISecurityTask, error) {
	var tasks []model.AISecurityTask
	query := s.db.WithContext(ctx).Order("created_at desc")
	if !includeTests {
		query = query.Where("is_test_task = ?", false)
	}
	err := query.Find(&tasks).Error
	return tasks, err
}

func (s *TaskService) Get(ctx context.Context, id uint) (model.AISecurityTask, error) {
	var task model.AISecurityTask
	if err := s.db.WithContext(ctx).First(&task, id).Error; err != nil {
		return task, err
	}
	return task, nil
}

func (s *TaskService) Timeline(ctx context.Context, taskID uint) ([]model.AIAuditEvent, error) {
	var events []model.AIAuditEvent
	err := s.db.WithContext(ctx).Where("task_id = ? OR task_id IS NULL", taskID).Order("occurred_at desc").Limit(100).Find(&events).Error
	return events, err
}

func inferTargetType(target string, taskType string) string {
	if taskType == model.TaskTypeCodeAudit {
		return "repo"
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return "url"
	}
	if strings.Contains(target, "/") {
		return "cidr"
	}
	return "domain"
}

func initialIntentType(taskType string) string {
	if taskType == model.TaskTypeCodeAudit {
		return "code_trace"
	}
	if taskType == model.TaskTypePentest {
		return "recon"
	}
	return "recon"
}
