package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"shenji/backend/internal/model"
	"shenji/backend/internal/service"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Handler struct {
	services *service.Services
}

func NewHandler(services *service.Services) *Handler {
	return &Handler{services: services}
}

func (h *Handler) Overview(c *gin.Context) {
	ctx := c.Request.Context()
	var total, running, incompleteContracts, high int64
	h.services.DB.WithContext(ctx).Model(&model.AISecurityTask{}).Where("is_test_task = ?", false).Count(&total)
	h.services.DB.WithContext(ctx).Model(&model.AISecurityTask{}).Where("is_test_task = ? AND status = ?", false, model.TaskStatusRunning).Count(&running)
	taskScope := h.services.DB.WithContext(ctx).Model(&model.AISecurityTask{}).Select("id").Where("is_test_task = ?", false)
	h.services.DB.WithContext(ctx).Model(&model.AIFinding{}).Where("contract_status = ? AND task_id IN (?)", model.ContractStatusIncomplete, taskScope).Count(&incompleteContracts)
	h.services.DB.WithContext(ctx).Model(&model.AIFinding{}).Where("severity IN ? AND task_id IN (?)", []string{"critical", "high"}, taskScope).Count(&high)
	var recent []model.AISecurityTask
	h.services.DB.WithContext(ctx).Where("is_test_task = ?", false).Order("created_at desc").Limit(6).Find(&recent)
	c.JSON(http.StatusOK, gin.H{
		"totalTasks":       total,
		"runningTasks":     running,
		"pendingReviews":   incompleteContracts,
		"highRiskFindings": high,
		"recentTasks":      recent,
		"runnerHealth": gin.H{
			"codeAudit": "ready",
			"browser":   "planned",
			"pentest":   "ready",
			"sandbox":   "ready",
		},
	})
}

func (h *Handler) Tools(c *gin.Context) {
	c.JSON(http.StatusOK, h.services.Registry.List())
}

func (h *Handler) ListModelConfigs(c *gin.Context) {
	configs, err := h.services.ModelConfig.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, configs)
}

func (h *Handler) CreateModelConfig(c *gin.Context) {
	var input service.ModelConfigUpsertInput
	if err := c.ShouldBindJSON(&input); err != nil {
		writeBadRequest(c, err)
		return
	}
	config, err := h.services.ModelConfig.Create(c.Request.Context(), input)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, config)
}

func (h *Handler) UpdateModelConfig(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	var input service.ModelConfigUpsertInput
	if err := c.ShouldBindJSON(&input); err != nil {
		writeBadRequest(c, err)
		return
	}
	config, err := h.services.ModelConfig.Update(c.Request.Context(), id, input)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, config)
}

func (h *Handler) ListTasks(c *gin.Context) {
	includeTests := strings.EqualFold(c.Query("include_tests"), "true")
	tasks, err := h.services.Task.List(c.Request.Context(), includeTests)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (h *Handler) CreateTask(c *gin.Context) {
	var input service.CreateTaskInput
	if err := c.ShouldBindJSON(&input); err != nil {
		writeBadRequest(c, err)
		return
	}
	task, err := h.services.Task.Create(c.Request.Context(), input)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, task)
}

func (h *Handler) GetTask(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	task, err := h.services.Task.Get(ctx, id)
	if err != nil {
		writeError(c, err)
		return
	}
	toolRuns, _ := h.services.ToolRun.ListByTask(ctx, id)
	evidence, _ := h.services.Evidence.ListByTask(ctx, id)
	findings, _ := h.services.Finding.ListByTask(ctx, id)
	reports, _ := h.services.Report.ListByTask(ctx, id)
	intents, _ := h.services.Intent.ListByTask(ctx, id)
	contractChecks, _ := h.services.Contract.ListByTask(ctx, id)
	timeline, _ := h.services.Task.Timeline(ctx, id)
	nodes, _ := h.services.Blackboard.RecentNodes(ctx, id, 30)
	c.JSON(http.StatusOK, gin.H{
		"task":           task,
		"toolRuns":       toolRuns,
		"evidence":       evidence,
		"findings":       findings,
		"reports":        reports,
		"intents":        intents,
		"contractChecks": contractChecks,
		"timeline":       timeline,
		"blackboard":     nodes,
		"toolCatalog":    h.services.Registry.List(),
	})
}

func (h *Handler) StartTask(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	task, err := h.services.Task.Get(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	if task.TaskType == model.TaskTypeCodeAudit || task.TaskType == model.TaskTypeHybrid {
		extracted := filepath.Join(h.services.Config.WorkspaceRoot, "task-"+strconv.FormatUint(uint64(id), 10), "input", "extracted")
		entries, readErr := os.ReadDir(extracted)
		if readErr != nil || len(entries) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请先上传代码 ZIP，再启动代码审计任务"})
			return
		}
	}
	h.services.Orchestrator.StartAsync(id)
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "taskId": id})
}

func (h *Handler) UploadZip(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	file, err := c.FormFile("file")
	if err != nil {
		writeBadRequest(c, err)
		return
	}
	src, err := file.Open()
	if err != nil {
		writeBadRequest(c, err)
		return
	}
	defer src.Close()
	manifest, err := h.services.Task.UploadZip(c.Request.Context(), id, file.Filename, src)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, manifest)
}

func (h *Handler) TaskTimeline(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	events, err := h.services.Task.Timeline(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, events)
}

func (h *Handler) TaskToolRuns(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	runs, err := h.services.ToolRun.ListByTask(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, runs)
}

func (h *Handler) TaskEvidence(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	evidence, err := h.services.Evidence.ListByTask(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, evidence)
}

func (h *Handler) TaskFindings(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	findings, err := h.services.Finding.ListByTask(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, findings)
}

func (h *Handler) ListFindings(c *gin.Context) {
	ctx := c.Request.Context()
	var findings []model.AIFinding
	if err := h.services.DB.WithContext(ctx).Order("created_at desc").Find(&findings).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, findings)
}

func (h *Handler) GetFinding(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var finding model.AIFinding
	if err := h.services.DB.WithContext(ctx).First(&finding, id).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, finding)
}

func (h *Handler) TaskReports(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	reports, err := h.services.Report.ListByTask(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, reports)
}

func (h *Handler) ListReports(c *gin.Context) {
	ctx := c.Request.Context()
	var reports []model.AIReport
	if err := h.services.DB.WithContext(ctx).Order("generated_at desc, id desc").Find(&reports).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, reports)
}

func (h *Handler) RegenerateTaskReport(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	report, err := h.services.Report.Generate(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, report)
}

func parseID(c *gin.Context, name string) (uint, bool) {
	raw := c.Param(name)
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 {
		writeBadRequest(c, errors.New("invalid id"))
		return 0, false
	}
	return uint(value), true
}

func writeBadRequest(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

func writeError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

func normalizeUserRole(role string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "", "admin":
		return "admin", nil
	case "viewer":
		return "viewer", nil
	default:
		return "", fmt.Errorf("用户角色只能是 admin 或 viewer")
	}
}

// ==================== Auth Handlers ====================

func (h *Handler) Login(c *gin.Context) {
	var input service.LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		writeBadRequest(c, err)
		return
	}
	token, err := h.services.Auth.Login(c.Request.Context(), input)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, token)
}

func (h *Handler) GetCurrentUser(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	user, err := h.services.Auth.GetCurrentUser(c.Request.Context(), userID.(uint))
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *Handler) ChangePassword(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	var input service.ChangePasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		writeBadRequest(c, err)
		return
	}
	if err := h.services.Auth.ChangePassword(c.Request.Context(), userID.(uint), input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "密码修改成功"})
}

// ==================== Chat Handler ====================

func (h *Handler) Chat(c *gin.Context) {
	var req service.ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeBadRequest(c, err)
		return
	}
	if len(req.Messages) == 0 {
		writeBadRequest(c, errors.New("messages cannot be empty"))
		return
	}
	resp, err := h.services.Chat.Chat(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ==================== Task Delete ====================

func (h *Handler) DeleteTask(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var task model.AISecurityTask
	if err := h.services.DB.WithContext(ctx).First(&task, id).Error; err != nil {
		writeError(c, err)
		return
	}
	if task.Status == model.TaskStatusRunning {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能删除正在执行的任务"})
		return
	}
	if err := h.services.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		deletes := []struct {
			name  string
			model any
			query string
			args  []any
		}{
			{"model_call_logs", &model.AIModelCallLog{}, "task_id = ?", []any{id}},
			{"contract_checks", &model.AIContractCheckResult{}, "task_id = ?", []any{id}},
			{"findings", &model.AIFinding{}, "task_id = ?", []any{id}},
			{"capabilities", &model.AICapability{}, "task_id = ?", []any{id}},
			{"evidence", &model.AIEvidence{}, "task_id = ?", []any{id}},
			{"tool_runs", &model.AIToolRun{}, "task_id = ?", []any{id}},
			{"intents", &model.AIIntent{}, "task_id = ?", []any{id}},
			{"blackboard_edges", &model.AIBlackboardEdge{}, "task_id = ?", []any{id}},
			{"blackboard_nodes", &model.AIBlackboardNode{}, "task_id = ?", []any{id}},
			{"agent_loop_iterations", &model.AIAgentLoopIteration{}, "task_id = ?", []any{id}},
			{"agent_loops", &model.AIAgentLoop{}, "task_id = ?", []any{id}},
			{"reports", &model.AIReport{}, "task_id = ?", []any{id}},
			{"human_reviews", &model.AIHumanReview{}, "task_id = ?", []any{id}},
			{"task_targets", &model.AITaskTarget{}, "task_id = ?", []any{id}},
			{"goal_profiles", &model.AIGoalProfile{}, "task_id = ?", []any{id}},
			{"hypotheses", &model.AIHypothesisNode{}, "task_id = ?", []any{id}},
			{"negative_facts", &model.AINegativeFact{}, "task_id = ?", []any{id}},
			{"unverified_risks", &model.AIUnverifiedRisk{}, "task_id = ?", []any{id}},
			{"coverage_items", &model.AICoverageItem{}, "task_id = ?", []any{id}},
			{"environment_models", &model.AIEnvironmentModel{}, "task_id = ?", []any{id}},
			{"objective_ladders", &model.AIObjectiveLadder{}, "task_id = ?", []any{id}},
			{"audit_events", &model.AIAuditEvent{}, "task_id = ?", []any{id}},
		}
		for _, item := range deletes {
			if err := tx.Where(item.query, item.args...).Delete(item.model).Error; err != nil {
				return fmt.Errorf("delete %s: %w", item.name, err)
			}
		}
		if err := tx.Delete(&task).Error; err != nil {
			return err
		}
		var remaining int64
		if err := tx.Model(&model.AISecurityTask{}).Where("workspace_id = ?", task.WorkspaceID).Count(&remaining).Error; err != nil {
			return err
		}
		if remaining == 0 {
			if err := tx.Delete(&model.AIWorkspace{}, task.WorkspaceID).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		writeError(c, err)
		return
	}
	if h.services.Store != nil {
		if err := h.services.Store.DeletePrefix(ctx, fmt.Sprintf("task-%d/", id)); err != nil {
			writeError(c, fmt.Errorf("delete task artifacts: %w", err))
			return
		}
	}
	_ = os.RemoveAll(filepath.Join(h.services.Config.WorkspaceRoot, fmt.Sprintf("task-%d", id)))
	_ = os.RemoveAll(filepath.Join(h.services.Config.ArtifactRoot, fmt.Sprintf("task-%d", id)))
	_ = os.RemoveAll(filepath.Join(h.services.Config.ArtifactRoot, "rabbit-artifacts", fmt.Sprintf("task-%d", id)))
	c.JSON(http.StatusOK, gin.H{"message": "任务已删除", "taskId": id})
}

// ==================== Task Restart ====================

func (h *Handler) RestartTask(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var task model.AISecurityTask
	if err := h.services.DB.WithContext(ctx).First(&task, id).Error; err != nil {
		writeError(c, err)
		return
	}
	if task.Status == model.TaskStatusRunning {
		c.JSON(http.StatusBadRequest, gin.H{"error": "任务正在执行中"})
		return
	}
	// Reset task status
	task.Status = model.TaskStatusPending
	task.ProgressStage = "等待重新启动"
	task.ProgressPercent = 0
	task.StartedAt = nil
	task.FinishedAt = nil
	if err := h.services.DB.WithContext(ctx).Save(&task).Error; err != nil {
		writeError(c, err)
		return
	}
	// Start the task
	h.services.Orchestrator.StartAsync(task.ID)
	c.JSON(http.StatusOK, gin.H{"message": "任务已重新启动", "taskId": id})
}

// ==================== User Management ====================

func (h *Handler) ListUsers(c *gin.Context) {
	ctx := c.Request.Context()
	var users []model.AIUser
	if err := h.services.DB.WithContext(ctx).Order("id asc").Find(&users).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

func (h *Handler) CreateUser(c *gin.Context) {
	var input struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"displayName"`
		Role        string `json:"role"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeBadRequest(c, err)
		return
	}
	if strings.TrimSpace(input.Username) == "" || strings.TrimSpace(input.Password) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名和密码不能为空"})
		return
	}
	if len(input.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密码长度不能少于6位"})
		return
	}
	// Check duplicate
	var count int64
	h.services.DB.WithContext(c.Request.Context()).Model(&model.AIUser{}).Where("username = ?", input.Username).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名已存在"})
		return
	}
	hash, err := bcryptHash(input.Password)
	if err != nil {
		writeError(c, err)
		return
	}
	role, err := normalizeUserRole(input.Role)
	if err != nil {
		writeBadRequest(c, err)
		return
	}
	user := model.AIUser{
		Username:     strings.TrimSpace(input.Username),
		PasswordHash: hash,
		DisplayName:  strings.TrimSpace(input.DisplayName),
		Role:         role,
		Enabled:      true,
	}
	if err := h.services.DB.WithContext(c.Request.Context()).Create(&user).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *Handler) UpdateUser(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	var input struct {
		DisplayName *string `json:"displayName"`
		Role        *string `json:"role"`
		Enabled     *bool   `json:"enabled"`
		Password    *string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeBadRequest(c, err)
		return
	}
	ctx := c.Request.Context()
	var user model.AIUser
	if err := h.services.DB.WithContext(ctx).First(&user, id).Error; err != nil {
		writeError(c, err)
		return
	}
	if input.DisplayName != nil {
		user.DisplayName = *input.DisplayName
	}
	if input.Role != nil {
		role, err := normalizeUserRole(*input.Role)
		if err != nil {
			writeBadRequest(c, err)
			return
		}
		user.Role = role
	}
	if input.Enabled != nil {
		user.Enabled = *input.Enabled
	}
	if input.Password != nil && *input.Password != "" {
		if len(*input.Password) < 6 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "密码长度不能少于6位"})
			return
		}
		hash, err := bcryptHash(*input.Password)
		if err != nil {
			writeError(c, err)
			return
		}
		user.PasswordHash = hash
	}
	if err := h.services.DB.WithContext(ctx).Save(&user).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, user)
}

// ==================== Audit Log ====================

func (h *Handler) ListAuditEvents(c *gin.Context) {
	ctx := c.Request.Context()
	var events []model.AIAuditEvent
	query := h.services.DB.WithContext(ctx).Order("occurred_at desc").Limit(200)
	if taskID := c.Query("taskId"); taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if eventType := c.Query("eventType"); eventType != "" {
		query = query.Where("event_type LIKE ?", "%"+eventType+"%")
	}
	if err := query.Find(&events).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, events)
}

func bcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ==================== Data Export ====================

func (h *Handler) ExportFindings(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var findings []model.AIFinding
	if err := h.services.DB.WithContext(ctx).Where("task_id = ?", id).Order("severity asc, created_at desc").Find(&findings).Error; err != nil {
		writeError(c, err)
		return
	}
	format := c.DefaultQuery("format", "json")
	if format == "csv" {
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", "attachment; filename=findings.csv")
		c.Writer.WriteString("\xEF\xBB\xBF") // UTF-8 BOM
		c.Writer.WriteString("ID,标题,漏洞类型,严重程度,状态,验证状态,Contract状态,影响目标,影响组件,创建时间\n")
		for _, f := range findings {
			line := fmt.Sprintf("%d,\"%s\",\"%s\",%s,%s,%s,%s,\"%s\",\"%s\",%s\n",
				f.ID, csvEscape(f.Title), csvEscape(f.VulnerabilityType), f.Severity, f.Status, f.ValidationStatus, f.ContractStatus, csvEscape(f.AffectedTarget), csvEscape(f.AffectedComponent), f.CreatedAt.Format("2006-01-02 15:04:05"))
			c.Writer.WriteString(line)
		}
		return
	}
	c.JSON(http.StatusOK, findings)
}

func (h *Handler) ExportEvidence(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var evidence []model.AIEvidence
	if err := h.services.DB.WithContext(ctx).Where("task_id = ?", id).Order("created_at desc").Find(&evidence).Error; err != nil {
		writeError(c, err)
		return
	}
	format := c.DefaultQuery("format", "json")
	if format == "csv" {
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", "attachment; filename=evidence.csv")
		c.Writer.WriteString("\xEF\xBB\xBF")
		c.Writer.WriteString("ID,类型,关系类型,标题,文件路径,行号,目标,创建时间\n")
		for _, e := range evidence {
			lineStart := ""
			if e.LineStart != nil {
				lineStart = strconv.Itoa(*e.LineStart)
			}
			line := fmt.Sprintf("%d,\"%s\",\"%s\",\"%s\",\"%s\",%s,\"%s\",%s\n",
				e.ID, e.EvidenceType, e.RelationType, csvEscape(e.Title), csvEscape(e.FilePath), lineStart, csvEscape(e.Target), e.CreatedAt.Format("2006-01-02 15:04:05"))
			c.Writer.WriteString(line)
		}
		return
	}
	c.JSON(http.StatusOK, evidence)
}

func csvEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\"", "\"\""), "\n", " ")
}

// ==================== Model Connection Test ====================

func (h *Handler) TestModelConfig(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var config model.AIModelConfig
	if err := h.services.DB.WithContext(ctx).First(&config, id).Error; err != nil {
		writeError(c, err)
		return
	}
	result := h.services.Chat.TestConnection(ctx, config)
	c.JSON(http.StatusOK, result)
}

// ==================== Model Call Logs ====================

func (h *Handler) ListModelCallLogs(c *gin.Context) {
	ctx := c.Request.Context()
	var logs []model.AIModelCallLog
	query := h.services.DB.WithContext(ctx).Order("called_at desc").Limit(200)
	if taskID := c.Query("taskId"); taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if purpose := c.Query("purpose"); purpose != "" {
		query = query.Where("purpose = ?", purpose)
	}
	if modelName := c.Query("model"); modelName != "" {
		query = query.Where("model_name = ?", modelName)
	}
	if err := query.Find(&logs).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, logs)
}

// ==================== Capability API ====================

func (h *Handler) TaskCapabilities(c *gin.Context) {
	id, ok := parseID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var caps []model.AICapability
	if err := h.services.DB.WithContext(ctx).Where("task_id = ?", id).Order("created_at desc").Find(&caps).Error; err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, caps)
}
