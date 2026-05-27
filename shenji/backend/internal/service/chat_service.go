package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type ChatService struct {
	db     *gorm.DB
	client *http.Client
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Messages []ChatMessage `json:"messages"`
	TaskID   *uint         `json:"taskId,omitempty"`
}

type ChatResponse struct {
	Reply   string `json:"reply"`
	ModelID string `json:"modelId"`
}

type ConnectionTestResult struct {
	Success   bool   `json:"success"`
	LatencyMs int64  `json:"latencyMs"`
	Model     string `json:"model"`
	Message   string `json:"message"`
}

func NewChatService(db *gorm.DB) *ChatService {
	return &ChatService{
		db:     db,
		client: &http.Client{Timeout: 300 * time.Second},
	}
}

func (s *ChatService) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	// Load model config
	config, err := s.loadActiveModelConfig(ctx)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("没有可用的模型配置: %v", err)
	}

	// Build system prompt
	systemPrompt := s.buildSystemPrompt(ctx, req.TaskID)

	// Build messages for the model - limit history to last 10 messages to avoid token overflow
	messages := []map[string]string{
		{"role": "system", "content": systemPrompt},
	}
	historyMessages := req.Messages
	if len(historyMessages) > 10 {
		historyMessages = historyMessages[len(historyMessages)-10:]
	}
	for _, msg := range historyMessages {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	// Call model
	start := time.Now()
	reply, err := s.callModel(ctx, config, messages)
	latency := time.Since(start).Milliseconds()

	// Log the call
	status := "success"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	promptTokens := 0
	for _, m := range messages {
		promptTokens += len(m["content"]) / 4 // rough estimate
	}
	compTokens := 0
	if reply != "" {
		compTokens = len(reply) / 4
	}
	_ = s.db.Create(&model.AIModelCallLog{
		TaskID:       req.TaskID,
		ModelName:    config.Model,
		Provider:     config.Provider,
		Purpose:      "chat",
		Status:       status,
		LatencyMs:    latency,
		PromptTokens: promptTokens,
		CompTokens:   compTokens,
		ErrorMessage: errMsg,
		CalledAt:     time.Now().UTC(),
	}).Error

	if err != nil {
		return ChatResponse{}, err
	}

	return ChatResponse{
		Reply:   reply,
		ModelID: config.Model,
	}, nil
}

func (s *ChatService) buildSystemPrompt(ctx context.Context, taskID *uint) string {
	base := `你是 Rabbit AI 安全验证平台的智能助手。你精通网络安全、渗透测试、代码审计、漏洞分析。
你的职责是帮助用户理解安全验证结果、解释漏洞原理、提供修复建议、回答安全相关问题。
回答要专业、简洁、有条理。如果涉及具体漏洞，请给出详细的技术分析。`

	if taskID == nil {
		return base
	}

	// Load task context
	var task model.AISecurityTask
	if err := s.db.WithContext(ctx).First(&task, *taskID).Error; err != nil {
		return base
	}

	var findings []model.AIFinding
	_ = s.db.WithContext(ctx).Where("task_id = ?", *taskID).Limit(10).Find(&findings).Error

	var evidence []model.AIEvidence
	_ = s.db.WithContext(ctx).Where("task_id = ?", *taskID).Order("created_at desc").Limit(20).Find(&evidence).Error

	// Build context
	var ctx_parts []string
	ctx_parts = append(ctx_parts, fmt.Sprintf("\n\n当前任务上下文：\n- 任务名称: %s\n- 任务类型: %s\n- 状态: %s\n- 目标: %s",
		task.Name, task.TaskType, task.Status, task.Objective))

	if len(findings) > 0 {
		ctx_parts = append(ctx_parts, fmt.Sprintf("\n- 已发现 %d 个漏洞:", len(findings)))
		for i, f := range findings {
			if i >= 5 {
				ctx_parts = append(ctx_parts, fmt.Sprintf("  ... 还有 %d 个", len(findings)-5))
				break
			}
			ctx_parts = append(ctx_parts, fmt.Sprintf("  %d. [%s] %s (%s)", i+1, f.Severity, f.Title, f.Status))
		}
	}

	if len(evidence) > 0 {
		ctx_parts = append(ctx_parts, fmt.Sprintf("\n- 已收集 %d 条证据", len(evidence)))
	}

	return base + strings.Join(ctx_parts, "")
}

func (s *ChatService) loadActiveModelConfig(ctx context.Context) (model.AIModelConfig, error) {
	var config model.AIModelConfig
	err := s.db.WithContext(ctx).
		Where("enabled = ? AND (purpose = ? OR purpose = '')", true, model.ModelPurposeBrain).
		Order("id asc").
		First(&config).Error
	return config, err
}

func (s *ChatService) callModel(ctx context.Context, config model.AIModelConfig, messages []map[string]string) (string, error) {
	var options modelRuntimeOptions
	_ = unmarshalJSON(config.OptionsJSON, &options)
	apiKey, err := resolveModelSecret(config.APIKeyRef, options.RequiresOpenAIAuth)
	if err != nil {
		return "", err
	}

	// Determine endpoint
	baseURL := strings.TrimRight(config.BaseURL, "/")
	if !strings.HasSuffix(baseURL, "/v1") {
		baseURL = baseURL + "/v1"
	}
	endpoint := baseURL + "/chat/completions"

	// Build request body
	reqBody := map[string]any{
		"model":    config.Model,
		"messages": messages,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	applyCustomHeaders(req, options.CustomHeaders)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("模型调用失败: %v", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("模型返回错误 %d: %s", resp.StatusCode, string(payload[:min(len(payload), 200)]))
	}

	// Parse response
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return "", fmt.Errorf("模型响应解析失败: %v", err)
	}
	if len(result.Choices) == 0 || result.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("模型返回空内容")
	}

	return result.Choices[0].Message.Content, nil
}

// TestConnection sends a minimal request to verify the model API is reachable.
func (s *ChatService) TestConnection(ctx context.Context, config model.AIModelConfig) ConnectionTestResult {
	start := time.Now()
	var options modelRuntimeOptions
	_ = unmarshalJSON(config.OptionsJSON, &options)
	apiKey, err := resolveModelSecret(config.APIKeyRef, options.RequiresOpenAIAuth)
	if err != nil {
		return ConnectionTestResult{Success: false, Model: config.Model, Message: "API Key 解析失败: " + err.Error()}
	}

	messages := []map[string]string{
		{"role": "user", "content": "ping"},
	}

	baseURL := strings.TrimRight(config.BaseURL, "/")
	if !strings.HasSuffix(baseURL, "/v1") {
		baseURL = baseURL + "/v1"
	}
	endpoint := baseURL + "/chat/completions"

	reqBody := map[string]any{
		"model":      config.Model,
		"messages":   messages,
		"max_tokens": 5,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return ConnectionTestResult{Success: false, Model: config.Model, Message: "请求构建失败: " + err.Error()}
	}

	testCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(testCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ConnectionTestResult{Success: false, Model: config.Model, Message: "请求创建失败: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	applyCustomHeaders(req, options.CustomHeaders)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := s.client.Do(req)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return ConnectionTestResult{Success: false, LatencyMs: latency, Model: config.Model, Message: "连接失败: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		payload, _ := io.ReadAll(resp.Body)
		msg := fmt.Sprintf("模型返回 HTTP %d", resp.StatusCode)
		if len(payload) > 0 && len(payload) < 200 {
			msg += ": " + string(payload)
		}
		return ConnectionTestResult{Success: false, LatencyMs: latency, Model: config.Model, Message: msg}
	}

	return ConnectionTestResult{
		Success:   true,
		LatencyMs: latency,
		Model:     config.Model,
		Message:   fmt.Sprintf("连接成功，延迟 %dms", latency),
	}
}
