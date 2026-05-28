package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type ModelRuntimeService struct {
	db     *gorm.DB
	client *http.Client
}

type IterationPlan struct {
	ModelProvider  string
	ModelName      string
	ThoughtSummary string
	PlannedAction  string
	NextIntents    []SecurityGraphIntentSuggestion
}

type ModelCallMetadata struct {
	Provider   string
	Model      string
	IntentType string
	LatencyMs  int64
}

type WorkerRuntimeSelection struct {
	Config     model.AIModelConfig
	WorkerID   string
	TaskTypes  []string
	Priority   int
	MaxRunning int
	Running    int64
}

const defaultExternalWorkerMaxRunning = 2

type EvidenceIntentSuggestion struct {
	Title      string
	Objective  string
	IntentType string
}

type ReportNarrative struct {
	ExecutiveSummary  string
	FindingNarratives map[uint]string
}

type CodeAuditSnippet struct {
	EvidenceID uint
	FilePath   string
	LineStart  int
	LineEnd    int
	Summary    string
	Content    string
}

type SecurityGraphNode struct {
	ID           uint   `json:"id"`
	NodeType     string `json:"node_type"`
	Title        string `json:"title"`
	Summary      string `json:"summary"`
	SourceType   string `json:"source_type"`
	EvidenceRefs []uint `json:"evidence_refs"`
}

type SecurityGraphEdge struct {
	FromID   uint    `json:"from_id"`
	ToID     uint    `json:"to_id"`
	EdgeType string  `json:"edge_type"`
	Weight   float64 `json:"weight"`
}

type SecurityGraphIntent struct {
	ID        uint   `json:"id"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Objective string `json:"objective"`
}

type SecurityGraphFactSuggestion struct {
	NodeType string `json:"node_type"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
}

type SecurityGraphIntentSuggestion struct {
	Title            string   `json:"title"`
	Objective        string   `json:"objective"`
	IntentType       string   `json:"intent_type"`
	RequiredEvidence []string `json:"required_evidence"`
	SourceNodeIDs    []uint   `json:"source_node_ids"`
	Hypothesis       string   `json:"hypothesis"`
	SuccessCriteria  string   `json:"success_criteria"`
	FailureCriteria  string   `json:"failure_criteria"`
	AllowedTools     []string `json:"allowed_tools"`
	RiskLevel        string   `json:"risk_level"`
	Priority         int      `json:"priority"`
}

type SecurityGraphAuditPacket struct {
	CurrentIntent SecurityGraphIntent `json:"current_intent"`
	Nodes         []SecurityGraphNode `json:"nodes"`
	Edges         []SecurityGraphEdge `json:"edges"`
	Snippets      []CodeAuditSnippet  `json:"snippets"`
}

type SecurityGraphDecision struct {
	Facts       []SecurityGraphFactSuggestion   `json:"facts"`
	NextIntents []SecurityGraphIntentSuggestion `json:"next_intents"`
	StopReason  string                          `json:"stop_reason"`
}

type modelRuntimeOptions struct {
	ReviewModel                 string         `json:"reviewModel"`
	ModelReasoningEffort        string         `json:"modelReasoningEffort"`
	DisableResponseStorage      bool           `json:"disableResponseStorage"`
	NetworkAccess               string         `json:"networkAccess"`
	WindowsWslSetupAcknowledged bool           `json:"windowsWslSetupAcknowledged"`
	ModelContextWindow          int            `json:"modelContextWindow"`
	ModelAutoCompactTokenLimit  int            `json:"modelAutoCompactTokenLimit"`
	WireAPI                     string         `json:"wireApi"`
	RequiresOpenAIAuth          bool           `json:"requiresOpenAIAuth"`
	CustomHeaders               map[string]any `json:"customHeaders"`
	WorkerDriver                string         `json:"workerDriver"`
	WorkerTools                 []string       `json:"workerTools"`
	WorkerTaskTypes             []string       `json:"workerTaskTypes"`
	WorkerPriority              int            `json:"workerPriority"`
	WorkerMaxRunning            int            `json:"workerMaxRunning"`
}

func NewModelRuntimeService(db *gorm.DB, timeout time.Duration) *ModelRuntimeService {
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	return &ModelRuntimeService{
		db:     db,
		client: &http.Client{Timeout: timeout},
	}
}

func (s *ModelRuntimeService) PlanIteration(ctx context.Context, task model.AISecurityTask, intent *model.AIIntent, agentContext AgentContext) (IterationPlan, error) {
	if task.ModelConfigID == nil {
		return deterministicIterationPlan(task, intent), nil
	}

	config, options, err := s.loadConfig(ctx, *task.ModelConfigID)
	if err != nil {
		return IterationPlan{}, err
	}

	start := time.Now()
	provider := normalizeModelProvider(config.Provider)
	var plan IterationPlan
	switch provider {
	case "openai", "openai-compatible":
		plan, err = s.planWithOpenAI(ctx, config, options, task, intent, agentContext)
	default:
		err = fmt.Errorf("unsupported model provider: %s", config.Provider)
	}
	s.logModelCall(ctx, &task.ID, config.Model, config.Provider, "plan", start, err)
	if err != nil {
		return IterationPlan{}, err
	}
	return plan, nil
}

func (s *ModelRuntimeService) SuggestEvidenceIntent(ctx context.Context, task model.AISecurityTask, finding model.AIFinding, missingFields []string) (EvidenceIntentSuggestion, error) {
	if task.ModelConfigID == nil {
		return deterministicEvidenceIntent(finding, missingFields), nil
	}

	config, options, err := s.loadConfig(ctx, *task.ModelConfigID)
	if err != nil {
		return EvidenceIntentSuggestion{}, err
	}

	start := time.Now()
	provider := normalizeModelProvider(config.Provider)
	var suggestion EvidenceIntentSuggestion
	switch provider {
	case "openai", "openai-compatible":
		suggestion, err = s.suggestWithOpenAI(ctx, config, options, task, finding, missingFields)
	default:
		err = fmt.Errorf("unsupported model provider: %s", config.Provider)
	}
	s.logModelCall(ctx, &task.ID, config.Model, config.Provider, "evidence_intent", start, err)
	if err != nil {
		return EvidenceIntentSuggestion{}, err
	}
	return suggestion, nil
}

func (s *ModelRuntimeService) GenerateReportNarrative(ctx context.Context, task model.AISecurityTask, findings []model.AIFinding, evidence []model.AIEvidence, toolRuns []model.AIToolRun) (ReportNarrative, error) {
	if task.ModelConfigID == nil {
		return deterministicReportNarrative(task, findings, evidence, toolRuns), nil
	}

	config, options, err := s.loadConfig(ctx, *task.ModelConfigID)
	if err != nil {
		return ReportNarrative{}, err
	}

	provider := normalizeModelProvider(config.Provider)
	start := time.Now()
	var narrative ReportNarrative
	switch provider {
	case "openai", "openai-compatible":
		narrative, err = s.generateNarrativeWithOpenAI(ctx, config, options, task, findings, evidence, toolRuns)
	default:
		err = fmt.Errorf("unsupported model provider: %s", config.Provider)
	}
	s.logModelCall(ctx, &task.ID, config.Model, config.Provider, "report_narrative", start, err)
	if err != nil {
		return ReportNarrative{}, err
	}
	return narrative, nil
}

func (s *ModelRuntimeService) AnalyzeSecurityGraph(ctx context.Context, task model.AISecurityTask, packet SecurityGraphAuditPacket) (SecurityGraphDecision, ModelCallMetadata, error) {
	metadata := ModelCallMetadata{Provider: "model-runtime", Model: "", IntentType: "security_graph_reasoning"}
	if task.ModelConfigID == nil {
		return SecurityGraphDecision{}, metadata, fmt.Errorf("model config is required for graph reasoning")
	}
	config, options, err := s.loadConfig(ctx, *task.ModelConfigID)
	if err != nil {
		return SecurityGraphDecision{}, metadata, err
	}
	graphConfig := config
	if strings.TrimSpace(options.ReviewModel) != "" {
		graphConfig.Model = strings.TrimSpace(options.ReviewModel)
	}
	metadata.Provider = config.Provider
	metadata.Model = graphConfig.Model
	provider := normalizeModelProvider(config.Provider)
	start := time.Now()
	switch provider {
	case "openai", "openai-compatible":
		decision, err := s.analyzeSecurityGraphWithOpenAI(ctx, graphConfig, options, task, packet)
		s.logModelCall(ctx, &task.ID, graphConfig.Model, config.Provider, "graph_reasoning", start, err)
		return decision, metadata, err
	default:
		return SecurityGraphDecision{}, metadata, fmt.Errorf("unsupported model provider: %s", config.Provider)
	}
}

func (s *ModelRuntimeService) FallbackIterationPlan(ctx context.Context, task model.AISecurityTask, intent *model.AIIntent) IterationPlan {
	plan := deterministicIterationPlan(task, intent)
	if task.ModelConfigID == nil {
		return plan
	}
	if config, _, err := s.loadConfig(ctx, *task.ModelConfigID); err == nil {
		plan.ModelProvider = "deterministic-fallback"
		plan.ModelName = config.Model
	}
	return plan
}

func (s *ModelRuntimeService) IterationCallMetadata(ctx context.Context, task model.AISecurityTask, intent *model.AIIntent) ModelCallMetadata {
	metadata := ModelCallMetadata{
		Provider: "deterministic-runtime",
		Model:    "first-stage-bootstrap",
	}
	if intent != nil {
		metadata.IntentType = intent.IntentType
	}
	if task.ModelConfigID == nil {
		return metadata
	}
	if config, _, err := s.loadConfig(ctx, *task.ModelConfigID); err == nil {
		metadata.Provider = config.Provider
		metadata.Model = config.Model
	}
	return metadata
}

func (s *ModelRuntimeService) SelectWorkerForIntent(ctx context.Context, taskID uint, intent *model.AIIntent) (WorkerRuntimeSelection, bool, error) {
	if s == nil {
		return WorkerRuntimeSelection{}, false, nil
	}
	intentType := ""
	if intent != nil {
		intentType = intent.IntentType
	}
	var task model.AISecurityTask
	if err := s.db.WithContext(ctx).Select("id", "worker_model_config_id").First(&task, taskID).Error; err == nil && task.WorkerModelConfigID != nil {
		var cfg model.AIModelConfig
		if err := s.db.WithContext(ctx).
			Where("id = ? AND enabled = ? AND purpose = ?", *task.WorkerModelConfigID, true, model.ModelPurposeWorker).
			First(&cfg).Error; err != nil {
			return WorkerRuntimeSelection{}, false, err
		}
		selection, ok, err := s.workerSelectionForConfig(ctx, cfg, intentType)
		if err != nil || !ok {
			return selection, ok, err
		}
		return selection, true, nil
	}
	var configs []model.AIModelConfig
	if err := s.db.WithContext(ctx).
		Where("enabled = ? AND purpose = ?", true, model.ModelPurposeWorker).
		Order("id asc").
		Find(&configs).Error; err != nil {
		return WorkerRuntimeSelection{}, false, err
	}
	if len(configs) == 0 {
		return WorkerRuntimeSelection{}, false, nil
	}
	var selected *WorkerRuntimeSelection
	for _, cfg := range configs {
		candidate, ok, err := s.workerSelectionForConfig(ctx, cfg, intentType)
		if err != nil {
			return WorkerRuntimeSelection{}, false, err
		}
		if !ok {
			continue
		}
		if selected == nil ||
			candidate.Priority < selected.Priority ||
			(candidate.Priority == selected.Priority && candidate.Running < selected.Running) ||
			(candidate.Priority == selected.Priority && candidate.Running == selected.Running && candidate.Config.ID < selected.Config.ID) {
			copy := candidate
			selected = &copy
		}
	}
	if selected == nil {
		return WorkerRuntimeSelection{}, false, nil
	}
	return *selected, true, nil
}

func (s *ModelRuntimeService) workerSelectionForConfig(ctx context.Context, cfg model.AIModelConfig, intentType string) (WorkerRuntimeSelection, bool, error) {
	var options modelRuntimeOptions
	_ = unmarshalJSON(cfg.OptionsJSON, &options)
	if !isExternalWorkerDriver(options.WorkerDriver) {
		return WorkerRuntimeSelection{}, false, nil
	}
	taskTypes := normalizeWorkerTaskTypes(options.WorkerTaskTypes)
	if !workerAcceptsIntent(taskTypes, intentType) {
		return WorkerRuntimeSelection{}, false, nil
	}
	maxRunning := options.WorkerMaxRunning
	if maxRunning <= 0 {
		maxRunning = defaultExternalWorkerMaxRunning
	}
	workerID := workerRuntimeID(cfg)
	var running int64
	if err := s.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("claimed_by = ? AND status IN ?", workerID, []string{model.IntentStatusClaimed, model.IntentStatusRunning}).
		Count(&running).Error; err != nil {
		return WorkerRuntimeSelection{}, false, err
	}
	if running >= int64(maxRunning) {
		return WorkerRuntimeSelection{}, false, nil
	}
	return WorkerRuntimeSelection{
		Config:     cfg,
		WorkerID:   workerID,
		TaskTypes:  taskTypes,
		Priority:   options.WorkerPriority,
		MaxRunning: maxRunning,
		Running:    running,
	}, true, nil
}

func isExternalWorkerDriver(driver string) bool {
	switch normalizeWorkerDriver(driver) {
	case "pi_container_kali":
		return true
	default:
		return false
	}
}

func normalizeWorkerDriver(driver string) string {
	normalized := strings.ToLower(strings.TrimSpace(driver))
	if normalized == "pi_cli" {
		return "pi_container_kali"
	}
	return normalized
}

func workerRuntimeID(config model.AIModelConfig) string {
	name := strings.TrimSpace(config.Name)
	if name == "" {
		name = config.Model
	}
	name = strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-").Replace(name)
	return fmt.Sprintf("worker:%d:%s", config.ID, name)
}

func normalizeWorkerTaskTypes(taskTypes []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range taskTypes {
		text := strings.ToLower(strings.TrimSpace(item))
		if text == "" || seen[text] {
			continue
		}
		seen[text] = true
		out = append(out, text)
	}
	return out
}

func workerAcceptsIntent(taskTypes []string, intentType string) bool {
	if len(taskTypes) == 0 {
		return true
	}
	intentType = strings.ToLower(strings.TrimSpace(intentType))
	if intentType == "" {
		return true
	}
	for _, taskType := range taskTypes {
		if taskType == "all" || taskType == intentType {
			return true
		}
		switch taskType {
		case "code_audit":
			if isCodeAuditRuntimeIntent(intentType) || strings.Contains(intentType, "code") || strings.Contains(intentType, "trace") {
				return true
			}
		case "pentest":
			if isPentestRuntimeIntent(intentType) || intentType == "recon" || intentType == "validate" || intentType == "fingerprint" {
				return true
			}
		case "reason", "explore", "bootstrap":
			return true
		}
	}
	return false
}

func deterministicIterationPlan(task model.AISecurityTask, intent *model.AIIntent) IterationPlan {
	thought := "Observed authorized origin, selected a high-value evidence collection step, and kept execution inside the current scope boundary."
	action := "Run task-type appropriate registered tools and persist ToolRun/Evidence."
	if intent != nil {
		thought = fmt.Sprintf("Observed current intent %s and aligned the next action with the authorized task objective.", intent.IntentType)
		action = "Execute current intent through registered tools and persist ToolRun/Evidence."
	}
	return IterationPlan{
		ModelProvider:  "deterministic-runtime",
		ModelName:      "first-stage-bootstrap",
		ThoughtSummary: thought,
		PlannedAction:  action,
	}
}

func deterministicEvidenceIntent(finding model.AIFinding, missingFields []string) EvidenceIntentSuggestion {
	intentType := "collect_evidence"
	title := "补齐 Finding Contract 缺失证据"
	objective := "Collect missing evidence fields for finding: " + finding.Title
	if finding.VulnerabilityType == "pentest_candidate" {
		intentType = "validate"
		title = "执行 HTTP 差异验证并补齐证据"
		objective = "Collect validation evidence for pentest finding: " + finding.Title
	}
	return EvidenceIntentSuggestion{
		Title:      title,
		Objective:  objective + " Missing fields: " + strings.Join(missingFields, ", "),
		IntentType: intentType,
	}
}

func deterministicReportNarrative(task model.AISecurityTask, findings []model.AIFinding, evidence []model.AIEvidence, toolRuns []model.AIToolRun) ReportNarrative {
	summary := fmt.Sprintf("本次安全验证在授权范围内完成，共形成 %d 个漏洞发现。报告主体仅保留能够支撑漏洞定性、攻击路径、代码证据和修复建议的关键材料。", len(findings))
	narratives := make(map[uint]string, len(findings))
	for _, finding := range findings {
		details := map[string]any{}
		_ = unmarshalJSON(finding.RichDetails, &details)
		narratives[finding.ID] = fallbackFindingNarrative(finding, details)
	}
	return ReportNarrative{
		ExecutiveSummary:  summary,
		FindingNarratives: narratives,
	}
}

func fallbackFindingNarrative(finding model.AIFinding, details map[string]any) string {
	parts := []string{}
	if entry := modelDetailValue(details, "entrypoint"); entry != "" {
		parts = append(parts, "入口点："+entry)
	}
	if path := modelDetailValue(details, "propagation_path"); path != "" {
		parts = append(parts, "模型基于证据链识别到传播路径："+path)
	}
	if observed := modelDetailValue(details, "observed_result"); observed != "" {
		parts = append(parts, "观察结果："+observed)
	}
	if impact := modelDetailValue(details, "impact_explanation"); impact != "" {
		parts = append(parts, "影响说明："+impact)
	}
	if len(parts) > 0 {
		return strings.Join(parts, "。") + "。"
	}
	if finding.Status == model.FindingStatusDynamicallyValidated || finding.Status == model.FindingStatusHumanConfirmed {
		return "该结果已通过动态验证，证据链和执行记录可用于正式交付。"
	}
	return "该结果仍属于候选风险，证据或 Contract 尚未完整，报告避免使用强确认措辞。"
}

func modelDetailValue(details map[string]any, key string) string {
	value, ok := details[key]
	if !ok || value == nil {
		return ""
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "[]" || text == "<nil>" || strings.Contains(text, "readonly validation proof") {
		return ""
	}
	return text
}

func (s *ModelRuntimeService) loadConfig(ctx context.Context, id uint) (model.AIModelConfig, modelRuntimeOptions, error) {
	var config model.AIModelConfig
	if err := s.db.WithContext(ctx).First(&config, id).Error; err != nil {
		return config, modelRuntimeOptions{}, err
	}
	var options modelRuntimeOptions
	_ = unmarshalJSON(config.OptionsJSON, &options)
	if options.WireAPI == "" {
		options.WireAPI = "responses"
	}
	return config, options, nil
}

func (s *ModelRuntimeService) planWithOpenAI(ctx context.Context, config model.AIModelConfig, options modelRuntimeOptions, task model.AISecurityTask, intent *model.AIIntent, agentContext AgentContext) (IterationPlan, error) {
	apiKey, err := resolveModelSecret(config.APIKeyRef, options.RequiresOpenAIAuth)
	if err != nil {
		return IterationPlan{}, err
	}
	systemPrompt, userPrompt := buildPlannerPrompt(task, intent, agentContext)
	var raw string
	switch strings.ToLower(strings.TrimSpace(options.WireAPI)) {
	case "", "responses":
		raw, err = s.callResponsesAPI(ctx, config, options, apiKey, systemPrompt, userPrompt)
	case "chat_completions":
		raw, err = s.callChatCompletionsAPI(ctx, config, options, apiKey, systemPrompt, userPrompt)
	default:
		err = fmt.Errorf("unsupported wire api: %s", options.WireAPI)
	}
	if err != nil {
		return IterationPlan{}, err
	}

	parsed, err := parsePlannerOutput(raw)
	if err != nil {
		return IterationPlan{}, err
	}
	thought := strings.TrimSpace(parsed.ThoughtSummary)
	action := strings.TrimSpace(parsed.PlannedAction)
	if thought == "" || action == "" {
		return IterationPlan{}, fmt.Errorf("model returned an incomplete iteration plan")
	}
	return IterationPlan{
		ModelProvider:  config.Provider,
		ModelName:      config.Model,
		ThoughtSummary: thought,
		PlannedAction:  action,
		NextIntents:    normalizeSecurityGraphIntents(parsed.NextIntents),
	}, nil
}

func (s *ModelRuntimeService) suggestWithOpenAI(ctx context.Context, config model.AIModelConfig, options modelRuntimeOptions, task model.AISecurityTask, finding model.AIFinding, missingFields []string) (EvidenceIntentSuggestion, error) {
	apiKey, err := resolveModelSecret(config.APIKeyRef, options.RequiresOpenAIAuth)
	if err != nil {
		return EvidenceIntentSuggestion{}, err
	}
	systemPrompt, userPrompt := buildEvidenceIntentPrompt(task, finding, missingFields)
	var raw string
	switch strings.ToLower(strings.TrimSpace(options.WireAPI)) {
	case "", "responses":
		raw, err = s.callResponsesAPI(ctx, config, options, apiKey, systemPrompt, userPrompt)
	case "chat_completions":
		raw, err = s.callChatCompletionsAPI(ctx, config, options, apiKey, systemPrompt, userPrompt)
	default:
		err = fmt.Errorf("unsupported wire api: %s", options.WireAPI)
	}
	if err != nil {
		return EvidenceIntentSuggestion{}, err
	}
	parsed, err := parseEvidenceIntentOutput(raw)
	if err != nil {
		return EvidenceIntentSuggestion{}, err
	}
	if strings.TrimSpace(parsed.Title) == "" || strings.TrimSpace(parsed.Objective) == "" || strings.TrimSpace(parsed.IntentType) == "" {
		return EvidenceIntentSuggestion{}, fmt.Errorf("model returned an incomplete evidence intent suggestion")
	}
	return EvidenceIntentSuggestion{
		Title:      strings.TrimSpace(parsed.Title),
		Objective:  strings.TrimSpace(parsed.Objective),
		IntentType: strings.TrimSpace(parsed.IntentType),
	}, nil
}

func (s *ModelRuntimeService) callResponsesAPI(ctx context.Context, config model.AIModelConfig, options modelRuntimeOptions, apiKey, systemPrompt, userPrompt string) (string, error) {
	type inputContent struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type inputMessage struct {
		Role    string         `json:"role"`
		Content []inputContent `json:"content"`
	}
	type requestBody struct {
		Model     string         `json:"model"`
		Input     []inputMessage `json:"input"`
		Store     *bool          `json:"store,omitempty"`
		Reasoning map[string]any `json:"reasoning,omitempty"`
	}
	reqBody := requestBody{
		Model: config.Model,
		Input: []inputMessage{
			{Role: "system", Content: []inputContent{{Type: "input_text", Text: systemPrompt}}},
			{Role: "user", Content: []inputContent{{Type: "input_text", Text: userPrompt}}},
		},
	}
	if options.DisableResponseStorage {
		store := false
		reqBody.Store = &store
	}
	if options.ModelReasoningEffort != "" {
		reqBody.Reasoning = map[string]any{"effort": options.ModelReasoningEffort}
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinAPIURL(config.BaseURL, "/responses"), bytes.NewReader(body))
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
		return "", err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("model responses api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	type responseContent struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type responseItem struct {
		Content []responseContent `json:"content"`
	}
	type responseBody struct {
		OutputText string         `json:"output_text"`
		Output     []responseItem `json:"output"`
	}
	var parsed responseBody
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return "", err
	}
	if strings.TrimSpace(parsed.OutputText) != "" {
		return parsed.OutputText, nil
	}
	var builder strings.Builder
	for _, item := range parsed.Output {
		for _, content := range item.Content {
			if strings.TrimSpace(content.Text) == "" {
				continue
			}
			if builder.Len() > 0 {
				builder.WriteByte('\n')
			}
			builder.WriteString(content.Text)
		}
	}
	if builder.Len() == 0 {
		return "", fmt.Errorf("model responses api returned no text output")
	}
	return builder.String(), nil
}

func (s *ModelRuntimeService) generateNarrativeWithOpenAI(ctx context.Context, config model.AIModelConfig, options modelRuntimeOptions, task model.AISecurityTask, findings []model.AIFinding, evidence []model.AIEvidence, toolRuns []model.AIToolRun) (ReportNarrative, error) {
	apiKey, err := resolveModelSecret(config.APIKeyRef, options.RequiresOpenAIAuth)
	if err != nil {
		return ReportNarrative{}, err
	}
	reportConfig := config
	if strings.TrimSpace(options.ReviewModel) != "" {
		reportConfig.Model = strings.TrimSpace(options.ReviewModel)
	}
	systemPrompt, userPrompt := buildReportNarrativePrompt(task, findings, evidence, toolRuns)
	var raw string
	switch strings.ToLower(strings.TrimSpace(options.WireAPI)) {
	case "", "responses":
		raw, err = s.callResponsesAPI(ctx, reportConfig, options, apiKey, systemPrompt, userPrompt)
	case "chat_completions":
		raw, err = s.callChatCompletionsAPI(ctx, reportConfig, options, apiKey, systemPrompt, userPrompt)
	default:
		err = fmt.Errorf("unsupported wire api: %s", options.WireAPI)
	}
	if err != nil {
		return ReportNarrative{}, err
	}
	parsed, err := parseReportNarrativeOutput(raw)
	if err != nil {
		return ReportNarrative{}, err
	}
	result := deterministicReportNarrative(task, findings, evidence, toolRuns)
	if strings.TrimSpace(parsed.ExecutiveSummary) != "" {
		result.ExecutiveSummary = strings.TrimSpace(parsed.ExecutiveSummary)
	}
	for _, finding := range findings {
		if text, ok := parsed.FindingNarratives[fmt.Sprintf("%d", finding.ID)]; ok && strings.TrimSpace(text) != "" {
			result.FindingNarratives[finding.ID] = enforceFindingNarrativeGuardrail(finding, strings.TrimSpace(text))
		}
	}
	return result, nil
}

func (s *ModelRuntimeService) analyzeSecurityGraphWithOpenAI(ctx context.Context, config model.AIModelConfig, options modelRuntimeOptions, task model.AISecurityTask, packet SecurityGraphAuditPacket) (SecurityGraphDecision, error) {
	apiKey, err := resolveModelSecret(config.APIKeyRef, options.RequiresOpenAIAuth)
	if err != nil {
		return SecurityGraphDecision{}, err
	}
	systemPrompt, userPrompt := buildSecurityGraphPrompt(task, packet)
	graphOptions := options
	graphOptions.ModelReasoningEffort = codeAuditReasoningEffort(options.ModelReasoningEffort)
	graphOptions.DisableResponseStorage = true
	var raw string
	switch strings.ToLower(strings.TrimSpace(options.WireAPI)) {
	case "", "responses":
		callCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
		raw, err = s.callResponsesAPI(callCtx, config, graphOptions, apiKey, systemPrompt, userPrompt)
		cancel()
		if err != nil && ctx.Err() == nil {
			chatCtx, chatCancel := context.WithTimeout(ctx, 300*time.Second)
			chatRaw, chatErr := s.callChatCompletionsAPI(chatCtx, config, graphOptions, apiKey, systemPrompt, userPrompt)
			chatCancel()
			if chatErr == nil {
				raw = chatRaw
				err = nil
			} else {
				err = fmt.Errorf("responses failed: %v; chat_completions fallback failed: %v", err, chatErr)
			}
		}
	case "chat_completions":
		raw, err = s.callChatCompletionsAPI(ctx, config, graphOptions, apiKey, systemPrompt, userPrompt)
	default:
		err = fmt.Errorf("unsupported wire api: %s", options.WireAPI)
	}
	if err != nil {
		return SecurityGraphDecision{}, err
	}
	return parseSecurityGraphDecisionOutput(raw)
}

func codeAuditReasoningEffort(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return "medium"
	}
	return v
}

func (s *ModelRuntimeService) callChatCompletionsAPI(ctx context.Context, config model.AIModelConfig, options modelRuntimeOptions, apiKey, systemPrompt, userPrompt string) (string, error) {
	type requestMessage struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type requestBody struct {
		Model          string            `json:"model"`
		Messages       []requestMessage  `json:"messages"`
		ResponseFormat map[string]string `json:"response_format,omitempty"`
	}
	reqBody := requestBody{
		Model: config.Model,
		Messages: []requestMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		ResponseFormat: map[string]string{"type": "json_object"},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinAPIURL(config.BaseURL, "/chat/completions"), bytes.NewReader(body))
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
		return "", err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("model chat completions api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	type responseBody struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	var parsed responseBody
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("model chat completions api returned no content")
	}
	return parsed.Choices[0].Message.Content, nil
}

type plannerOutput struct {
	ThoughtSummary string                          `json:"thought_summary"`
	PlannedAction  string                          `json:"planned_action"`
	NextIntents    []flexSecurityGraphIntentOutput `json:"next_intents"`
}

type evidenceIntentOutput struct {
	Title      string `json:"title"`
	Objective  string `json:"objective"`
	IntentType string `json:"intent_type"`
}

type reportNarrativeOutput struct {
	ExecutiveSummary  string            `json:"executive_summary"`
	FindingNarratives map[string]string `json:"finding_narratives"`
}

type securityGraphDecisionOutput struct {
	Facts       []SecurityGraphFactSuggestion   `json:"facts"`
	NextIntents []flexSecurityGraphIntentOutput `json:"next_intents"`
	Selected    []flexSecurityGraphIntentOutput `json:"selected_intents"`
	StopReason  string                          `json:"stop_reason"`
}

type flexSecurityGraphIntentOutput struct {
	Title            string `json:"title"`
	Objective        string `json:"objective"`
	IntentType       string `json:"intent_type"`
	RequiredEvidence any    `json:"required_evidence"`
	SourceNodeIDs    any    `json:"source_node_ids"`
	Hypothesis       string `json:"hypothesis"`
	SuccessCriteria  string `json:"success_criteria"`
	FailureCriteria  string `json:"failure_criteria"`
	AllowedTools     any    `json:"allowed_tools"`
	RiskLevel        string `json:"risk_level"`
	Priority         any    `json:"priority"`
}

func parsePlannerOutput(raw string) (plannerOutput, error) {
	var output plannerOutput
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return output, fmt.Errorf("model returned an empty planner response")
	}
	if err := json.Unmarshal([]byte(trimmed), &output); err == nil {
		return output, nil
	}
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(trimmed[start:end+1]), &output); err == nil {
			return output, nil
		}
	}
	return output, fmt.Errorf("model returned a non-json planner response")
}

func parseEvidenceIntentOutput(raw string) (evidenceIntentOutput, error) {
	var output evidenceIntentOutput
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return output, fmt.Errorf("model returned an empty evidence intent response")
	}
	if err := json.Unmarshal([]byte(trimmed), &output); err == nil {
		return output, nil
	}
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(trimmed[start:end+1]), &output); err == nil {
			return output, nil
		}
	}
	return output, fmt.Errorf("model returned a non-json evidence intent response")
}

func parseReportNarrativeOutput(raw string) (reportNarrativeOutput, error) {
	var output reportNarrativeOutput
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return output, fmt.Errorf("model returned an empty report narrative response")
	}
	if err := json.Unmarshal([]byte(trimmed), &output); err == nil {
		if output.FindingNarratives == nil {
			output.FindingNarratives = map[string]string{}
		}
		return output, nil
	}
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(trimmed[start:end+1]), &output); err == nil {
			if output.FindingNarratives == nil {
				output.FindingNarratives = map[string]string{}
			}
			return output, nil
		}
	}
	return output, fmt.Errorf("model returned a non-json report narrative response")
}

func parseSecurityGraphDecisionOutput(raw string) (SecurityGraphDecision, error) {
	var output securityGraphDecisionOutput
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return SecurityGraphDecision{}, fmt.Errorf("model returned an empty security graph decision")
	}
	jsonStr := trimmed
	if err := json.Unmarshal([]byte(trimmed), &output); err != nil {
		start := strings.Index(trimmed, "{")
		end := strings.LastIndex(trimmed, "}")
		if start < 0 || end <= start {
			return SecurityGraphDecision{}, fmt.Errorf("model returned a non-json security graph decision")
		}
		jsonStr = trimmed[start : end+1]
		if err := json.Unmarshal([]byte(jsonStr), &output); err != nil {
			// Strict unmarshal failed — always try lenient field-by-field extraction
			lenient, lenientErr := lenientParseSecurityGraphDecision(jsonStr)
			if lenientErr != nil {
				return SecurityGraphDecision{}, fmt.Errorf("model returned an invalid security graph decision: %w", err)
			}
			return lenient, nil
		}
	}
	return SecurityGraphDecision{
		Facts:       output.Facts,
		NextIntents: normalizeSecurityGraphIntents(firstNonEmptyGraphIntentOutputs(output.NextIntents, output.Selected)),
		StopReason:  strings.TrimSpace(output.StopReason),
	}, nil
}

// lenientParseSecurityGraphDecision extracts as much as possible from a model response
// even when some fields have type mismatches (e.g. model returns numbers where strings are expected).
func lenientParseSecurityGraphDecision(jsonStr string) (SecurityGraphDecision, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return SecurityGraphDecision{}, err
	}

	result := SecurityGraphDecision{}

	// Parse facts (usually clean)
	if factsRaw, ok := raw["facts"]; ok {
		var facts []SecurityGraphFactSuggestion
		if err := json.Unmarshal(factsRaw, &facts); err == nil {
			result.Facts = facts
		}
	}

	// Parse next_intents leniently
	if intentsRaw, ok := firstRawMessage(raw, "next_intents", "selected_intents"); ok {
		var intentsArray []json.RawMessage
		if err := json.Unmarshal(intentsRaw, &intentsArray); err == nil {
			for _, itemRaw := range intentsArray {
				var flex flexSecurityGraphIntentOutput
				if err := json.Unmarshal(itemRaw, &flex); err == nil {
					result.NextIntents = append(result.NextIntents, SecurityGraphIntentSuggestion{
						Title:            strings.TrimSpace(flex.Title),
						Objective:        strings.TrimSpace(flex.Objective),
						IntentType:       strings.TrimSpace(flex.IntentType),
						RequiredEvidence: normalizeStringListAny(flex.RequiredEvidence),
						SourceNodeIDs:    normalizeUintListAny(flex.SourceNodeIDs),
						Hypothesis:       strings.TrimSpace(flex.Hypothesis),
						SuccessCriteria:  strings.TrimSpace(flex.SuccessCriteria),
						FailureCriteria:  strings.TrimSpace(flex.FailureCriteria),
						AllowedTools:     normalizeStringListAny(flex.AllowedTools),
						RiskLevel:        strings.TrimSpace(flex.RiskLevel),
						Priority:         normalizeIntAny(flex.Priority),
					})
				} else {
					// Even more lenient: parse as map
					var m map[string]any
					if json.Unmarshal(itemRaw, &m) == nil {
						suggestion := SecurityGraphIntentSuggestion{
							Title:            lenientStringFromMap(m, "title"),
							Objective:        lenientStringFromMap(m, "objective"),
							IntentType:       lenientStringFromMap(m, "intent_type"),
							RequiredEvidence: normalizeStringListAny(m["required_evidence"]),
							SourceNodeIDs:    normalizeUintListAny(m["source_node_ids"]),
							Hypothesis:       lenientStringFromMap(m, "hypothesis"),
							SuccessCriteria:  lenientStringFromMap(m, "success_criteria"),
							FailureCriteria:  lenientStringFromMap(m, "failure_criteria"),
							AllowedTools:     normalizeStringListAny(m["allowed_tools"]),
							RiskLevel:        lenientStringFromMap(m, "risk_level"),
							Priority:         normalizeIntAny(m["priority"]),
						}
						if suggestion.Title != "" {
							result.NextIntents = append(result.NextIntents, suggestion)
						}
					}
				}
			}
		}
	}

	// Parse stop_reason
	if stopRaw, ok := raw["stop_reason"]; ok {
		var stop string
		if json.Unmarshal(stopRaw, &stop) == nil {
			result.StopReason = strings.TrimSpace(stop)
		}
	}

	if len(result.Facts) == 0 && len(result.NextIntents) == 0 {
		return result, fmt.Errorf("lenient parse extracted no usable content")
	}
	return result, nil
}

func firstNonEmptyGraphIntentOutputs(primary, fallback []flexSecurityGraphIntentOutput) []flexSecurityGraphIntentOutput {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func firstRawMessage(raw map[string]json.RawMessage, keys ...string) (json.RawMessage, bool) {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func lenientStringFromMap(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func normalizeSecurityGraphIntents(items []flexSecurityGraphIntentOutput) []SecurityGraphIntentSuggestion {
	result := make([]SecurityGraphIntentSuggestion, 0, len(items))
	for _, item := range items {
		result = append(result, SecurityGraphIntentSuggestion{
			Title:            strings.TrimSpace(item.Title),
			Objective:        strings.TrimSpace(item.Objective),
			IntentType:       strings.TrimSpace(item.IntentType),
			RequiredEvidence: normalizeStringListAny(item.RequiredEvidence),
			SourceNodeIDs:    normalizeUintListAny(item.SourceNodeIDs),
			Hypothesis:       strings.TrimSpace(item.Hypothesis),
			SuccessCriteria:  strings.TrimSpace(item.SuccessCriteria),
			FailureCriteria:  strings.TrimSpace(item.FailureCriteria),
			AllowedTools:     normalizeStringListAny(item.AllowedTools),
			RiskLevel:        strings.TrimSpace(item.RiskLevel),
			Priority:         normalizeIntAny(item.Priority),
		})
	}
	return result
}

func normalizeUintListAny(value any) []uint {
	switch typed := value.(type) {
	case nil:
		return nil
	case []uint:
		return compactUintList(typed)
	case []int:
		result := make([]uint, 0, len(typed))
		for _, item := range typed {
			if item > 0 {
				result = append(result, uint(item))
			}
		}
		return compactUintList(result)
	case []float64:
		result := make([]uint, 0, len(typed))
		for _, item := range typed {
			if item > 0 {
				result = append(result, uint(item))
			}
		}
		return compactUintList(result)
	case []any:
		result := make([]uint, 0, len(typed))
		for _, item := range typed {
			if id := normalizeUintAny(item); id > 0 {
				result = append(result, id)
			}
		}
		return compactUintList(result)
	case string:
		parts := strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == '\n' || r == ' ' || r == '\t'
		})
		result := make([]uint, 0, len(parts))
		for _, part := range parts {
			if id := normalizeUintAny(part); id > 0 {
				result = append(result, id)
			}
		}
		return compactUintList(result)
	default:
		if id := normalizeUintAny(value); id > 0 {
			return []uint{id}
		}
		return nil
	}
}

func normalizeUintAny(value any) uint {
	switch typed := value.(type) {
	case uint:
		return typed
	case int:
		if typed > 0 {
			return uint(typed)
		}
	case int64:
		if typed > 0 {
			return uint(typed)
		}
	case float64:
		if typed > 0 {
			return uint(typed)
		}
	case json.Number:
		if parsed, err := typed.Int64(); err == nil && parsed > 0 {
			return uint(parsed)
		}
	case string:
		text := strings.TrimSpace(typed)
		text = strings.TrimPrefix(text, "node:")
		text = strings.TrimPrefix(text, "blackboard_node:")
		if parsed, err := strconv.ParseUint(text, 10, 64); err == nil && parsed > 0 {
			return uint(parsed)
		}
	}
	return 0
}

func normalizeIntAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
		return parsed
	default:
		return 0
	}
}

func compactUintList(values []uint) []uint {
	seen := map[uint]struct{}{}
	result := make([]uint, 0, len(values))
	for _, value := range values {
		if value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeStringListAny(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case []string:
		return compactStringListForModel(typed)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" && text != "<nil>" {
				result = append(result, text)
			}
		}
		return compactStringListForModel(result)
	case string:
		return compactStringListForModel(strings.Split(typed, "\n"))
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || text == "<nil>" {
			return nil
		}
		return []string{text}
	}
}

func compactStringListForModel(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text := strings.TrimSpace(strings.TrimPrefix(value, "-"))
		if text == "" {
			continue
		}
		key := strings.ToLower(text)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, text)
	}
	return result
}

func buildPlannerPrompt(task model.AISecurityTask, intent *model.AIIntent, agentContext AgentContext) (string, string) {
	systemPrompt := "You are Rabbit Security Validation Platform's coverage-oriented graph reasoner. Respond with a single JSON object only. Keys: thought_summary, planned_action, next_intents. next_intents is optional and must contain 0-3 evidence-seeking follow-up intents with title, objective, intent_type, required_evidence. Prefer generic graph-search intent types such as discover_entrypoints, enumerate_surfaces, inspect_dataflow, inspect_guard, inspect_auth_boundary, inspect_sink_reachability, validate_hypothesis, compare_behavior, resolve_unknown, verify_capability, expand_attack_surface, recheck_inconclusive_path, or run_tool. A verified capability is an output item, not a global stop condition. After a capability is verified, continue exploring unresolved high-priority surfaces unless budget is exhausted or coverage is sufficient. Do not generate intents only to complete a report or finding. Use coverage gain, evidence gap, novelty, and risk signal to prioritize intents. Vulnerability type is a result label, not the planning boundary. Do not reveal chain-of-thought. Do not create findings. Keep every suggestion inside the authorized scope and focused on facts that can be observed or validated."
	intentType := ""
	intentTitle := ""
	intentObjective := ""
	if intent != nil {
		intentType = intent.IntentType
		intentTitle = intent.Title
		intentObjective = intent.Objective
	}
	factLines := summarizeBlackboard(agentContext.KeyFacts, 8)
	evidenceLines := summarizeEvidence(agentContext.RecentEvidence, 6)
	graphSummary := "{}"
	if agentContext.GraphSummary != nil {
		raw, _ := json.Marshal(agentContext.GraphSummary)
		graphSummary = string(raw)
	}
	userPrompt := fmt.Sprintf(
		"Task Type: %s\nObjective: %s\nAuthorization: %s\nCurrent Intent Type: %s\nCurrent Intent Title: %s\nCurrent Intent Objective: %s\nRecommended Next: %s\nGraphSummary:\n%s\nKey Facts:\n%s\nRecent Evidence:\n%s\nReturn JSON only. Example shape: {\"thought_summary\":\"...\",\"planned_action\":\"...\",\"next_intents\":[{\"title\":\"Inspect unresolved guard\",\"objective\":\"Determine whether the observed source-to-sink path has an effective guard.\",\"intent_type\":\"inspect_guard\",\"required_evidence\":[\"code_slice\",\"guard\"]}]}",
		task.TaskType,
		task.Objective,
		agentContext.AuthorizationView,
		intentType,
		intentTitle,
		intentObjective,
		agentContext.RecommendedNext,
		graphSummary,
		factLines,
		evidenceLines,
	)
	return systemPrompt, userPrompt
}

func buildEvidenceIntentPrompt(task model.AISecurityTask, finding model.AIFinding, missingFields []string) (string, string) {
	systemPrompt := "You are Rabbit Security Validation Platform's evidence-gap planner. Respond with a single JSON object only. Keys: title, objective, intent_type. Keep the result concise, evidence-focused, and inside the authorized scope. Allowed intent_type values: collect_evidence, validate, code_trace."
	userPrompt := fmt.Sprintf(
		"Task Type: %s\nTask Objective: %s\nFinding Title: %s\nFinding Type: %s\nValidation Status: %s\nContract Status: %s\nMissing Fields: %s\nReturn the single next best evidence collection intent as JSON only.",
		task.TaskType,
		task.Objective,
		finding.Title,
		finding.VulnerabilityType,
		finding.ValidationStatus,
		finding.ContractStatus,
		strings.Join(missingFields, ", "),
	)
	return systemPrompt, userPrompt
}

func buildSecurityGraphPrompt(task model.AISecurityTask, packet SecurityGraphAuditPacket) (string, string) {
	systemPrompt := `You are the Reasoner in a Cairn-style security state-space search engine.
Your job: read the current graph state, assess coverage progress, and output 1-3 high-value structured Intents.
You do NOT execute tools. You only reason and plan.
Rules:
- Each Intent must cite the concrete graph nodes it comes from using source_node_ids.
- source_node_ids may contain multiple node ids when facts combine into one exploration direction.
- Each Intent must have a testable hypothesis, success/failure criteria, and allowed tools.
- Do not emit findings directly. Emit Intents that will produce Evidence and Capabilities.
- A verified capability is an output item, not a global stop condition.
- Continue exploring unresolved high-priority surfaces unless budget is exhausted or coverage is sufficient.
- Do not generate intents only to complete a report or finding.
- Use coverage gain, evidence gap, novelty, and risk signal to prioritize intents.
- Prioritize unexplored high-value paths over repeating failed ones.
- For code audit: think cross-file (route→auth→model→sink), not single-file grep.
- For pentest: think behavior probing (baseline vs variant), not CVE lookup.
- Return JSON only. No markdown, no explanation outside JSON.`

	nodes := make([]string, 0, len(packet.Nodes))
	for i, node := range packet.Nodes {
		if i >= 20 {
			break
		}
		nodes = append(nodes, fmt.Sprintf("- node_id=%d [%s] %s: %s", node.ID, node.NodeType, node.Title, node.Summary))
	}
	edges := make([]string, 0, len(packet.Edges))
	for i, edge := range packet.Edges {
		if i >= 30 {
			break
		}
		edges = append(edges, fmt.Sprintf("- %d -[%s]-> %d", edge.FromID, edge.EdgeType, edge.ToID))
	}
	snippets := make([]string, 0, len(packet.Snippets))
	for i, snippet := range packet.Snippets {
		if i >= 4 {
			break
		}
		content := truncatePromptText(snippet.Content, 500)
		snippets = append(snippets, fmt.Sprintf("FILE: %s (lines %d-%d)\n%s", snippet.FilePath, snippet.LineStart, snippet.LineEnd, content))
	}

	schema := `{
  "analysis_summary": "brief assessment of current state",
  "goal_progress": "coverage status, unresolved high-priority surfaces, and evidence gaps",
  "should_finalize": false,
  "finalize_reason": "",
  "selected_intents": [
    {
      "title": "short human-readable intent title",
      "intent_type": "behavior_probe|code_slice_analysis|dataflow_trace|surface_discovery|...",
      "source_node_ids": [12, 18],
      "hypothesis": "what you think might be vulnerable and why",
      "objective": "what this intent will verify",
      "success_criteria": "observable outcome if hypothesis is true",
      "failure_criteria": "observable outcome if hypothesis is false",
      "allowed_tools": ["behavior_probe","code_slice","http_request","..."],
      "risk_level": "low|medium|high",
      "priority": 90
    }
  ],
  "facts": [{"node_type":"fact","title":"","summary":""}]
}`

	userPrompt := fmt.Sprintf(
		"Task: %s\nType: %s\nGoal: %s\n\nCurrent Graph State:\n%s\n\nRelationships:\n%s\n\nCode Context:\n%s\n\nReturn structured JSON:\n%s",
		task.Name,
		task.TaskType,
		task.Objective,
		strings.Join(nodes, "\n"),
		strings.Join(edges, "\n"),
		strings.Join(snippets, "\n\n"),
		schema,
	)
	return systemPrompt, userPrompt
}

func buildReportNarrativePrompt(task model.AISecurityTask, findings []model.AIFinding, evidence []model.AIEvidence, toolRuns []model.AIToolRun) (string, string) {
	systemPrompt := "You are Rabbit Security Validation Platform's report narrator. Respond with a single JSON object only. Keys: executive_summary, finding_narratives. finding_narratives must be an object keyed by finding id as a string. Write in professional Chinese. Focus on vulnerability proof, not tool execution logs. Never use 'confirmed', 'successfully exploited', 'getshell', or similarly strong confirmation language unless the finding status is dynamically_validated or human_confirmed. Keep wording concise and delivery-ready."
	findingsSummary := make([]string, 0, len(findings))
	for _, finding := range findings {
		findingsSummary = append(findingsSummary, fmt.Sprintf("- id=%d title=%s status=%s validation=%s contract=%s severity=%s evidenceRefs=%s", finding.ID, finding.Title, finding.Status, finding.ValidationStatus, finding.ContractStatus, finding.Severity, string(finding.EvidenceRefs)))
	}
	evidenceSummary := summarizeEvidence(evidence, 8)
	toolRunSummary := make([]string, 0, min(8, len(toolRuns)))
	for _, run := range toolRuns {
		toolRunSummary = append(toolRunSummary, fmt.Sprintf("- %s status=%s", run.ToolName, run.Status))
		if len(toolRunSummary) >= 8 {
			break
		}
	}
	userPrompt := fmt.Sprintf(
		"Task: %s\nTask Type: %s\nAuthorized Scope: %s\nFindings:\n%s\nEvidence Summary:\n%s\nTool Runs:\n%s\nReturn JSON only.",
		task.Name,
		task.TaskType,
		string(task.ScopeJSON),
		strings.Join(findingsSummary, "\n"),
		evidenceSummary,
		strings.Join(toolRunSummary, "\n"),
	)
	return systemPrompt, userPrompt
}

func summarizeBlackboard(items []model.AIBlackboardNode, limit int) string {
	if len(items) == 0 {
		return "- none"
	}
	lines := make([]string, 0, min(limit, len(items)))
	for _, item := range items {
		lines = append(lines, fmt.Sprintf("- %s: %s", item.NodeType, item.Summary))
		if len(lines) >= limit {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func summarizeEvidence(items []model.AIEvidence, limit int) string {
	if len(items) == 0 {
		return "- none"
	}
	lines := make([]string, 0, min(limit, len(items)))
	for _, item := range items {
		lines = append(lines, fmt.Sprintf("- %s: %s", item.EvidenceType, item.Summary))
		if len(lines) >= limit {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func summarizeFindings(items []model.AIFinding, limit int) string {
	if len(items) == 0 {
		return "- none"
	}
	lines := make([]string, 0, min(limit, len(items)))
	for _, item := range items {
		lines = append(lines, fmt.Sprintf("- %s | validation=%s | contract=%s", item.Title, item.ValidationStatus, item.ContractStatus))
		if len(lines) >= limit {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func truncatePromptText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "\n...[truncated for prompt budget]"
}

func resolveModelSecret(ref string, required bool) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		if required {
			return "", fmt.Errorf("api key reference is required for the selected model provider")
		}
		return "", nil
	}
	if strings.HasPrefix(ref, "env://") {
		envKey := strings.TrimSpace(strings.TrimPrefix(ref, "env://"))
		if envKey == "" {
			return "", fmt.Errorf("api key env reference is empty")
		}
		value := strings.TrimSpace(os.Getenv(envKey))
		if value == "" {
			return "", fmt.Errorf("api key env %s is empty", envKey)
		}
		return value, nil
	}
	if required {
		return ref, nil
	}
	return ref, nil
}

func joinAPIURL(baseURL string, path string) string {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return path
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return strings.TrimRight(baseURL, "/") + path
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	return parsed.String()
}

func normalizeModelProvider(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "zhipu", "bailian", "newapi", "oneapi", "openrouter":
		return "openai-compatible"
	default:
		return normalized
	}
}

func applyCustomHeaders(req *http.Request, headers map[string]any) {
	if req == nil || len(headers) == 0 {
		return
	}
	for key, value := range headers {
		name := strings.TrimSpace(key)
		if name == "" || strings.ContainsAny(name, "\r\n") {
			continue
		}
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || strings.ContainsAny(text, "\r\n") {
			continue
		}
		req.Header.Set(name, text)
	}
}

// logModelCall records a model API call to the ai_model_call_logs table.
func (s *ModelRuntimeService) logModelCall(ctx context.Context, taskID *uint, modelName, provider, purpose string, start time.Time, callErr error) {
	latency := time.Since(start).Milliseconds()
	status := "success"
	errMsg := ""
	if callErr != nil {
		status = "failed"
		errMsg = callErr.Error()
		if strings.Contains(errMsg, "deadline exceeded") || strings.Contains(errMsg, "Timeout") {
			status = "timeout"
		}
	}
	_ = s.db.Create(&model.AIModelCallLog{
		TaskID:       taskID,
		ModelName:    modelName,
		Provider:     provider,
		Purpose:      purpose,
		Status:       status,
		LatencyMs:    latency,
		PromptTokens: 0,
		CompTokens:   0,
		ErrorMessage: errMsg,
		CalledAt:     time.Now().UTC(),
	}).Error
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func enforceFindingNarrativeGuardrail(finding model.AIFinding, narrative string) string {
	trimmed := strings.TrimSpace(narrative)
	if trimmed == "" {
		return trimmed
	}
	lower := strings.ToLower(trimmed)
	if finding.Status != model.FindingStatusDynamicallyValidated && finding.Status != model.FindingStatusHumanConfirmed {
		unsafePhrases := []string{"confirmed", "successfully exploited", "getshell", "已确认", "成功利用", "已成功利用"}
		for _, phrase := range unsafePhrases {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				return "该结果当前仍属于候选风险，证据或 Contract 尚未完整，报告不使用强确认措辞。"
			}
		}
	}
	return trimmed
}
