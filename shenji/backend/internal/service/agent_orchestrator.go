package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"shenji/backend/internal/config"
	"shenji/backend/internal/model"
	"shenji/backend/internal/runner"
	"shenji/backend/internal/tools"

	"gorm.io/gorm"
)

type AgentOrchestrator struct {
	cfg        config.Config
	db         *gorm.DB
	registry   *tools.ToolRegistry
	intents    *IntentService
	toolRuns   *ToolRunService
	blackboard *BlackboardService
	findings   *FindingService
	contracts  *ContractService
	context    *ContextBuilder
	compactor  *BlackboardCompactor
	reports    *ReportService
	models     *ModelRuntimeService
}

const (
	httpInputSurfaceFrontierWindow  = 4
	defaultReasonNoOpPassBudget     = 4
	defaultNoProgressFinalizeRounds = 6
	defaultPlannerNextIntentLimit   = 3
)

// AgentOrchestrator runs Rabbit's Cairn-style state-space loop.
//
// Rabbit is not a scanner, not a CVE/PoC search engine, and not a
// report-first vulnerability formatter. The orchestrator keeps the product
// centered on:
//
//	Fact / Observation / Evidence -> Hypothesis / Intent -> Runner / Explore
//	-> Evidence / New Fact -> Capability / NegativeFact / UnverifiedRisk
//	-> Next Intent.
//
// Tools only observe or validate. Findings are delivery artifacts. Contracts
// are report quality gates. Reports are outputs. The graph exploration loop is
// the product.
func NewAgentOrchestrator(cfg config.Config, db *gorm.DB, registry *tools.ToolRegistry, intents *IntentService, toolRuns *ToolRunService, blackboard *BlackboardService, findings *FindingService, contracts *ContractService, contextBuilder *ContextBuilder, compactor *BlackboardCompactor, reports *ReportService, models *ModelRuntimeService) *AgentOrchestrator {
	return &AgentOrchestrator{cfg: cfg, db: db, registry: registry, intents: intents, toolRuns: toolRuns, blackboard: blackboard, findings: findings, contracts: contracts, context: contextBuilder, compactor: compactor, reports: reports, models: models}
}

func (o *AgentOrchestrator) piWorkerTimeout() time.Duration {
	if o != nil && o.cfg.PiWorkerTimeout > 0 {
		return o.cfg.PiWorkerTimeout
	}
	if o != nil && o.cfg.ToolTimeout > 5*time.Minute {
		return o.cfg.ToolTimeout
	}
	return 5 * time.Minute
}

func (o *AgentOrchestrator) intentClaimLease(selectedWorker *WorkerRuntimeSelection) time.Duration {
	lease := o.cfg.WorkerLease
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	if selectedWorker == nil {
		return lease
	}
	needed := o.piWorkerTimeout() + 30*time.Second
	if lease < needed {
		return needed
	}
	return lease
}

func (o *AgentOrchestrator) reasonNoOpPassBudget() int {
	if o != nil && o.cfg.ReasonNoOpPassBudget > 0 {
		return o.cfg.ReasonNoOpPassBudget
	}
	return defaultReasonNoOpPassBudget
}

func (o *AgentOrchestrator) noProgressFinalizeRounds() int {
	if o != nil && o.cfg.NoProgressFinalizeRounds > 0 {
		return o.cfg.NoProgressFinalizeRounds
	}
	return defaultNoProgressFinalizeRounds
}

func (o *AgentOrchestrator) plannerNextIntentLimit() int {
	if o != nil && o.cfg.PlannerNextIntentLimit > 0 {
		return o.cfg.PlannerNextIntentLimit
	}
	return defaultPlannerNextIntentLimit
}

func (o *AgentOrchestrator) StartAsync(taskID uint) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), o.cfg.MaxRuntime)
		defer cancel()
		_ = o.Run(ctx, taskID)
	}()
}

func (o *AgentOrchestrator) Run(ctx context.Context, taskID uint) error {
	var task model.AISecurityTask
	if err := o.db.WithContext(ctx).First(&task, taskID).Error; err != nil {
		return err
	}
	if task.Status == model.TaskStatusRunning {
		return fmt.Errorf("task is already running")
	}
	now := time.Now().UTC()
	task.Status = model.TaskStatusRunning
	task.ProgressStage = "Agent 正在观察授权范围"
	task.ProgressPercent = 18
	task.StartedAt = &now
	task.FinishedAt = nil
	if err := o.db.WithContext(ctx).Save(&task).Error; err != nil {
		return err
	}
	defer o.cleanupTaskWorkerContainer(task.ID)
	appendAuditEvent(ctx, o.db, &task.ID, "agent.started", "agent-runtime", "Agent loop started with fail-closed runtime budget.", map[string]any{"maxRuntime": o.cfg.MaxRuntime.String()})

	loop := model.AIAgentLoop{
		TaskID:    task.ID,
		Status:    "running",
		Goal:      task.Objective,
		StartedAt: now,
		CreatedAt: now,
	}
	if err := o.db.WithContext(ctx).Create(&loop).Error; err != nil {
		return o.failTask(ctx, &task, err)
	}

	err := o.runLoopIterations(ctx, &task, &loop)
	finished := time.Now().UTC()
	loop.FinishedAt = &finished
	if err != nil {
		loop.Status = "failed"
		loop.StopReason = err.Error()
		_ = o.db.WithContext(ctx).Save(&loop).Error
		return o.failTask(ctx, &task, err)
	}
	loop.Status = "completed"
	loop.StopReason = "first-stage bootstrap loop completed"
	if err := o.db.WithContext(ctx).Save(&loop).Error; err != nil {
		return o.failTask(ctx, &task, err)
	}
	if err := o.compactor.Compact(ctx, task.ID); err != nil {
		return o.failTask(ctx, &task, err)
	}
	task.ProgressStage = "正在生成交付报告"
	task.ProgressPercent = 92
	if err := o.db.WithContext(ctx).Save(&task).Error; err != nil {
		return err
	}
	if _, err := o.reports.Generate(ctx, task.ID); err != nil {
		return o.failTask(ctx, &task, err)
	}
	finished = time.Now().UTC()
	task.Status = model.TaskStatusCompleted
	task.ProgressStage = "报告已生成"
	task.ProgressPercent = 100
	task.FinishedAt = &finished
	if err := o.db.WithContext(ctx).Save(&task).Error; err != nil {
		return err
	}
	appendAuditEvent(ctx, o.db, &task.ID, "agent.completed", "agent-runtime", "Task completed with evidence-backed report.", nil)
	return nil
}

func (o *AgentOrchestrator) cleanupTaskWorkerContainer(taskID uint) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := runner.NewRunnerManager(o.cfg).StopTaskWorkerContainer(cleanupCtx, taskID); err != nil {
		appendAuditEvent(context.Background(), o.db, &taskID, "agent.worker_container_cleanup_failed", "agent-runtime", err.Error(), nil)
	}
}

func (o *AgentOrchestrator) runLoopIterations(ctx context.Context, task *model.AISecurityTask, loop *model.AIAgentLoop) error {
	cairn := NewCairnLoop(o.db, o.blackboard, o.intents, o.toolRuns, o.findings, o.contracts, o.models, o.reports, o.compactor)
	consecutiveNoProgress := 0
	lastExpansionCount := o.graphExpansionCount(ctx, task.ID)

	for iterationNo := 1; iterationNo <= o.cfg.MaxIterations; iterationNo++ {
		// === STEP 1: Check termination ===
		if cairn.ShouldFinalizeWithNoProgressLimit(ctx, *task, iterationNo, o.cfg.MaxIterations, consecutiveNoProgress, o.noProgressFinalizeRounds()) {
			appendAuditEvent(ctx, o.db, &task.ID, "agent.cairn_finalize", "agent-runtime",
				fmt.Sprintf("Cairn loop finalizing at iteration %d: promoting capabilities to findings.", iterationNo), nil)
			// Promote verified capabilities to findings before report
			_ = cairn.PromoteCapabilitiesToFindings(ctx, *task)
			return nil
		}

		// === STEP 2: Pick next intent (Explore phase) ===
		_ = NewStateExpansionPlannerService(o.db).ScorePendingValidationIntents(ctx, *task)
		_, _ = NewExplorationBudgetManager(o.db).SuppressLowValueBranchesFor(ctx, task.ID, DefaultExplorationBudgetConfig(), "pre_next_pending_suppression")
		intent, err := o.intents.NextPending(ctx, task.ID)
		if err != nil {
			return err
		}

		if intent == nil {
			// === STEP 3: Reason phase — ask model to generate next intents ===
			task.ProgressStage = fmt.Sprintf("Cairn 推理中 (迭代 %d/%d)", iterationNo, o.cfg.MaxIterations)
			task.ProgressPercent = 30 + (iterationNo*60)/o.cfg.MaxIterations
			_ = o.db.WithContext(ctx).Save(task).Error

			createdIntent, err := o.runReasonPhase(ctx, task, loop, iterationNo, consecutiveNoProgress)
			if err != nil {
				return err
			}
			if !createdIntent {
				consecutiveNoProgress++
				if consecutiveNoProgress >= o.noProgressFinalizeRounds() {
					appendAuditEvent(ctx, o.db, &task.ID, "agent.no_progress", "agent-runtime",
						fmt.Sprintf("No new intents for %d consecutive rounds. Finalizing.", consecutiveNoProgress), nil)
					_ = cairn.PromoteCapabilitiesToFindings(ctx, *task)
					return nil
				}
				continue
			}
			consecutiveNoProgress = 0
			continue
		}

		// === STEP 4: Execute intent (Explore phase) ===
		task.ProgressStage = fmt.Sprintf("探索: %s", intent.Title)
		task.ProgressPercent = 30 + (iterationNo*60)/o.cfg.MaxIterations
		_ = o.db.WithContext(ctx).Save(task).Error

		workerName := "worker:cairn-native"
		var selectedWorker *WorkerRuntimeSelection
		if o.models != nil {
			if selected, ok, selectErr := o.models.SelectWorkerForIntent(ctx, task.ID, intent); selectErr != nil {
				appendAuditEvent(ctx, o.db, &task.ID, "agent.worker_select_failed", "agent-runtime", selectErr.Error(), map[string]any{"intentId": intent.ID})
			} else if ok {
				workerName = selected.WorkerID
				workerCopy := selected
				selectedWorker = &workerCopy
				appendAuditEvent(ctx, o.db, &task.ID, "agent.worker_selected", "agent-runtime",
					fmt.Sprintf("Selected worker model %s for intent %d.", selected.Config.Name, intent.ID),
					map[string]any{
						"intentId":   intent.ID,
						"intentType": intent.IntentType,
						"workerId":   selected.WorkerID,
						"modelId":    selected.Config.ID,
						"model":      selected.Config.Model,
						"provider":   selected.Config.Provider,
						"priority":   selected.Priority,
						"running":    selected.Running,
						"maxRunning": selected.MaxRunning,
						"taskTypes":  selected.TaskTypes,
					})
			}
		}
		if err := o.intents.Claim(ctx, intent, workerName, o.intentClaimLease(selectedWorker)); err != nil {
			return err
		}
		if err := o.runSingleIteration(ctx, task, loop, intent, iterationNo, selectedWorker); err != nil {
			return err
		}

		// === STEP 5: Reflect — graph expansion, not finding count, drives continuation ===
		currentExpansionCount := o.graphExpansionCount(ctx, task.ID)
		if currentExpansionCount > lastExpansionCount {
			lastExpansionCount = currentExpansionCount
			consecutiveNoProgress = 0
		} else {
			consecutiveNoProgress++
		}
	}

	// Budget exhausted — finalize with what we have
	appendAuditEvent(ctx, o.db, &task.ID, "agent.budget_exhausted", "agent-runtime",
		fmt.Sprintf("Cairn loop completed %d iterations. Promoting capabilities and generating report.", o.cfg.MaxIterations), nil)
	_ = cairn.PromoteCapabilitiesToFindings(ctx, *task)
	return nil
}

func (o *AgentOrchestrator) graphExpansionCount(ctx context.Context, taskID uint) int64 {
	var facts, evidence, hypotheses, caps, negatives, risks, pendingIntents int64
	_ = o.db.WithContext(ctx).Model(&model.AIBlackboardNode{}).Where("task_id = ? AND status = ?", taskID, model.BlackboardNodeStatusActive).Count(&facts).Error
	_ = o.db.WithContext(ctx).Model(&model.AIEvidence{}).Where("task_id = ?", taskID).Count(&evidence).Error
	_ = o.db.WithContext(ctx).Model(&model.AIHypothesisNode{}).Where("task_id = ?", taskID).Count(&hypotheses).Error
	_ = o.db.WithContext(ctx).Model(&model.AICapability{}).Where("task_id = ?", taskID).Count(&caps).Error
	_ = o.db.WithContext(ctx).Model(&model.AINegativeFact{}).Where("task_id = ?", taskID).Count(&negatives).Error
	_ = o.db.WithContext(ctx).Model(&model.AIUnverifiedRisk{}).Where("task_id = ?", taskID).Count(&risks).Error
	_ = o.db.WithContext(ctx).Model(&model.AIIntent{}).Where("task_id = ? AND status = ?", taskID, model.IntentStatusPending).Count(&pendingIntents).Error
	return facts + evidence + hypotheses + caps + negatives + risks + pendingIntents
}

func (o *AgentOrchestrator) supportingEvidenceForIntent(ctx context.Context, intent *model.AIIntent, evidenceItems []model.AIEvidence, outcomes []ToolRunOutcome) ([]uint, bool, string) {
	_ = ctx
	meta := intent.ValidationMetadata()
	for _, outcome := range outcomes {
		if outcome.Result != nil && workerMetadataInt(outcome.Result.Metadata, "workerNegativeFacts") > 0 {
			return nil, true, "Worker returned NegativeFact for this validation path."
		}
		if outcome.Result != nil && workerMetadataBool(outcome.Result.Metadata, "workerOutputRepaired") {
			return evidenceIDsFromItems(evidenceItems), true, model.UnverifiedReasonMethodNotObservable + ": Pi worker returned unstructured output, so Rabbit preserved it as observation-only evidence instead of treating it as hypothesis validation."
		}
	}
	if meta.ExpectedCapability == model.CapInternalServiceAccess || meta.ExpectedCapability == model.CapSourceCodeRead {
		return evidenceIDsFromItems(evidenceItems), false, ""
	}
	supporting := []uint{}
	for _, outcome := range outcomes {
		if outcome.ToolRun.Status != model.ToolRunStatusSuccess {
			continue
		}
		if outcomeSupportsCapability(outcome, meta.ExpectedCapability) {
			for _, item := range outcome.Evidence {
				supporting = appendUniqueUint(supporting, item.ID)
			}
		}
	}
	if len(supporting) > 0 {
		return supporting, false, ""
	}
	if len(evidenceItems) == 0 {
		return nil, true, "Validation produced no evidence."
	}
	if meta.ExpectedCapability == model.CapSQLInjection {
		return nil, true, model.UnverifiedReasonMethodNotObservable + ": current SQL injection validation method did not produce SQL error, boolean/time differential, reflected UNION output, or another supporting proof signal. This records a method-level fact, not a route-level disproof."
	}
	if allEvidenceIsNegativeObservation(evidenceItems, outcomes) {
		return nil, true, model.UnverifiedReasonMethodNotObservable + ": current validation method produced only no-difference observations; alternate interaction context or validation method may still be required."
	}
	return evidenceIDsFromItems(evidenceItems), false, ""
}

func (o *AgentOrchestrator) capabilityTargetFromEvidence(ctx context.Context, evidenceIDs []uint, intent *model.AIIntent) string {
	items := o.loadEvidenceByIDs(ctx, evidenceIDs)
	for _, item := range items {
		if url := evidenceValidationURL(item); strings.TrimSpace(url) != "" {
			return url
		}
	}
	for _, item := range items {
		if strings.TrimSpace(item.Target) != "" {
			return item.Target
		}
	}
	return firstNonEmpty(intent.Objective, intent.Title)
}

type capabilityEvidenceGroup struct {
	Target      string
	EvidenceIDs []uint
}

func (o *AgentOrchestrator) capabilityEvidenceGroups(ctx context.Context, capability string, evidenceIDs []uint, intent *model.AIIntent) []capabilityEvidenceGroup {
	if capability != model.CapSQLInjection {
		return []capabilityEvidenceGroup{{
			Target:      o.capabilityTargetFromEvidence(ctx, evidenceIDs, intent),
			EvidenceIDs: evidenceIDs,
		}}
	}
	items := o.loadEvidenceByIDs(ctx, evidenceIDs)
	grouped := map[string][]uint{}
	order := []string{}
	for _, item := range items {
		target := evidenceEndpointKey(item)
		if strings.TrimSpace(target) == "" {
			target = o.capabilityTargetFromEvidence(ctx, []uint{item.ID}, intent)
		}
		if strings.TrimSpace(target) == "" {
			continue
		}
		if _, ok := grouped[target]; !ok {
			order = append(order, target)
		}
		grouped[target] = appendUniqueUint(grouped[target], item.ID)
	}
	if len(order) == 0 {
		return []capabilityEvidenceGroup{{
			Target:      o.capabilityTargetFromEvidence(ctx, evidenceIDs, intent),
			EvidenceIDs: evidenceIDs,
		}}
	}
	sort.Strings(order)
	groups := make([]capabilityEvidenceGroup, 0, len(order))
	for _, target := range order {
		groups = append(groups, capabilityEvidenceGroup{Target: target, EvidenceIDs: grouped[target]})
	}
	return groups
}

func evidenceEndpointKey(item model.AIEvidence) string {
	return endpointWithoutPayload(evidenceValidationURL(item))
}

func endpointWithoutPayload(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return strings.TrimSpace(rawURL)
	}
	query := parsed.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := url.Values{}
	for _, key := range keys {
		values.Set(key, "")
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func (o *AgentOrchestrator) deliveryProofSummaryForCapability(ctx context.Context, task model.AISecurityTask, intent model.AIIntent, capability string, evidenceIDs []uint) string {
	items := o.loadEvidenceByIDs(ctx, evidenceIDs)
	entrypoint := firstNonEmpty(taskTargetSummary(ctx, o.db, task.ID), intent.Objective, intent.Title)
	validationURL := ""
	baseline := ""
	validation := ""
	requestPacket := ""
	for _, item := range items {
		if url := evidenceValidationURL(item); validationURL == "" && url != "" {
			validationURL = url
		}
		if strings.TrimSpace(item.Summary) != "" {
			if validation == "" {
				validation = item.Summary
			} else if !strings.Contains(validation, item.Summary) {
				validation += "; " + item.Summary
			}
		}
		if requestPacket == "" {
			requestPacket = evidenceRequestPacket(item)
		}
	}
	if validationURL != "" {
		entrypoint = validationURL
	}
	if baseline == "" {
		baseline = "baseline request captured in paired HTTP evidence"
	}
	if validation == "" {
		validation = fmt.Sprintf("validation intent %d produced supporting evidence", intent.ID)
	}
	if requestPacket == "" && validationURL != "" {
		requestPacket = requestPacketFromURL(validationURL)
	}
	if requestPacket == "" {
		requestPacket = "未形成可交付证据"
	}
	curlCmd := "未形成可交付证据"
	pythonCmd := "未形成可交付证据"
	if validationURL != "" {
		curlCmd = "curl -i " + shellQuote(validationURL)
		pythonCmd = "import requests\nrequests.get(" + strconv.Quote(validationURL) + ", timeout=10)"
	}
	details := map[string]any{
		"entrypoint":                  entrypoint,
		"controlled_input":            controlledInputFromURL(validationURL),
		"propagation_path":            "authorized request input produced a validated behavioral response difference",
		"sensitive_sink_or_behavior":  capability,
		"trigger_payload_or_action":   firstNonEmpty(validationURL, intent.Title),
		"baseline_evidence":           baseline,
		"validation_evidence":         validation,
		"observed_result":             validation,
		"impact_explanation":          impactForCapability(capability),
		"scope_statement":             "authorized task scope only",
		"safety_statement":            "non-destructive validation; no destructive state change was required",
		"remediation":                 remediationForCapability(capability),
		"retest_steps":                "repeat the baseline and validation requests after remediation and confirm the differential signal is gone",
		"evidence_mapping":            evidenceIDs,
		"request_packet":              requestPacket,
		"bash_poc":                    curlCmd,
		"python_poc":                  pythonCmd,
		"success_criteria":            "validation response no longer exposes the previously observed differential signal",
		"root_cause":                  rootCauseForCapability(capability),
		"validated_by_intent_id":      intent.ID,
		"validation_intent_type":      intent.IntentType,
		"validation_intent_objective": intent.Objective,
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Sprintf("Hypothesis-backed validation intent %d produced %d supporting evidence item(s).", intent.ID, len(evidenceIDs))
	}
	return string(raw)
}

func (o *AgentOrchestrator) loadEvidenceByIDs(ctx context.Context, ids []uint) []model.AIEvidence {
	if len(ids) == 0 {
		return nil
	}
	var items []model.AIEvidence
	_ = o.db.WithContext(ctx).Where("id IN ?", ids).Order("id asc").Find(&items).Error
	return items
}

func evidenceValidationURL(item model.AIEvidence) string {
	var req map[string]any
	if len(item.RequestSnapshot) > 0 && json.Unmarshal(item.RequestSnapshot, &req) == nil {
		if urlValue, ok := req["url"].(string); ok && strings.TrimSpace(urlValue) != "" {
			return urlValue
		}
	}
	var resp map[string]any
	if len(item.ResponseSnapshot) > 0 && json.Unmarshal(item.ResponseSnapshot, &resp) == nil {
		if urlValue, ok := resp["validationUrl"].(string); ok && strings.TrimSpace(urlValue) != "" {
			return urlValue
		}
	}
	return item.Target
}

func evidenceRequestPacket(item model.AIEvidence) string {
	var req map[string]any
	if len(item.RequestSnapshot) == 0 || json.Unmarshal(item.RequestSnapshot, &req) != nil {
		return ""
	}
	method, _ := req["method"].(string)
	if strings.TrimSpace(method) == "" {
		method = http.MethodGet
	}
	rawURL, _ := req["url"].(string)
	return requestPacketFromMethodURL(method, rawURL)
}

func requestPacketFromURL(rawURL string) string {
	return requestPacketFromMethodURL(http.MethodGet, rawURL)
}

func requestPacketFromMethodURL(method, rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s %s HTTP/1.1\nHost: %s", strings.ToUpper(method), path, parsed.Host)
}

func controlledInputFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "authorized validation input"
	}
	params := []string{}
	for key := range parsed.Query() {
		params = append(params, key)
	}
	sort.Strings(params)
	if len(params) == 0 {
		return "authorized validation input"
	}
	return "query parameter(s): " + strings.Join(params, ", ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func impactForCapability(capability string) string {
	switch capability {
	case model.CapSQLInjection:
		return "validated SQL injection behavior may allow unauthorized data access or query manipulation inside the authorized application scope"
	case model.CapCrossUserObjectAccess, model.CapArbitraryObjectAccess:
		return "validated authorization boundary weakness may allow access to another actor's object inside scope"
	default:
		return "validated capability can affect protected application behavior inside scope"
	}
}

func remediationForCapability(capability string) string {
	switch capability {
	case model.CapSQLInjection:
		return "use parameterized queries, remove dynamic SQL string concatenation, validate input types, and add regression tests for the affected parameter"
	case model.CapCrossUserObjectAccess, model.CapArbitraryObjectAccess:
		return "enforce server-side object ownership and role checks on every affected read and write path"
	default:
		return "enforce server-side validation and authorization on the affected path and add regression coverage"
	}
}

func rootCauseForCapability(capability string) string {
	switch capability {
	case model.CapSQLInjection:
		return "user-controlled request input reaches SQL execution without sufficient parameterization or input handling"
	case model.CapCrossUserObjectAccess, model.CapArbitraryObjectAccess:
		return "object access is not consistently constrained by actor ownership or authorization policy"
	default:
		return "server-side trust boundary is incomplete for the affected behavior"
	}
}

func taskTargetSummary(ctx context.Context, db *gorm.DB, taskID uint) string {
	var target model.AITaskTarget
	if err := db.WithContext(ctx).
		Where("task_id = ? AND scope_status = ?", taskID, "in_scope").
		Order("id asc").
		First(&target).Error; err != nil {
		return ""
	}
	return target.Value
}

func outcomeSupportsCapability(outcome ToolRunOutcome, capability string) bool {
	if outcome.Result == nil {
		return false
	}
	text := strings.ToLower(strings.Join([]string{
		outcome.Result.Summary,
		outcome.Result.Stdout,
		outcome.Result.Stderr,
		string(outcome.ToolRun.InputJSON),
	}, "\n"))
	if strings.Contains(text, "no observable diff") || strings.Contains(text, "no observable difference") {
		return false
	}
	switch capability {
	case model.CapSQLInjection:
		if containsSQLiProofSignal(text) {
			return true
		}
		// SQL injection needs a SQL-specific proof signal. A generic body
		// length change is too weak, especially when the server returns a
		// redirect page that only reflects the requested URL.
		return false
	default:
		if statusDiff, _ := outcome.Result.Metadata["statusDiff"].(bool); statusDiff {
			return true
		}
		if lengthDiff, _ := outcome.Result.Metadata["lengthDiff"].(bool); lengthDiff {
			return true
		}
		if markerFound, _ := outcome.Result.Metadata["markerFound"].(bool); markerFound {
			return true
		}
		if statusChanged, _ := outcome.Result.Metadata["statusChanged"].(bool); statusChanged {
			return true
		}
		if bodyChanged, _ := outcome.Result.Metadata["bodyChanged"].(bool); bodyChanged {
			return true
		}
		return strings.TrimSpace(outcome.Result.Stdout) != "" && !strings.Contains(text, "no observable")
	}
}

func outcomesSupportExpectedCapability(intent *model.AIIntent, outcomes []ToolRunOutcome) bool {
	expected := intentExpectedCapability(intent)
	if expected == "" {
		return false
	}
	for _, outcome := range outcomes {
		if outcome.ToolRun.Status == model.ToolRunStatusSuccess && outcomeSupportsCapability(outcome, expected) {
			return true
		}
	}
	return false
}

func workerMetadataInt(metadata map[string]any, key string) int {
	if metadata == nil {
		return 0
	}
	switch value := metadata[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case float32:
		return int(value)
	default:
		return 0
	}
}

func workerMetadataBool(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	switch value := metadata[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func containsSQLiProofSignal(text string) bool {
	signals := []string{
		"you have an error in your sql syntax",
		"mysql server version",
		"warning: mysql",
		"mariadb",
		"sql syntax",
		"odbc sql",
		"postgresql error",
		"ora-",
		"unclosed quotation mark",
		"sql 错误",
		"sql 语法",
		"sql 注入",
		"错误型 sql",
		"your login name:2",
		"your password:3",
	}
	for _, signal := range signals {
		if strings.Contains(text, signal) {
			return true
		}
	}
	return false
}

func allEvidenceIsNegativeObservation(items []model.AIEvidence, outcomes []ToolRunOutcome) bool {
	if len(items) == 0 {
		return false
	}
	negative := 0
	for _, item := range items {
		text := strings.ToLower(item.Summary + "\n" + item.Title)
		if strings.Contains(text, "no observable diff") || strings.Contains(text, "no observable difference") || strings.Contains(text, "no supporting evidence") {
			negative++
		}
	}
	for _, outcome := range outcomes {
		if outcome.Result == nil {
			continue
		}
		text := strings.ToLower(outcome.Result.Summary)
		if strings.Contains(text, "no observable diff") || strings.Contains(text, "no observable difference") {
			negative++
		}
	}
	return negative > 0 && negative >= len(items)/2
}

func firstNonEmptyUintSlice(primary []uint, fallback []uint) []uint {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func (o *AgentOrchestrator) writeTestedPathFact(ctx context.Context, taskID uint, intent *model.AIIntent, outcomes []ToolRunOutcome, evidenceIDs []uint, validationFailed bool, reason string) {
	if intent == nil || o.blackboard == nil {
		return
	}
	toolNames := []string{}
	statuses := []string{}
	for _, outcome := range outcomes {
		if outcome.ToolRun.ToolName != "" {
			toolNames = append(toolNames, outcome.ToolRun.ToolName)
		}
		if outcome.ToolRun.Status != "" {
			statuses = append(statuses, outcome.ToolRun.Status)
		}
	}
	summary := "Validation method executed and produced evidence for graph reasoning."
	if validationFailed {
		summary = firstNonEmpty(reason, "Validation method did not support the expected capability.")
	} else if len(evidenceIDs) > 0 {
		summary = "Validation method produced evidence that can support or refine the current hypothesis."
	}
	node, err := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeTestedPath,
		Title:           "Tested path: " + firstNonEmpty(intent.Title, intent.Objective, intent.IntentType),
		Summary:         summary,
		Content:         map[string]any{"intentId": intent.ID, "intentType": intent.IntentType, "tools": toolNames, "statuses": statuses, "validationFailed": validationFailed, "reason": reason},
		DedupSeed:       fmt.Sprintf("tested-path-%d-%s", intent.ID, strings.Join(statuses, ",")),
		ImportanceScore: 0.66,
		SourceType:      "agent",
		SourceID:        fmt.Sprintf("intent-%d", intent.ID),
		EvidenceRefs:    evidenceIDs,
	})
	if err != nil || node.ID == 0 {
		return
	}
	if parentID := blackboardNodeIDForIntent(ctx, o.db, taskID, intent.ID); parentID != 0 {
		_ = o.blackboard.AddEdge(ctx, taskID, parentID, node.ID, model.EdgeProduces, 0.72, map[string]any{"intentId": intent.ID, "evidenceIds": evidenceIDs})
	}
}

func (o *AgentOrchestrator) ingestPlannerNextIntents(ctx context.Context, task *model.AISecurityTask, parent *model.AIIntent, plan IterationPlan, evidenceIDs []uint) int {
	if task == nil || parent == nil || len(plan.NextIntents) == 0 {
		return 0
	}
	requested := len(plan.NextIntents)
	limit := o.plannerNextIntentLimit()
	if requested > limit {
		requested = limit
	}
	decision := NewExplorationBudgetManager(o.db).AllowIntentGenerationFor(ctx, task.ID, requested, DefaultExplorationBudgetConfig(), "iteration_planner")
	if !decision.Allowed {
		appendAuditEvent(ctx, o.db, &task.ID, "planner.next_intents_blocked", "exploration-budget-manager", decision.Reason, map[string]any{"parentIntentId": parent.ID, "decision": decision})
		return 0
	}
	allowed := decision.MaxToGenerate
	if allowed > limit {
		allowed = limit
	}
	created := 0
	for _, suggestion := range plan.NextIntents {
		if allowed <= 0 {
			break
		}
		if o.createPlannerSuggestedIntent(ctx, task.ID, parent, suggestion, evidenceIDs) {
			created++
			allowed--
		}
	}
	if created > 0 {
		appendAuditEvent(ctx, o.db, &task.ID, "planner.next_intents_created", "model-runtime", "Planner suggestions were converted into evidence-seeking Intents.", map[string]any{"parentIntentId": parent.ID, "created": created})
	}
	return created
}

func (o *AgentOrchestrator) createPlannerSuggestedIntent(ctx context.Context, taskID uint, parent *model.AIIntent, suggestion SecurityGraphIntentSuggestion, evidenceIDs []uint) bool {
	title := firstNonEmpty(strings.TrimSpace(suggestion.Title), strings.TrimSpace(suggestion.Objective))
	objective := firstNonEmpty(strings.TrimSpace(suggestion.Objective), title)
	if title == "" || objective == "" {
		return false
	}
	if NewCairnLoop(o.db, o.blackboard, o.intents, o.toolRuns, o.findings, o.contracts, o.models, o.reports, o.compactor).intentMatchesNegativeFact(ctx, taskID, title, objective) {
		return false
	}
	intentType, ok := workerSuggestedIntentType(suggestion.IntentType)
	if !ok {
		appendAuditEvent(ctx, o.db, &taskID, "planner.unsupported_intent_skipped", "model-runtime", "Planner suggested an unsupported runtime intent; skipped.", map[string]any{"parentIntentId": parent.ID, "intentType": suggestion.IntentType})
		return false
	}
	var existing int64
	_ = o.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("task_id = ? AND intent_type = ? AND objective = ? AND status IN ?", taskID, intentType, objective, []string{model.IntentStatusPending, model.IntentStatusRunning, model.IntentStatusCompleted}).
		Count(&existing).Error
	if existing > 0 {
		return false
	}
	parentNodeID := blackboardNodeIDForIntent(ctx, o.db, taskID, parent.ID)
	lifecycle := NewHypothesisLifecycleService(o.db, o.blackboard)
	hypothesis, err := lifecycle.FormHypothesis(ctx, plannerSuggestionHypothesisDraft(taskID, parent.ID, parentNodeID, suggestion, evidenceIDs))
	if err != nil {
		return false
	}
	intent, err := lifecycle.CreateValidationIntent(ctx, hypothesis, intentType, "planner_suggested_followup", 0.7)
	if err != nil {
		return false
	}
	intent.CreatedBy = "model-planner"
	intent.CreatedReason = "Iteration planner suggested follow-up exploration from graph facts; StateExpansionPlanner and NextPending still control execution."
	intent.RequiredEvidence = mustJSON(suggestion.RequiredEvidence)
	intent.Objective = objective
	values := map[string]any{}
	_ = json.Unmarshal(intent.ConstraintsJSON, &values)
	values["source"] = "iteration_planner"
	values["parentIntentId"] = parent.ID
	values["evidenceIds"] = evidenceIDs
	intent.ConstraintsJSON = mustJSON(values)
	intent.UpdatedAt = time.Now().UTC()
	if err := o.db.WithContext(ctx).Save(&intent).Error; err != nil {
		return false
	}
	intentNode, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeIntent,
		Title:           intent.Title,
		Summary:         intent.Objective,
		Content:         intent,
		DedupSeed:       fmt.Sprintf("intent-%d", intent.ID),
		ImportanceScore: intent.PriorityScore,
		SourceType:      "model-planner",
		SourceID:        fmt.Sprintf("%d", intent.ID),
		EvidenceRefs:    evidenceIDs,
	})
	if parentNodeID != 0 && intentNode.ID != 0 {
		_ = o.blackboard.AddEdge(ctx, taskID, parentNodeID, intentNode.ID, model.EdgeSpawnedIntent, 0.78, map[string]any{"parentIntentId": parent.ID, "intentId": intent.ID})
	}
	return true
}

func plannerSuggestionHypothesisDraft(taskID uint, parentIntentID uint, parentNodeID uint, suggestion SecurityGraphIntentSuggestion, evidenceIDs []uint) HypothesisDraft {
	title := firstNonEmpty(suggestion.Title, suggestion.Objective)
	description := firstNonEmpty(suggestion.Objective, suggestion.Title)
	sourceRefs := []string{fmt.Sprintf("planner_intent:%d", parentIntentID)}
	if parentNodeID != 0 {
		sourceRefs = append(sourceRefs, fmt.Sprintf("blackboard_node:%d", parentNodeID))
	}
	for _, evidenceID := range evidenceIDs {
		sourceRefs = append(sourceRefs, fmt.Sprintf("evidence:%d", evidenceID))
	}
	return HypothesisDraft{
		TaskID:                taskID,
		HypothesisType:        workerHypothesisTypeForIntent(suggestion.IntentType),
		Title:                 title,
		Description:           description,
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: sourceRefs,
		TargetEntity:          firstNonEmpty(suggestion.Objective, suggestion.Title),
		ExpectedCapability:    workerExpectedCapabilityForIntent(suggestion.IntentType),
	}
}

func (o *AgentOrchestrator) runReasonPhase(ctx context.Context, task *model.AISecurityTask, loop *model.AIAgentLoop, iterationNo int, reasonPasses int) (bool, error) {
	if reasonPasses >= o.reasonNoOpPassBudget() {
		appendAuditEvent(ctx, o.db, &task.ID, "agent.reason_budget_exhausted", "agent-runtime", "Reason phase stopped after repeated no-op graph decisions.", map[string]any{"reasonPasses": reasonPasses, "budget": o.reasonNoOpPassBudget()})
		return false, nil
	}
	if o.models == nil || task.ModelConfigID == nil {
		appendAuditEvent(ctx, o.db, &task.ID, "agent.reason_unavailable", "model-runtime", "No model config available; cannot continue Cairn-style graph reasoning.", nil)
		return false, nil
	}
	task.ProgressStage = "大模型正在进行全局图推理"
	task.ProgressPercent = 72
	_ = o.db.WithContext(ctx).Save(task)
	reasonIntent := &model.AIIntent{
		TaskID:     task.ID,
		IntentType: "reason",
		Title:      "全局图推理",
		Objective:  "Read the blackboard graph, decide whether the goal is sufficiently supported, and propose high-value next intents if not.",
		CreatedBy:  "agent",
	}
	callMeta := o.models.IterationCallMetadata(ctx, *task, reasonIntent)
	started := time.Now()
	iteration := model.AIAgentLoopIteration{
		LoopID:          loop.ID,
		TaskID:          task.ID,
		IterationNo:     iterationNo,
		InputContextRef: fmt.Sprintf("task-%d/context/reason-%d", task.ID, time.Now().UnixNano()),
		ModelProvider:   callMeta.Provider,
		ModelName:       callMeta.Model,
		ThoughtSummary:  "模型读取 Fact/Intent/Evidence 图，判断是否继续探索或收束报告。",
		PlannedAction:   "reason over blackboard graph and create next intents when valuable",
		Status:          "running",
		StartedAt:       time.Now().UTC(),
	}
	if err := o.db.WithContext(ctx).Create(&iteration).Error; err != nil {
		return false, err
	}
	reasonNode, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          task.ID,
		NodeType:        "intent",
		Title:           reasonIntent.Title,
		Summary:         reasonIntent.Objective,
		Content:         map[string]any{"loopId": loop.ID, "iterationId": iteration.ID, "reasonPass": reasonPasses + 1},
		DedupSeed:       fmt.Sprintf("reason-intent-%d-%d", loop.ID, iteration.ID),
		ImportanceScore: 0.82,
		SourceType:      "agent",
		SourceID:        fmt.Sprintf("iteration-%d", iteration.ID),
	})
	if reasonNode.ID != 0 {
		reasonIntent.ParentNodeID = &reasonNode.ID
	}
	var beforePending int64
	_ = o.db.WithContext(ctx).Model(&model.AIIntent{}).Where("task_id = ? AND status = ?", task.ID, model.IntentStatusPending).Count(&beforePending).Error
	items := o.loadTaskEvidenceItems(ctx, task.ID, 80)
	snippets := []CodeAuditSnippet(nil)
	if task.TaskType == model.TaskTypeCodeAudit || task.TaskType == model.TaskTypeHybrid {
		snippets = o.buildCodeAuditSnippets(task, items, min(o.codeAuditMaxSnippets(), 180))
	}
	metadata, failures := o.reasonOverSecurityGraph(ctx, task, reasonIntent, items, snippets)
	metadata.LatencyMs = time.Since(started).Milliseconds()
	var afterPending int64
	_ = o.db.WithContext(ctx).Model(&model.AIIntent{}).Where("task_id = ? AND status = ?", task.ID, model.IntentStatusPending).Count(&afterPending).Error
	createdIntent := afterPending > beforePending
	status := "completed"
	var finishErr error
	if len(failures) > 0 && !createdIntent {
		appendAuditEvent(ctx, o.db, &task.ID, "agent.reason_noop", "model-runtime", strings.Join(failures, " | "), map[string]any{
			"provider":  metadata.Provider,
			"model":     metadata.Model,
			"latencyMs": metadata.LatencyMs,
		})
	}
	iteration.ToolRunIDs = mustJSON([]uint{})
	iteration.EvidenceRefs = mustJSON(evidenceIDsFromItems(items))
	iteration.BlackboardDelta = mustJSON(map[string]any{
		"reasonPass":      reasonPasses + 1,
		"createdIntent":   createdIntent,
		"pendingBefore":   beforePending,
		"pendingAfter":    afterPending,
		"evidenceContext": len(items),
		"snippetContext":  len(snippets),
	})
	finishErr = o.finishIteration(ctx, &iteration, status, nil)
	return createdIntent, finishErr
}

func (o *AgentOrchestrator) runSingleIteration(ctx context.Context, task *model.AISecurityTask, loop *model.AIAgentLoop, currentIntent *model.AIIntent, iterationNo int, selectedWorker *WorkerRuntimeSelection) error {
	agentContext, err := o.context.Build(ctx, task.ID, currentIntent, 32)
	if err != nil {
		return err
	}
	intentNode, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          task.ID,
		NodeType:        "intent",
		Title:           currentIntent.Title,
		Summary:         currentIntent.Objective,
		Content:         currentIntent,
		DedupSeed:       fmt.Sprintf("intent-%d", currentIntent.ID),
		ImportanceScore: 0.86,
		SourceType:      currentIntent.CreatedBy,
		SourceID:        fmt.Sprintf("%d", currentIntent.ID),
	})
	if intentNode.ID != 0 && currentIntent.ParentNodeID != nil {
		_ = o.blackboard.AddEdge(ctx, task.ID, *currentIntent.ParentNodeID, intentNode.ID, "spawned_intent", 0.88, map[string]any{"intentId": currentIntent.ID})
	}
	callMeta := o.models.IterationCallMetadata(ctx, *task, currentIntent)
	startedModelCall := time.Now()
	plan, err := o.models.PlanIteration(ctx, *task, currentIntent, agentContext)
	callMeta.LatencyMs = time.Since(startedModelCall).Milliseconds()
	if err != nil {
		appendAuditEvent(ctx, o.db, &task.ID, "agent.model_fallback", "model-runtime", err.Error(), map[string]any{
			"intentId":   currentIntent.ID,
			"intentType": currentIntent.IntentType,
			"provider":   callMeta.Provider,
			"model":      callMeta.Model,
			"latencyMs":  callMeta.LatencyMs,
			"fallbackTo": "deterministic-runtime",
		})
		plan = o.models.FallbackIterationPlan(ctx, *task, currentIntent)
	} else {
		appendAuditEvent(ctx, o.db, &task.ID, "agent.model_plan", "model-runtime", "Model-assisted iteration plan generated.", map[string]any{
			"intentId":   currentIntent.ID,
			"intentType": currentIntent.IntentType,
			"provider":   callMeta.Provider,
			"model":      callMeta.Model,
			"latencyMs":  callMeta.LatencyMs,
		})
	}
	contextRef := fmt.Sprintf("task-%d/context/bootstrap-%d", task.ID, time.Now().UnixNano())
	iteration := model.AIAgentLoopIteration{
		LoopID:          loop.ID,
		TaskID:          task.ID,
		IterationNo:     iterationNo,
		InputContextRef: contextRef,
		ModelProvider:   plan.ModelProvider,
		ModelName:       plan.ModelName,
		ThoughtSummary:  plan.ThoughtSummary,
		PlannedAction:   plan.PlannedAction,
		Status:          "running",
		StartedAt:       time.Now().UTC(),
	}
	iteration.CurrentIntentID = &currentIntent.ID
	if err := o.db.WithContext(ctx).Create(&iteration).Error; err != nil {
		return err
	}
	var outcomes []ToolRunOutcome
	if selectedWorker != nil {
		handled, workerOutcomes, workerErr := o.runExternalWorkerIntent(ctx, task, currentIntent, &iteration, agentContext, *selectedWorker)
		if handled && workerErr == nil {
			outcomes = append(outcomes, workerOutcomes...)
		} else if handled && workerErr != nil {
			appendAuditEvent(ctx, o.db, &task.ID, "agent.worker_execution_failed", "agent-runtime",
				"External worker failed; Rabbit will not silently replace it with a native runner.",
				map[string]any{"intentId": currentIntent.ID, "workerId": selectedWorker.WorkerID, "error": workerErr.Error()})
			return o.finishIteration(ctx, &iteration, "failed", workerErr)
		}
	}
	if len(outcomes) == 0 {
		switch {
		case currentIntent.IntentType == "code_trace" || currentIntent.IntentType == "collect_evidence":
			outcome, err := o.runCodeAuditIntent(ctx, task, currentIntent, &iteration)
			if err != nil {
				return o.finishIteration(ctx, &iteration, "failed", err)
			}
			outcomes = append(outcomes, outcome...)
		case isCodeAuditRuntimeIntent(currentIntent.IntentType):
			outcome, err := o.runCodeAuditIntent(ctx, task, currentIntent, &iteration)
			if err != nil {
				return o.finishIteration(ctx, &iteration, "failed", err)
			}
			outcomes = append(outcomes, outcome...)
		case currentIntent.IntentType == "recon" || currentIntent.IntentType == "validate" || currentIntent.IntentType == "fingerprint":
			more, err := o.runPentestIntent(ctx, task, currentIntent, &iteration)
			if err != nil {
				return o.finishIteration(ctx, &iteration, "failed", err)
			}
			outcomes = append(outcomes, more...)
		case isPentestRuntimeIntent(currentIntent.IntentType):
			more, err := o.runPentestIntent(ctx, task, currentIntent, &iteration)
			if err != nil {
				return o.finishIteration(ctx, &iteration, "failed", err)
			}
			outcomes = append(outcomes, more...)
		default:
			return o.finishIteration(ctx, &iteration, "failed", fmt.Errorf("unsupported intent type: %s", currentIntent.IntentType))
		}
	}
	evidenceIDs := []uint{}
	evidenceItems := []model.AIEvidence{}
	toolRunIDs := []uint{}
	toolBlocked := false
	toolFailed := false
	toolFailureReason := ""
	hypotheses := NewHypothesisLifecycleService(o.db, o.blackboard)
	for _, outcome := range outcomes {
		toolRunIDs = append(toolRunIDs, outcome.ToolRun.ID)
		_ = hypotheses.UpdateEnvironmentFromOutcome(ctx, task.ID, outcome)
		if outcome.ToolRun.Status == model.ToolRunStatusBlocked {
			toolBlocked = true
			if outcome.ToolRun.BlockReason != "" {
				toolFailureReason = outcome.ToolRun.BlockReason
			}
		}
		if outcome.ToolRun.Status == model.ToolRunStatusFailed || outcome.ToolRun.Status == model.ToolRunStatusTimeout {
			toolFailed = true
			if outcome.Result != nil && outcome.Result.Summary != "" {
				toolFailureReason = outcome.Result.Summary
			}
		}
		if outcome.Result != nil && workerMetadataInt(outcome.Result.Metadata, "workerUnverifiedRisks") > 0 {
			toolBlocked = true
			toolFailureReason = "Worker returned UnverifiedRisk; hypothesis remains inconclusive until a later validation intent resolves the blocked path."
		}
		toolRunNode, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          task.ID,
			NodeType:        "fact",
			Title:           "ToolRun: " + outcome.ToolRun.ToolName,
			Summary:         fmt.Sprintf("%s finished with status %s", outcome.ToolRun.ToolName, outcome.ToolRun.Status),
			Content:         outcome.ToolRun,
			DedupSeed:       fmt.Sprintf("toolrun-%d", outcome.ToolRun.ID),
			ImportanceScore: 0.68,
			SourceType:      "tool",
			SourceID:        fmt.Sprintf("%d", outcome.ToolRun.ID),
		})
		if intentNode.ID != 0 && toolRunNode.ID != 0 {
			_ = o.blackboard.AddEdge(ctx, task.ID, intentNode.ID, toolRunNode.ID, "executed_tool", 0.78, map[string]any{"toolRunId": outcome.ToolRun.ID})
		}
		for _, item := range outcome.Evidence {
			evidenceIDs = append(evidenceIDs, item.ID)
			evidenceItems = append(evidenceItems, item)
			evidenceNode, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
				TaskID:          task.ID,
				NodeType:        "evidence",
				Title:           item.Title,
				Summary:         item.Summary,
				Content:         item,
				DedupSeed:       fmt.Sprintf("evidence-%s-%s-%s", item.EvidenceType, item.Hash, item.FilePath),
				ImportanceScore: 0.72,
				SourceType:      "tool",
				SourceID:        fmt.Sprintf("%d", outcome.ToolRun.ID),
				EvidenceRefs:    []uint{item.ID},
			})
			if toolRunNode.ID != 0 && evidenceNode.ID != 0 {
				_ = o.blackboard.AddEdge(ctx, task.ID, toolRunNode.ID, evidenceNode.ID, "produced_evidence", 0.84, map[string]any{"evidenceId": item.ID})
			}
			factNodeIDs := o.upsertFactsFromPentestEvidence(ctx, task.ID, outcome.ToolRun, item, outcome.Result)
			factNodeIDs = append(factNodeIDs, o.upsertFactsFromCodeEvidence(ctx, task.ID, outcome.ToolRun, item, outcome.Result)...)
			for _, factNodeID := range factNodeIDs {
				if evidenceNode.ID != 0 && factNodeID != 0 {
					_ = o.blackboard.AddEdge(ctx, task.ID, evidenceNode.ID, factNodeID, "supports_fact", 0.86, map[string]any{"evidenceId": item.ID})
				}
			}
		}
	}
	_, _ = hypotheses.ExpandFromEvidence(ctx, task.ID, nonHTTPInputSurfaceEvidence(evidenceItems), ExpansionBudget{})
	_, _ = o.replenishHTTPInputSurfaceFrontier(ctx, task.ID, hypotheses)
	if currentIntent.HypothesisID() != nil {
		supportingEvidenceIDs, validationFailed, validationReason := o.supportingEvidenceForIntent(ctx, currentIntent, evidenceItems, outcomes)
		o.writeTestedPathFact(ctx, task.ID, currentIntent, outcomes, firstNonEmptyUintSlice(supportingEvidenceIDs, evidenceIDs), validationFailed, validationReason)
		_ = hypotheses.ResolveIntentResult(ctx, task.ID, *currentIntent, HypothesisResolution{
			IntentID:         currentIntent.ID,
			EvidenceIDs:      firstNonEmptyUintSlice(supportingEvidenceIDs, evidenceIDs),
			ToolBlocked:      toolBlocked,
			ToolFailed:       toolFailed,
			ValidationFailed: validationFailed,
			Reason:           firstNonEmpty(validationReason, toolFailureReason),
		})
		meta := currentIntent.ValidationMetadata()
		if meta.ExpectedCapability != "" && len(supportingEvidenceIDs) > 0 && !toolBlocked && !toolFailed && !validationFailed {
			cairn := NewCairnLoop(o.db, o.blackboard, o.intents, o.toolRuns, o.findings, o.contracts, o.models, o.reports, o.compactor)
			for _, group := range o.capabilityEvidenceGroups(ctx, meta.ExpectedCapability, supportingEvidenceIDs, currentIntent) {
				_, _ = cairn.WriteCapability(ctx, task.ID, CapabilityDraft{
					CapabilityType: meta.ExpectedCapability,
					Target:         group.Target,
					Strength:       model.StrengthVerified,
					ProofSummary:   o.deliveryProofSummaryForCapability(ctx, *task, *currentIntent, meta.ExpectedCapability, group.EvidenceIDs),
					EvidenceIDs:    group.EvidenceIDs,
					CanAdvanceGoal: true,
				}, &currentIntent.ID)
			}
		}
	}
	createdFromPlan := o.ingestPlannerNextIntents(ctx, task, currentIntent, plan, evidenceIDs)
	if createdFromPlan > 0 {
		_ = NewStateExpansionPlannerService(o.db).ScorePendingValidationIntents(ctx, *task)
	}
	iteration.ToolRunIDs = mustJSON(toolRunIDs)
	iteration.EvidenceRefs = mustJSON(evidenceIDs)
	iteration.BlackboardDelta = mustJSON(map[string]any{"evidenceCount": len(evidenceIDs), "contextFacts": len(agentContext.KeyFacts), "plannerNextIntents": createdFromPlan})
	return o.finishIteration(ctx, &iteration, "completed", nil)
}

func (o *AgentOrchestrator) runCodeAuditIntent(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration) ([]ToolRunOutcome, error) {
	root := filepath.Join(o.cfg.WorkspaceRoot, fmt.Sprintf("task-%d", task.ID), "input", "extracted")
	if hasSource, err := hasExtractedSource(root); err != nil || !hasSource {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("source archive has not been uploaded; upload a ZIP before starting code audit")
	}

	// Check if this is a per-file focused intent (has filePath in constraints)
	var constraints map[string]any
	if intent.ConstraintsJSON != nil {
		_ = json.Unmarshal(intent.ConstraintsJSON, &constraints)
	}
	targetFile, _ := constraints["filePath"].(string)

	if targetFile != "" {
		// Phase 2: Focused single-file analysis
		return o.runSingleFileAudit(ctx, task, intent, iteration, root, targetFile)
	}

	// Phase 1: Full scan + generate per-file intents
	task.ProgressStage = "正在执行全量代码检索"
	task.ProgressPercent = 35
	_ = o.db.WithContext(ctx).Save(task)

	primary, err := o.toolRuns.Execute(ctx, ToolRunRequest{
		Task:        *task,
		IterationID: &iteration.ID,
		IntentID:    &intent.ID,
		ToolName:    "code_search",
		ImageName:   "runner-code-audit",
		Workspace:   root,
		Input: map[string]any{
			"taskId":  task.ID,
			"root":    root,
			"maxHits": o.codeAuditMaxHits(),
		},
	})
	if err != nil {
		return nil, err
	}
	outcomes := []ToolRunOutcome{primary}

	// Build file-level Source/Sink index from code_search results
	task.ProgressStage = "正在建立文件级安全索引"
	task.ProgressPercent = 45
	_ = o.db.WithContext(ctx).Save(task)

	fileIndex := o.buildFileSecurityIndex(primary.Evidence)

	// Create per-file intents for high-priority files (Source+Sink co-occurrence)
	createdIntents := 0
	maxFileIntents := 20 // Limit to top 20 files
	for _, fi := range fileIndex {
		if createdIntents >= maxFileIntents {
			break
		}
		if !fi.HasSource || !fi.HasSink {
			continue // Skip files without both Source and Sink
		}

		// Check if intent already exists for this file
		var existing int64
		_ = o.db.WithContext(ctx).Model(&model.AIIntent{}).
			Where("task_id = ? AND constraints_json @> ? AND status IN ?",
				task.ID,
				mustJSON(map[string]any{"filePath": fi.FilePath}),
				[]string{model.IntentStatusPending, model.IntentStatusRunning, model.IntentStatusCompleted}).
			Count(&existing).Error
		if existing > 0 {
			continue
		}

		fileIntent := model.AIIntent{
			TaskID:     task.ID,
			IntentType: "code_trace",
			Title:      fmt.Sprintf("深度审计: %s", filepath.Base(fi.FilePath)),
			Objective:  fmt.Sprintf("Analyze complete file %s for vulnerabilities. Sources: %s. Sinks: %s.", fi.FilePath, strings.Join(fi.SourceTypes, ","), strings.Join(fi.SinkTypes, ",")),
			ConstraintsJSON: mustJSON(map[string]any{
				"filePath":    fi.FilePath,
				"sourceTypes": fi.SourceTypes,
				"sinkTypes":   fi.SinkTypes,
				"priority":    fi.Priority,
			}),
			RequiredEvidence: mustJSON([]string{"entrypoint", "controlled_input", "sensitive_sink_or_behavior"}),
			PriorityScore:    float64(fi.Priority) / 100.0,
			Status:           model.IntentStatusPending,
			CreatedBy:        "agent",
			CreatedReason:    fmt.Sprintf("File %s has %d sources and %d sinks; requires deep analysis", fi.FilePath, len(fi.SourceTypes), len(fi.SinkTypes)),
			CreatedAt:        time.Now().UTC(),
			UpdatedAt:        time.Now().UTC(),
		}
		if err := o.db.WithContext(ctx).Create(&fileIntent).Error; err == nil {
			createdIntents++
		}
	}

	appendAuditEvent(ctx, o.db, &task.ID, "agent.file_index_created", "agent-runtime",
		fmt.Sprintf("Built file security index: %d files analyzed, %d per-file intents created for deep audit.", len(fileIndex), createdIntents), nil)

	return outcomes, nil
}

// runSingleFileAudit performs focused analysis on a single file
func (o *AgentOrchestrator) runSingleFileAudit(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, root string, targetFile string) ([]ToolRunOutcome, error) {
	task.ProgressStage = fmt.Sprintf("正在深度审计: %s", filepath.Base(targetFile))
	task.ProgressPercent = 55
	_ = o.db.WithContext(ctx).Save(task)

	// Read the full file content via code_slice with large radius
	centerLine := 1
	sliceOutcome, err := o.toolRuns.Execute(ctx, ToolRunRequest{
		Task:        *task,
		IterationID: &iteration.ID,
		IntentID:    &intent.ID,
		ToolName:    "code_slice",
		ImageName:   "runner-code-audit",
		Workspace:   root,
		Input: map[string]any{
			"taskId":   task.ID,
			"root":     root,
			"filePath": targetFile,
			"line":     centerLine,
			"radius":   500, // Large radius to get full file
		},
	})
	if err != nil {
		return nil, err
	}

	return []ToolRunOutcome{sliceOutcome}, nil
}

// fileSecurityInfo holds Source/Sink information for a single file
type fileSecurityInfo struct {
	FilePath    string
	SourceTypes []string
	SinkTypes   []string
	HasSource   bool
	HasSink     bool
	Priority    int
}

// buildFileSecurityIndex groups evidence by file and identifies Source/Sink co-occurrence
func (o *AgentOrchestrator) buildFileSecurityIndex(evidence []model.AIEvidence) []fileSecurityInfo {
	fileMap := map[string]*fileSecurityInfo{}

	for _, item := range evidence {
		if item.FilePath == "" || item.EvidenceType != "code_snippet" {
			continue
		}
		fi, ok := fileMap[item.FilePath]
		if !ok {
			fi = &fileSecurityInfo{FilePath: item.FilePath}
			fileMap[item.FilePath] = fi
		}

		summary := strings.ToLower(item.Summary)
		switch {
		case strings.Contains(summary, "input_source") || strings.Contains(summary, "file_upload_source") || strings.Contains(summary, "file_upload_user_controlled"):
			fi.HasSource = true
			fi.SourceTypes = appendUnique(fi.SourceTypes, extractPatternType(summary))
		case strings.Contains(summary, "file_upload_sink") || strings.Contains(summary, "dynamic_code_execution") ||
			strings.Contains(summary, "database_query_sink") || strings.Contains(summary, "sql_template") ||
			strings.Contains(summary, "dynamic_sql") || strings.Contains(summary, "deserialization_sink") ||
			strings.Contains(summary, "file_include_sink") || strings.Contains(summary, "file_write_sink") ||
			strings.Contains(summary, "outbound_request_sink") || strings.Contains(summary, "xxe_parser_sink"):
			fi.HasSink = true
			fi.SinkTypes = appendUnique(fi.SinkTypes, extractPatternType(summary))
		case strings.Contains(summary, "file_upload_validation"):
			// Validation patterns increase priority (indicates security-relevant logic)
			fi.Priority += 10
		}
	}

	// Calculate priority scores
	result := make([]fileSecurityInfo, 0, len(fileMap))
	for _, fi := range fileMap {
		fi.Priority += len(fi.SourceTypes)*20 + len(fi.SinkTypes)*30
		fi.Priority += codeAuditPathPriority(fi.FilePath)
		if fi.HasSource && fi.HasSink {
			fi.Priority += 50 // Bonus for co-occurrence
		}
		result = append(result, *fi)
	}

	// Sort by priority descending
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Priority > result[j].Priority
	})

	return result
}

func extractPatternType(summary string) string {
	// Extract the pattern category from the summary
	if idx := strings.Index(summary, "matched "); idx >= 0 {
		return strings.TrimSpace(summary[idx+8:])
	}
	if strings.Contains(summary, "input_source") {
		return "input_source"
	}
	if strings.Contains(summary, "file_upload_sink") {
		return "file_upload_sink"
	}
	if strings.Contains(summary, "dynamic_code_execution") {
		return "code_execution"
	}
	if strings.Contains(summary, "database_query") || strings.Contains(summary, "sql") {
		return "sql_sink"
	}
	return "security_pattern"
}

func appendUnique(slice []string, value string) []string {
	for _, existing := range slice {
		if existing == value {
			return slice
		}
	}
	return append(slice, value)
}

func prioritizedSliceTargets(items []model.AIEvidence, limit int) []model.AIEvidence {
	if limit <= 0 {
		limit = 8
	}
	sortScore := func(item model.AIEvidence) int {
		text := strings.ToLower(item.Summary + "\n" + item.FilePath)
		score := codeAuditPathPriority(item.FilePath)
		switch {
		case strings.Contains(text, "eval") || strings.Contains(text, "system") || strings.Contains(text, "exec") || strings.Contains(text, "dynamic_code_execution"):
			score += 140
		case strings.Contains(text, "sql_template") || strings.Contains(text, "dynamic_sql") || strings.Contains(text, "database_query") || strings.Contains(text, "querylong") || strings.Contains(text, "getsqlwhere"):
			score += 135
		case strings.Contains(text, "unique_check") || strings.Contains(text, "checkphoneunique") || strings.Contains(text, "unique"):
			score += 128
		case strings.Contains(text, "move_uploaded_file") || strings.Contains(text, "file_upload_sink"):
			score += 120
		case strings.Contains(text, "$_files") || strings.Contains(text, "file_upload_source"):
			score += 105
		case strings.Contains(text, "save_name") || strings.Contains(text, "user_controlled_name"):
			score += 100
		case strings.Contains(text, "unserialize") || strings.Contains(text, "deserialization"):
			score += 96
		case strings.Contains(text, "getimagesize") || strings.Contains(text, "mime") || strings.Contains(text, "validation_check"):
			score += 82
		case strings.Contains(text, "input_source"):
			score += 72
		default:
			score += 10
		}
		return score
	}
	seen := map[string]struct{}{}
	result := make([]model.AIEvidence, 0, limit)
	candidates := append([]model.AIEvidence(nil), items...)
	sort.SliceStable(candidates, func(i, j int) bool {
		left := sortScore(candidates[i])
		right := sortScore(candidates[j])
		if left == right {
			return candidates[i].ID < candidates[j].ID
		}
		return left > right
	})
	fileCounts := map[string]int{}
	const preferredFileCap = 10
	const defaultFileCap = 5
	for _, item := range candidates {
		if item.FilePath == "" || item.LineStart == nil {
			continue
		}
		normalizedFile := strings.ToLower(strings.ReplaceAll(item.FilePath, "\\", "/"))
		capForFile := defaultFileCap
		if codeAuditPathPriority(item.FilePath) >= 80 {
			capForFile = preferredFileCap
		}
		if fileCounts[normalizedFile] >= capForFile {
			continue
		}
		key := fmt.Sprintf("%s:%d", item.FilePath, *item.LineStart)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		fileCounts[normalizedFile]++
		result = append(result, item)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func codeAuditPathPriority(path string) int {
	lower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	score := 0
	switch {
	case strings.Contains(lower, "/satweb/erp/"):
		score += 110
	case strings.Contains(lower, "/server/plugins/erp/"):
		score += 105
	case strings.Contains(lower, "/server/plugins/"):
		score += 80
	case strings.Contains(lower, "/api/") || strings.Contains(lower, "/controller") || strings.Contains(lower, "/routes/"):
		score += 75
	}
	base := filepath.Base(lower)
	if base == "user.js" || base == "app.js" || base == "erp.js" || base == "all_api.js" || strings.Contains(base, "controller") || strings.Contains(base, "service") {
		score += 45
	}
	if strings.Contains(lower, "/public/") || strings.Contains(lower, "/static/") || strings.Contains(lower, "/assets/") || strings.Contains(lower, "/jsutil/") ||
		strings.Contains(base, "bundle") || strings.Contains(base, "echarts") || strings.Contains(base, "jspdf") || strings.Contains(base, "mui") {
		score -= 160
	}
	return score
}

func codeSliceRadiusForEvidence(item model.AIEvidence) int {
	text := strings.ToLower(item.Summary + "\n" + item.FilePath)
	switch {
	case strings.Contains(text, "file_upload_sink") || strings.Contains(text, "file_upload_source") || strings.Contains(text, "file_upload_user_controlled"):
		return 80
	case strings.Contains(text, "database_query") || strings.Contains(text, "sql_template") || strings.Contains(text, "dynamic_sql") || strings.Contains(text, "unique_check"):
		return 60
	case strings.Contains(text, "dynamic_code_execution") || strings.Contains(text, "deserialization"):
		return 70
	case codeAuditPathPriority(item.FilePath) >= 80:
		return 50
	default:
		return 36
	}
}

func hasExtractedSource(root string) (bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return len(entries) > 0, nil
}

func (o *AgentOrchestrator) runPentestIntent(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration) ([]ToolRunOutcome, error) {
	task.ProgressStage = "正在执行授权信息收集"
	task.ProgressPercent = 40
	_ = o.db.WithContext(ctx).Save(task)
	var targets []model.AITaskTarget
	if err := o.db.WithContext(ctx).Where("task_id = ? AND target_type IN ?", task.ID, []string{"url", "domain"}).Find(&targets).Error; err != nil {
		return nil, err
	}
	outcomes := []ToolRunOutcome{}
	for _, target := range targets {
		if o.cfg.MaxToolRuns > 0 && len(outcomes) >= o.cfg.MaxToolRuns {
			break
		}
		value := target.Value
		if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			value = "https://" + value
		}
		switch intent.IntentType {
		case "recon":
			// Run standard recon first
			more, err := o.runPentestRecon(ctx, task, intent, iteration, value)
			if err != nil {
				return outcomes, err
			}
			outcomes = append(outcomes, more...)

			// Run fingerprint as part of recon (information gathering is the essence of pentest)
			if len(outcomes) < o.cfg.MaxToolRuns || o.cfg.MaxToolRuns <= 0 {
				fpOutcome, fpErr := o.runFingerprint(ctx, task, intent, iteration, value)
				if fpErr == nil {
					outcomes = append(outcomes, fpOutcome)
				}
			}

			for _, candidate := range validationCandidatesFromOutcomes(value, more, validationProbeMarker) {
				if len(outcomes) >= o.cfg.MaxToolRuns && o.cfg.MaxToolRuns > 0 {
					break
				}
				validationOutcomes, validationErr := o.runPentestValidation(ctx, task, intent, iteration, value, &candidate)
				if validationErr != nil {
					return outcomes, validationErr
				}
				outcomes = append(outcomes, validationOutcomes...)
			}

		case "validate":
			mode := validationProbeMarker
			if intentExpectedCapability(intent) == model.CapSQLInjection {
				mode = validationProbeSQLi
			}
			candidates := validationCandidatesFromIntent(intent, value)
			if len(candidates) == 0 {
				candidates = o.validationCandidatesFromEvidence(ctx, task.ID, value, mode)
			}
			if len(candidates) == 0 {
				candidates = []httpValidationCandidate{{URL: value, Param: "rabbit_validation", Method: http.MethodGet, Location: "query"}}
			}
			for _, candidate := range candidates {
				if len(outcomes) >= o.cfg.MaxToolRuns && o.cfg.MaxToolRuns > 0 {
					break
				}
				more, err := o.runPentestValidation(ctx, task, intent, iteration, value, &candidate)
				if err != nil {
					return outcomes, err
				}
				outcomes = append(outcomes, more...)
				if outcomesSupportExpectedCapability(intent, more) {
					break
				}
			}

		case "fingerprint":
			fpOutcome, fpErr := o.runFingerprint(ctx, task, intent, iteration, value)
			if fpErr != nil {
				return outcomes, fpErr
			}
			outcomes = append(outcomes, fpOutcome)

		case model.IntentSurfaceDiscovery, model.IntentJSAnalysis:
			surface, err := o.runSurfaceDiscovery(ctx, task, intent, iteration, value)
			if err != nil && surface.ToolRun.Status != model.ToolRunStatusBlocked {
				return outcomes, err
			}
			outcomes = append(outcomes, surface)

		case model.IntentFingerprintConfirm:
			fpOutcome, fpErr := o.runFingerprint(ctx, task, intent, iteration, value)
			if fpErr != nil {
				return outcomes, fpErr
			}
			outcomes = append(outcomes, fpOutcome)

		case model.IntentBehaviorProbe:
			if probe, ok := behaviorProbeInputFromIntent(intent, value, task.ID); ok {
				outcome, err := o.runBehaviorProbe(ctx, task, intent, iteration, probe)
				if err != nil && outcome.ToolRun.Status != model.ToolRunStatusBlocked {
					return outcomes, err
				}
				outcomes = append(outcomes, outcome)
				break
			}
			fallthrough

		case model.IntentAuthProbe,
			model.IntentIDORProbe,
			model.IntentMassAssignmentProbe,
			model.IntentBusinessLogicProbe,
			model.IntentPathTraversalProbe,
			model.IntentSQLiProbe,
			model.IntentSSRFProbe,
			model.IntentUploadProbe,
			model.IntentXSSProbe,
			model.IntentSSTIProbe,
			model.IntentCommandInjProbe,
			model.IntentSecretVerify,
			model.IntentCapabilityExpand,
			model.IntentGoalAttempt,
			model.IntentBootstrapGraph,
			model.IntentExploreEntrypoint,
			model.IntentInspectDataflow,
			model.IntentInspectGuard,
			model.IntentValidateHypothesis,
			model.IntentRunTool,
			model.IntentResolveUnknown,
			model.IntentCompareBehavior,
			model.IntentExpandAttackSurface,
			model.IntentPromoteCapability:
			mode := validationProbeMarker
			if intent.IntentType == model.IntentSQLiProbe || intentExpectedCapability(intent) == model.CapSQLInjection {
				mode = validationProbeSQLi
			}
			candidates := validationCandidatesFromIntent(intent, value)
			if len(candidates) == 0 {
				candidates = o.validationCandidatesFromEvidence(ctx, task.ID, value, mode)
			}
			if len(candidates) == 0 {
				candidates = []httpValidationCandidate{{URL: value, Param: "rabbit_validation", Method: http.MethodGet, Location: "query"}}
			}
			for _, candidate := range candidates {
				if len(outcomes) >= o.cfg.MaxToolRuns && o.cfg.MaxToolRuns > 0 {
					break
				}
				more, err := o.runPentestValidation(ctx, task, intent, iteration, value, &candidate)
				if err != nil {
					return outcomes, err
				}
				outcomes = append(outcomes, more...)
				if outcomesSupportExpectedCapability(intent, more) {
					break
				}
			}
		}
	}
	return outcomes, nil
}

func isCodeAuditRuntimeIntent(intentType string) bool {
	switch intentType {
	case model.IntentBootstrapGraph,
		model.IntentExploreEntrypoint,
		model.IntentInspectDataflow,
		model.IntentInspectGuard,
		model.IntentValidateHypothesis,
		model.IntentRunTool,
		model.IntentResolveUnknown,
		model.IntentCompareBehavior,
		model.IntentExpandAttackSurface,
		model.IntentPromoteCapability,
		model.IntentCodeProjectIndex,
		model.IntentCodeSliceAnalysis,
		model.IntentDataflowTrace,
		model.IntentRouteToSinkTrace,
		model.IntentEntryToAuthzTrace,
		model.IntentObjectOwnerCheck,
		model.IntentMassAssignTrace,
		model.IntentFilePathControl,
		model.IntentUploadToExec,
		model.IntentSecretToAPI,
		model.IntentBusinessStateTrace,
		model.IntentSQLConstructTrace,
		model.IntentDeserializationTrace,
		model.IntentTemplateRenderTrace,
		model.IntentSSRFURLControl:
		return true
	default:
		return false
	}
}

func isPentestRuntimeIntent(intentType string) bool {
	switch intentType {
	case model.IntentBootstrapGraph,
		model.IntentExploreEntrypoint,
		model.IntentInspectDataflow,
		model.IntentInspectGuard,
		model.IntentValidateHypothesis,
		model.IntentRunTool,
		model.IntentResolveUnknown,
		model.IntentCompareBehavior,
		model.IntentExpandAttackSurface,
		model.IntentPromoteCapability,
		model.IntentSurfaceDiscovery,
		model.IntentFingerprintConfirm,
		model.IntentJSAnalysis,
		model.IntentBehaviorProbe,
		model.IntentAuthProbe,
		model.IntentIDORProbe,
		model.IntentMassAssignmentProbe,
		model.IntentBusinessLogicProbe,
		model.IntentPathTraversalProbe,
		model.IntentSQLiProbe,
		model.IntentSSRFProbe,
		model.IntentUploadProbe,
		model.IntentXSSProbe,
		model.IntentSSTIProbe,
		model.IntentCommandInjProbe,
		model.IntentSecretVerify,
		model.IntentCapabilityExpand,
		model.IntentGoalAttempt:
		return true
	default:
		return false
	}
}

func intentExpectedCapability(intent *model.AIIntent) string {
	if intent == nil {
		return ""
	}
	return strings.TrimSpace(intent.ValidationMetadata().ExpectedCapability)
}

func validationCandidatesFromOutcomes(baseURL string, outcomes []ToolRunOutcome, mode validationProbeMode) []httpValidationCandidate {
	candidates := []httpValidationCandidate{}
	seen := map[string]struct{}{}
	add := func(candidate httpValidationCandidate) {
		if strings.TrimSpace(candidate.URL) == "" {
			candidate.URL = baseURL
		}
		if strings.TrimSpace(candidate.Param) == "" {
			return
		}
		key := strings.ToUpper(candidate.Method) + "|" + candidate.URL + "|" + strings.ToLower(candidate.Location) + "|" + candidate.Param + "|" + candidate.Payload
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate)
	}
	for _, outcome := range outcomes {
		if outcome.ToolRun.ToolName == "http_surface" {
			for _, candidate := range httpSurfaceValidationCandidates(baseURL, outcome.Result, mode) {
				add(candidate)
				if len(candidates) >= 12 {
					return candidates
				}
			}
		}
	}
	if len(candidates) == 0 {
		add(httpValidationCandidate{URL: baseURL, Param: "id", Method: http.MethodGet, Location: "query"})
		add(httpValidationCandidate{URL: baseURL, Param: "q", Method: http.MethodGet, Location: "query"})
		add(httpValidationCandidate{URL: baseURL, Param: "search", Method: http.MethodGet, Location: "query"})
	}
	if len(candidates) > 12 {
		return candidates[:12]
	}
	return candidates
}

func (o *AgentOrchestrator) validationCandidatesFromEvidence(ctx context.Context, taskID uint, baseURL string, mode validationProbeMode) []httpValidationCandidate {
	if o.toolRuns == nil || o.toolRuns.store == nil {
		return nil
	}
	var latest model.AIEvidence
	if err := o.db.WithContext(ctx).
		Where("task_id = ? AND title = ?", taskID, "HTTP input surface discovery").
		Order("created_at desc").
		First(&latest).Error; err != nil {
		return nil
	}
	if strings.TrimSpace(latest.RawRef) == "" {
		return nil
	}
	raw, err := o.toolRuns.store.ReadText(ctx, latest.RawRef)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	return httpSurfaceValidationCandidates(baseURL, &tools.ToolResult{Stdout: raw}, mode)
}

func (o *AgentOrchestrator) replenishHTTPInputSurfaceFrontier(ctx context.Context, taskID uint, hypotheses *HypothesisLifecycleService) ([]model.AIHypothesisNode, error) {
	if hypotheses == nil {
		return nil, nil
	}
	pending, err := pendingHTTPInputSurfaceValidationCount(ctx, o.db, taskID)
	if err != nil || pending >= httpInputSurfaceFrontierWindow {
		return nil, err
	}
	var latest model.AIEvidence
	if err := o.db.WithContext(ctx).
		Where("task_id = ? AND title = ?", taskID, "HTTP input surface discovery").
		Order("created_at desc").
		First(&latest).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	missing := httpInputSurfaceFrontierWindow - pending
	if missing <= 0 {
		return nil, nil
	}
	return hypotheses.ExpandFromEvidence(ctx, taskID, []model.AIEvidence{latest}, ExpansionBudget{MaxGeneratedPerRound: missing})
}

func pendingHTTPInputSurfaceValidationCount(ctx context.Context, db *gorm.DB, taskID uint) (int, error) {
	var intents []model.AIIntent
	if err := db.WithContext(ctx).
		Where("task_id = ? AND status = ?", taskID, model.IntentStatusPending).
		Find(&intents).Error; err != nil {
		return 0, err
	}
	count := 0
	for _, intent := range intents {
		var constraints map[string]any
		if len(intent.ConstraintsJSON) == 0 || json.Unmarshal(intent.ConstraintsJSON, &constraints) != nil {
			continue
		}
		if constraints["branch_kind"] == "http_input_surface" {
			count++
		}
	}
	return count, nil
}

func nonHTTPInputSurfaceEvidence(items []model.AIEvidence) []model.AIEvidence {
	filtered := make([]model.AIEvidence, 0, len(items))
	for _, item := range items {
		if item.Title == "HTTP input surface discovery" {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func (o *AgentOrchestrator) codeAuditMaxHits() int {
	value := o.cfg.CodeAuditMaxHits
	if value <= 0 {
		return 3000
	}
	if value > 5000 {
		return 5000
	}
	return value
}

func (o *AgentOrchestrator) codeAuditMaxSnippets() int {
	value := o.cfg.CodeAuditMaxSnippets
	if value <= 0 {
		return 420
	}
	if value > 1200 {
		return 1200
	}
	return value
}

func (o *AgentOrchestrator) codeAuditSliceLimit(intent *model.AIIntent) int {
	limit := o.codeAuditMaxSnippets()
	if intent == nil {
		return limit
	}
	switch intent.IntentType {
	case "code_trace", "collect_evidence":
		return maxInt(limit, 520)
	default:
		return limit
	}
}

func (o *AgentOrchestrator) runPentestRecon(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, target string) ([]ToolRunOutcome, error) {
	outcomes := []ToolRunOutcome{}
	for _, mode := range []string{"quick_http", "service_fingerprint", "web_crawl"} {
		outcome, err := o.toolRuns.Execute(ctx, ToolRunRequest{
			Task:        *task,
			IterationID: &iteration.ID,
			IntentID:    &intent.ID,
			ToolName:    "pentest_probe",
			ImageName:   "runner-pentest",
			Input: map[string]any{
				"taskId": task.ID,
				"target": target,
				"mode":   mode,
			},
		})
		if err != nil && outcome.ToolRun.Status != model.ToolRunStatusBlocked {
			return outcomes, err
		}
		outcomes = append(outcomes, outcome)
	}
	baseline, err := o.runHTTPRequest(ctx, task, intent, iteration, http.MethodGet, target, nil, "")
	if err != nil && baseline.ToolRun.Status != model.ToolRunStatusBlocked {
		return outcomes, err
	}
	outcomes = append(outcomes, baseline)
	if baseline.Result != nil {
		surface, surfaceErr := o.toolRuns.Execute(ctx, ToolRunRequest{
			Task:        *task,
			IterationID: &iteration.ID,
			IntentID:    &intent.ID,
			ToolName:    "http_surface",
			ImageName:   "runner-pentest",
			Input: map[string]any{
				"taskId":  task.ID,
				"baseUrl": target,
				"body":    baseline.Result.Stdout,
			},
		})
		if surfaceErr == nil || surface.ToolRun.Status == model.ToolRunStatusBlocked {
			outcomes = append(outcomes, surface)
		}
	}
	return outcomes, nil
}

func (o *AgentOrchestrator) runPentestValidation(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, target string, candidate *httpValidationCandidate) ([]ToolRunOutcome, error) {
	marker := fmt.Sprintf("AI_VALIDATION_MARKER_%d_%d", task.ID, time.Now().UnixNano())
	if candidate == nil {
		candidate = &httpValidationCandidate{URL: target, Param: "rabbit_validation", Method: http.MethodGet, Location: "query"}
	}
	validationValue := firstNonEmpty(candidate.Payload, marker)
	baselineURL := candidate.URL
	if strings.TrimSpace(baselineURL) == "" {
		baselineURL = target
	}
	method := strings.ToUpper(strings.TrimSpace(candidate.Method))
	if method == "" {
		method = http.MethodGet
	}
	baseline, err := o.runHTTPRequest(ctx, task, intent, iteration, method, baselineURL, nil, "")
	if err != nil && baseline.ToolRun.Status != model.ToolRunStatusBlocked {
		return []ToolRunOutcome{}, err
	}
	validationURL, body := buildMarkerValidationRequest(baselineURL, method, candidate.Param, validationValue, candidate.Location)
	validation, err := o.runHTTPRequest(ctx, task, intent, iteration, method, validationURL, nil, body)
	if err != nil && validation.ToolRun.Status != model.ToolRunStatusBlocked {
		return []ToolRunOutcome{baseline}, err
	}
	outcomes := []ToolRunOutcome{baseline, validation}
	if baseline.Result == nil || validation.Result == nil {
		return outcomes, nil
	}
	baselineStatus, _ := baseline.Result.Metadata["statusCode"].(int)
	validationStatus, _ := validation.Result.Metadata["statusCode"].(int)
	diff, diffErr := o.toolRuns.Execute(ctx, ToolRunRequest{
		Task:        *task,
		IterationID: &iteration.ID,
		IntentID:    &intent.ID,
		ToolName:    "response_diff",
		ImageName:   "runner-pentest",
		Input: map[string]any{
			"target":           target,
			"marker":           validationValue,
			"baselineUrl":      baselineURL,
			"validationUrl":    validationURL,
			"baselineStatus":   baselineStatus,
			"validationStatus": validationStatus,
			"baselineBody":     baseline.Result.Stdout,
			"validationBody":   validation.Result.Stdout,
		},
	})
	if diffErr == nil {
		outcomes = append(outcomes, diff)
	}
	return outcomes, nil
}

func (o *AgentOrchestrator) runHTTPRequest(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, method string, target string, headers map[string]string, body string) (ToolRunOutcome, error) {
	return o.toolRuns.Execute(ctx, ToolRunRequest{
		Task:        *task,
		IterationID: &iteration.ID,
		IntentID:    &intent.ID,
		ToolName:    "http_request",
		ImageName:   "runner-pentest",
		Input: map[string]any{
			"taskId":  task.ID,
			"method":  method,
			"url":     target,
			"headers": headers,
			"body":    body,
		},
	})
}

func (o *AgentOrchestrator) runSurfaceDiscovery(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, target string) (ToolRunOutcome, error) {
	return o.toolRuns.Execute(ctx, ToolRunRequest{
		Task:        *task,
		IterationID: &iteration.ID,
		IntentID:    &intent.ID,
		ToolName:    "surface_discovery",
		ImageName:   "runner-pentest",
		Input: map[string]any{
			"taskId": task.ID,
			"target": target,
		},
	})
}

func (o *AgentOrchestrator) runBehaviorProbe(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, input map[string]any) (ToolRunOutcome, error) {
	return o.toolRuns.Execute(ctx, ToolRunRequest{
		Task:        *task,
		IterationID: &iteration.ID,
		IntentID:    &intent.ID,
		ToolName:    "behavior_probe",
		ImageName:   "runner-pentest",
		Input:       input,
	})
}

func behaviorProbeInputFromIntent(intent *model.AIIntent, fallbackURL string, taskID uint) (map[string]any, bool) {
	if intent == nil || len(intent.ConstraintsJSON) == 0 {
		return nil, false
	}
	var constraints map[string]any
	if err := json.Unmarshal(intent.ConstraintsJSON, &constraints); err != nil {
		return nil, false
	}
	baselineURL := firstStringValue(constraints, "baselineUrl", "baseline_url", "baseline")
	variantURL := firstStringValue(constraints, "variantUrl", "variant_url", "variant")
	if strings.TrimSpace(baselineURL) == "" || strings.TrimSpace(variantURL) == "" {
		return nil, false
	}
	headers := map[string]string{}
	if raw, ok := constraints["headers"]; ok {
		if marshaled, err := json.Marshal(raw); err == nil {
			_ = json.Unmarshal(marshaled, &headers)
		}
	}
	return map[string]any{
		"taskId":       taskID,
		"baselineUrl":  firstNonEmpty(baselineURL, fallbackURL),
		"variantUrl":   variantURL,
		"method":       firstNonEmpty(firstStringValue(constraints, "method"), http.MethodGet),
		"headers":      headers,
		"baselineBody": firstStringValue(constraints, "baselineBody", "baseline_body"),
		"variantBody":  firstStringValue(constraints, "variantBody", "variant_body"),
		"marker":       firstStringValue(constraints, "marker"),
		"hypothesis":   firstNonEmpty(firstStringValue(constraints, "hypothesis"), intent.Objective, intent.Title),
	}, true
}

func firstStringValue(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return typed
				}
			case fmt.Stringer:
				if strings.TrimSpace(typed.String()) != "" {
					return typed.String()
				}
			}
		}
	}
	return ""
}

type httpValidationCandidate struct {
	URL      string
	Param    string
	Method   string
	Location string
	Payload  string
}

type validationProbeMode string

const (
	validationProbeMarker validationProbeMode = "marker"
	validationProbeSQLi   validationProbeMode = "sqli"
)

func httpSurfaceValidationCandidates(baseURL string, result *tools.ToolResult, mode validationProbeMode) []httpValidationCandidate {
	if result == nil || strings.TrimSpace(result.Stdout) == "" {
		return nil
	}
	return httpSurfaceValidationCandidatesFromJSON(baseURL, result.Stdout, mode)
}

func httpSurfaceValidationCandidatesFromJSON(baseURL string, raw string, mode validationProbeMode) []httpValidationCandidate {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var surface struct {
		Parameters []struct {
			Name     string `json:"name"`
			Location string `json:"location"`
			URL      string `json:"url"`
			Method   string `json:"method"`
		} `json:"parameters"`
		Links []struct {
			URL string `json:"url"`
		} `json:"links"`
	}
	if err := json.Unmarshal([]byte(raw), &surface); err != nil {
		return nil
	}
	candidates := []httpValidationCandidate{}
	seen := map[string]struct{}{}
	add := func(candidate httpValidationCandidate) {
		if strings.TrimSpace(candidate.URL) == "" {
			candidate.URL = baseURL
		}
		if strings.TrimSpace(candidate.Method) == "" {
			candidate.Method = http.MethodGet
		}
		if strings.TrimSpace(candidate.Location) == "" {
			candidate.Location = "query"
		}
		if strings.TrimSpace(candidate.Param) == "" {
			return
		}
		key := strings.ToUpper(candidate.Method) + "|" + candidate.URL + "|" + candidate.Location + "|" + candidate.Param + "|" + candidate.Payload
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate)
	}
	seedCandidates := []httpValidationCandidate{}
	seenSeeds := map[string]struct{}{}
	addSeed := func(candidate httpValidationCandidate) {
		if strings.TrimSpace(candidate.URL) == "" {
			candidate.URL = baseURL
		}
		if strings.TrimSpace(candidate.Method) == "" {
			candidate.Method = http.MethodGet
		}
		if strings.TrimSpace(candidate.Location) == "" {
			candidate.Location = "query"
		}
		if strings.TrimSpace(candidate.Param) == "" {
			return
		}
		key := strings.ToUpper(candidate.Method) + "|" + endpointWithoutPayload(candidate.URL) + "|" + strings.ToLower(candidate.Location) + "|" + candidate.Param
		if _, exists := seenSeeds[key]; exists {
			return
		}
		seenSeeds[key] = struct{}{}
		seedCandidates = append(seedCandidates, candidate)
	}
	for _, param := range surface.Parameters {
		addSeed(httpValidationCandidate{URL: param.URL, Param: param.Name, Method: param.Method, Location: param.Location})
	}
	injectableLinks := []httpValidationCandidate{}
	seenInjectable := map[string]struct{}{}
	for _, link := range surface.Links {
		if parsed, err := url.Parse(link.URL); err == nil {
			for name := range parsed.Query() {
				addSeed(httpValidationCandidate{URL: link.URL, Param: name, Method: http.MethodGet, Location: "query"})
			}
			if mode == validationProbeSQLi && looksInjectablePath(parsed.Path) && len(parsed.Query()) == 0 {
				base := urlWithQueryValue(link.URL, "id", "1")
				if _, ok := seenInjectable[base]; !ok {
					seenInjectable[base] = struct{}{}
					injectableLinks = append(injectableLinks, httpValidationCandidate{URL: base, Param: "id", Method: http.MethodGet, Location: "query"})
				}
			}
		}
	}
	if mode != validationProbeSQLi {
		for _, candidate := range seedCandidates {
			add(candidate)
		}
		return candidates
	}
	allSeeds := append(seedCandidates, injectableLinks...)
	for _, payload := range sqliProbePayloads() {
		for _, seed := range allSeeds {
			seed.Payload = payload
			add(seed)
		}
	}
	return candidates
}

func looksInjectablePath(path string) bool {
	lower := strings.ToLower(strings.Trim(path, "/"))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "less-") || strings.Contains(lower, "detail") || strings.Contains(lower, "view") || strings.Contains(lower, "show") || strings.Contains(lower, "item") || strings.Contains(lower, "product") || strings.Contains(lower, "user") {
		return true
	}
	return false
}

func sqliProbePayloads() []string {
	return []string{
		"1'",
		"1\"",
		"-1' UNION SELECT 1,2,3-- ",
		"1' AND '1'='2",
	}
}

func urlWithQueryValue(rawURL, key, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if looksInjectablePath(parsed.Path) && !strings.HasSuffix(parsed.Path, "/") && !pathHasExtension(parsed.Path) {
		parsed.Path += "/"
	}
	values := parsed.Query()
	values.Set(key, value)
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func pathHasExtension(p string) bool {
	last := p
	if idx := strings.LastIndex(last, "/"); idx >= 0 {
		last = last[idx+1:]
	}
	return strings.Contains(last, ".")
}

func validationCandidatesFromIntent(intent *model.AIIntent, fallbackURL string) []httpValidationCandidate {
	if intent == nil || len(intent.ConstraintsJSON) == 0 {
		return nil
	}
	var constraints map[string]any
	if err := json.Unmarshal(intent.ConstraintsJSON, &constraints); err != nil {
		return nil
	}
	raw, _ := json.Marshal(constraints["validation_candidates"])
	if len(raw) == 0 || string(raw) == "null" {
		raw, _ = json.Marshal(constraints["targets"])
	}
	var list []struct {
		URL      string `json:"url"`
		Param    string `json:"param"`
		Method   string `json:"method"`
		Location string `json:"location"`
		Payload  string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil
	}
	candidates := make([]httpValidationCandidate, 0, len(list))
	for _, item := range list {
		candidate := httpValidationCandidate{
			URL:      firstNonEmpty(item.URL, fallbackURL),
			Param:    firstNonEmpty(item.Param, "rabbit_validation"),
			Method:   firstNonEmpty(item.Method, http.MethodGet),
			Location: firstNonEmpty(item.Location, "query"),
			Payload:  item.Payload,
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func buildMarkerValidationRequest(rawURL string, method string, param string, marker string, location string) (string, string) {
	if strings.TrimSpace(param) == "" {
		param = "rabbit_validation"
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	location = strings.ToLower(strings.TrimSpace(location))
	if method == http.MethodPost || location == "form" {
		bodyValues := url.Values{}
		bodyValues.Set(param, marker)
		return rawURL, bodyValues.Encode()
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		separator := "?"
		if strings.Contains(rawURL, "?") {
			separator = "&"
		}
		return rawURL + separator + url.QueryEscape(param) + "=" + url.QueryEscape(marker), ""
	}
	values := parsed.Query()
	values.Set(param, marker)
	parsed.RawQuery = values.Encode()
	return parsed.String(), ""
}

func (o *AgentOrchestrator) upsertFactsFromPentestEvidence(ctx context.Context, taskID uint, run model.AIToolRun, item model.AIEvidence, result *tools.ToolResult) []uint {
	if run.ToolName != "pentest_probe" && run.ToolName != "http_surface" {
		return nil
	}
	if result == nil || strings.TrimSpace(result.Stdout) == "" {
		return nil
	}
	var nodes []uint
	if run.ToolName == "pentest_probe" {
		var report struct {
			Target string `json:"target"`
			Mode   string `json:"mode"`
			Facts  []struct {
				Kind    string `json:"kind"`
				Target  string `json:"target"`
				Summary string `json:"summary"`
			} `json:"facts"`
		}
		if err := json.Unmarshal([]byte(result.Stdout), &report); err != nil {
			return nil
		}
		for _, fact := range report.Facts {
			title := "Pentest fact: " + strings.TrimSpace(fact.Kind)
			if strings.TrimSpace(fact.Kind) == "" || strings.TrimSpace(fact.Summary) == "" {
				continue
			}
			node, err := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
				TaskID:          taskID,
				NodeType:        "fact",
				Title:           title,
				Summary:         fact.Summary,
				Content:         fact,
				DedupSeed:       "pentest-fact-" + fact.Kind + "-" + fact.Target + "-" + fact.Summary,
				ImportanceScore: 0.78,
				SourceType:      "tool",
				SourceID:        fmt.Sprintf("%d", run.ID),
				EvidenceRefs:    []uint{item.ID},
			})
			if err == nil {
				nodes = append(nodes, node.ID)
			}
		}
	}
	if run.ToolName == "http_surface" {
		var surface struct {
			BaseURL    string `json:"baseUrl"`
			Links      []any  `json:"links"`
			Forms      []any  `json:"forms"`
			Parameters []any  `json:"parameters"`
		}
		if err := json.Unmarshal([]byte(result.Stdout), &surface); err != nil {
			return nodes
		}
		summary := fmt.Sprintf("HTTP input surface for %s contains %d links, %d forms, and %d parameters.", surface.BaseURL, len(surface.Links), len(surface.Forms), len(surface.Parameters))
		node, err := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        "fact",
			Title:           "HTTP input surface discovered",
			Summary:         summary,
			Content:         surface,
			DedupSeed:       "http-surface-" + surface.BaseURL + "-" + summary,
			ImportanceScore: 0.84,
			SourceType:      "tool",
			SourceID:        fmt.Sprintf("%d", run.ID),
			EvidenceRefs:    []uint{item.ID},
		})
		if err == nil {
			nodes = append(nodes, node.ID)
		}
	}
	return nodes
}

func (o *AgentOrchestrator) upsertFactsFromCodeEvidence(ctx context.Context, taskID uint, run model.AIToolRun, item model.AIEvidence, result *tools.ToolResult) []uint {
	if run.ToolName != "code_search" && run.ToolName != "code_slice" {
		return nil
	}
	if item.EvidenceType != "code_snippet" && strings.TrimSpace(item.FilePath) == "" {
		return nil
	}
	content := map[string]any{
		"toolRunId":    run.ID,
		"toolName":     run.ToolName,
		"evidenceId":   item.ID,
		"evidenceType": item.EvidenceType,
		"relationType": item.RelationType,
		"filePath":     item.FilePath,
		"lineStart":    intPtrValue(item.LineStart),
		"lineEnd":      intPtrValue(item.LineEnd),
		"summary":      item.Summary,
		"title":        item.Title,
		"target":       item.Target,
	}
	if result != nil && strings.TrimSpace(result.Summary) != "" {
		content["toolSummary"] = result.Summary
	}
	title := "Code fact: " + firstNonEmpty(item.FilePath, item.Title, run.ToolName)
	summary := strings.TrimSpace(item.Summary)
	if summary == "" {
		summary = fmt.Sprintf("%s observed %s", run.ToolName, firstNonEmpty(item.FilePath, item.Title))
	}
	if item.FilePath != "" && item.LineStart != nil {
		summary = fmt.Sprintf("%s (%s:%d)", summary, item.FilePath, *item.LineStart)
	}
	node, err := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        "fact",
		Title:           title,
		Summary:         summary,
		Content:         content,
		DedupSeed:       fmt.Sprintf("code-fact-%s-%d-%s", strings.ToLower(filepath.Clean(item.FilePath)), intPtrValue(item.LineStart), item.Summary),
		ImportanceScore: 0.82,
		SourceType:      "tool",
		SourceID:        fmt.Sprintf("%d", run.ID),
		EvidenceRefs:    []uint{item.ID},
	})
	if err != nil || node.ID == 0 {
		return nil
	}
	return []uint{node.ID}
}

func (o *AgentOrchestrator) reasonOverSecurityGraph(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, items []model.AIEvidence, snippets []CodeAuditSnippet) (ModelCallMetadata, []string) {
	metadata := ModelCallMetadata{Provider: "model-runtime", Model: "", IntentType: "security_graph_reasoning"}
	packet := o.buildSecurityGraphPacket(ctx, task.ID, intent, snippets)
	if len(packet.Nodes) == 0 {
		return metadata, []string{"security graph packet has no nodes"}
	}
	started := time.Now()
	decision, callMetadata, err := o.models.AnalyzeSecurityGraph(ctx, *task, packet)
	callMetadata.LatencyMs = time.Since(started).Milliseconds()
	if callMetadata.Provider != "" {
		metadata.Provider = callMetadata.Provider
	}
	if callMetadata.Model != "" {
		metadata.Model = callMetadata.Model
	}
	if err != nil {
		appendAuditEvent(ctx, o.db, &task.ID, "agent.graph_reasoning_failed", "model-runtime", err.Error(), map[string]any{
			"intentId":     intent.ID,
			"nodeCount":    len(packet.Nodes),
			"edgeCount":    len(packet.Edges),
			"snippetCount": len(packet.Snippets),
			"latencyMs":    callMetadata.LatencyMs,
			"provider":     callMetadata.Provider,
			"model":        callMetadata.Model,
		})
		return metadata, []string{err.Error()}
	}
	o.applyGraphDecision(ctx, task, intent, decision, items)
	appendAuditEvent(ctx, o.db, &task.ID, "agent.graph_reasoning", "model-runtime", "Model reasoned over the blackboard graph.", map[string]any{
		"intentId":        intent.ID,
		"nodeCount":       len(packet.Nodes),
		"edgeCount":       len(packet.Edges),
		"snippetCount":    len(packet.Snippets),
		"nextIntentCount": len(decision.NextIntents),
		"latencyMs":       callMetadata.LatencyMs,
		"provider":        callMetadata.Provider,
		"model":           callMetadata.Model,
		"stopReason":      decision.StopReason,
	})
	return metadata, nil
}

func (o *AgentOrchestrator) buildSecurityGraphPacket(ctx context.Context, taskID uint, intent *model.AIIntent, snippets []CodeAuditSnippet) SecurityGraphAuditPacket {
	// Cairn-style focused reasoning: send only a small, relevant subset.
	// Each "Explore" step should be small and fast (< 30s model response).
	// Instead of dumping the entire graph, we send:
	// - Top 20 most important blackboard nodes, with stable node ids
	// - Top 30 edges between them
	// - Top 6 code snippets (the actual material for analysis)
	// This keeps total prompt under ~4000 tokens, well within gateway timeout limits.

	var nodes []model.AIBlackboardNode
	_ = o.db.WithContext(ctx).
		Where("task_id = ? AND status = ?", taskID, model.BlackboardNodeStatusActive).
		Order("importance_score desc, last_seen_at desc").
		Limit(20).
		Find(&nodes).Error
	nodeIDs := make([]uint, 0, len(nodes))
	graphNodes := make([]SecurityGraphNode, 0, len(nodes))
	for _, node := range nodes {
		nodeIDs = append(nodeIDs, node.ID)
		// Truncate summaries to keep prompt small
		summary := node.Summary
		if len(summary) > 120 {
			summary = summary[:120] + "..."
		}
		graphNodes = append(graphNodes, SecurityGraphNode{
			ID:           node.ID,
			NodeType:     node.NodeType,
			Title:        node.Title,
			Summary:      summary,
			SourceType:   node.SourceType,
			EvidenceRefs: parseUintJSONList(node.EvidenceRefs),
		})
	}
	var edges []model.AIBlackboardEdge
	if len(nodeIDs) > 0 {
		_ = o.db.WithContext(ctx).
			Where("task_id = ? AND from_id IN ? AND to_id IN ?", taskID, nodeIDs, nodeIDs).
			Order("weight desc, created_at desc").
			Limit(30).
			Find(&edges).Error
	}
	graphEdges := make([]SecurityGraphEdge, 0, len(edges))
	for _, edge := range edges {
		graphEdges = append(graphEdges, SecurityGraphEdge{FromID: edge.FromID, ToID: edge.ToID, EdgeType: edge.EdgeType, Weight: edge.Weight})
	}
	packet := SecurityGraphAuditPacket{
		CurrentIntent: SecurityGraphIntent{
			ID:        intent.ID,
			Type:      intent.IntentType,
			Title:     intent.Title,
			Objective: intent.Objective,
		},
		Nodes:    graphNodes,
		Edges:    graphEdges,
		Snippets: capCodeAuditSnippets(snippets, 6),
	}
	return packet
}

func (o *AgentOrchestrator) applyGraphDecision(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, decision SecurityGraphDecision, items []model.AIEvidence) {
	parentNodeID := uint(0)
	if intent.ParentNodeID != nil {
		parentNodeID = *intent.ParentNodeID
	} else if intent.ID != 0 {
		parentNodeID = blackboardNodeIDForIntent(ctx, o.db, task.ID, intent.ID)
	}
	for _, fact := range decision.Facts {
		nodeType := strings.TrimSpace(fact.NodeType)
		if nodeType == "" {
			nodeType = "fact"
		}
		title := strings.TrimSpace(fact.Title)
		summary := strings.TrimSpace(fact.Summary)
		if title == "" || summary == "" {
			continue
		}
		node, err := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          task.ID,
			NodeType:        nodeType,
			Title:           title,
			Summary:         summary,
			Content:         fact,
			DedupSeed:       "model-fact-" + title + "-" + summary,
			ImportanceScore: 0.82,
			SourceType:      "agent",
			SourceID:        "graph-reasoner",
		})
		if err == nil && parentNodeID != 0 {
			_ = o.blackboard.AddEdge(ctx, task.ID, parentNodeID, node.ID, "reasoned_fact", 0.74, map[string]any{"intentId": intent.ID})
		}
	}
	for _, next := range decision.NextIntents {
		_ = o.createGraphReasonedIntent(ctx, task.ID, parentNodeID, intent, next)
	}
	_ = items
}

func (o *AgentOrchestrator) createGraphReasonedIntent(ctx context.Context, taskID uint, parentNodeID uint, parent *model.AIIntent, suggestion SecurityGraphIntentSuggestion) bool {
	title := firstNonEmpty(strings.TrimSpace(suggestion.Title), strings.TrimSpace(suggestion.Objective), strings.TrimSpace(suggestion.Hypothesis))
	objective := firstNonEmpty(strings.TrimSpace(suggestion.Objective), title)
	if title == "" || objective == "" {
		return false
	}
	intentType, ok := workerSuggestedIntentType(suggestion.IntentType)
	if !ok {
		appendAuditEvent(ctx, o.db, &taskID, "graph_reasoner.unsupported_intent_skipped", "model-runtime", "Reasoner suggested an unsupported runtime intent; skipped.", map[string]any{"parentIntentId": safeIntentID(parent), "intentType": suggestion.IntentType})
		return false
	}
	sourceNodeIDs := o.validReasonSourceNodeIDs(ctx, taskID, suggestion.SourceNodeIDs)
	if len(sourceNodeIDs) == 0 {
		appendAuditEvent(ctx, o.db, &taskID, "graph_reasoner.intent_without_sources_skipped", "model-runtime", "Reasoner intent did not cite any valid graph source nodes.", map[string]any{"parentIntentId": safeIntentID(parent), "title": title})
		return false
	}
	sourceKey := uintListKey(sourceNodeIDs)
	var existing int64
	_ = o.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("task_id = ? AND intent_type = ? AND objective = ? AND status IN ?", taskID, intentType, objective, []string{model.IntentStatusPending, model.IntentStatusRunning, model.IntentStatusCompleted}).
		Count(&existing).Error
	if existing > 0 {
		return false
	}
	priority := graphReasonerPriority(suggestion.Priority)
	lifecycle := NewHypothesisLifecycleService(o.db, o.blackboard)
	hypothesis, err := lifecycle.FormHypothesis(ctx, graphReasonerHypothesisDraft(taskID, suggestion, intentType, sourceNodeIDs))
	if err != nil {
		return false
	}
	intent, err := lifecycle.CreateValidationIntent(ctx, hypothesis, intentType, "graph_reasoner_composed_validation", priority, graphIntentConstraints(parent, suggestion, sourceNodeIDs))
	if err != nil {
		return false
	}
	intent.ParentNodeID = &sourceNodeIDs[0]
	intent.CreatedBy = "graph-reasoner"
	intent.CreatedReason = "Cairn-style graph reasoner composed one or more facts into a validation intent; worker execution and evidence decide outcome."
	intent.RequiredEvidence = mustJSON(defaultRequiredEvidence(suggestion.RequiredEvidence))
	intent.Objective = objective
	intent.Title = title
	values := map[string]any{}
	_ = json.Unmarshal(intent.ConstraintsJSON, &values)
	values["source"] = "graph_reasoner"
	values["source_node_ids"] = sourceNodeIDs
	values["source_node_key"] = sourceKey
	values["hypothesis"] = firstNonEmpty(suggestion.Hypothesis, title)
	values["success_criteria"] = suggestion.SuccessCriteria
	values["failure_criteria"] = suggestion.FailureCriteria
	values["allowed_tools"] = suggestion.AllowedTools
	values["risk_level"] = suggestion.RiskLevel
	values["requiredEvidence"] = defaultRequiredEvidence(suggestion.RequiredEvidence)
	intent.ConstraintsJSON = mustJSON(values)
	intent.PriorityScore = priority
	intent.UpdatedAt = time.Now().UTC()
	if err := o.db.WithContext(ctx).Save(&intent).Error; err != nil {
		return false
	}
	intentNode, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeIntent,
		Title:           intent.Title,
		Summary:         intent.Objective,
		Content:         intent,
		DedupSeed:       fmt.Sprintf("intent-%d", intent.ID),
		ImportanceScore: intent.PriorityScore,
		SourceType:      "graph-reasoner",
		SourceID:        fmt.Sprintf("%d", intent.ID),
	})
	if intentNode.ID != 0 {
		for _, sourceID := range sourceNodeIDs {
			_ = o.blackboard.AddEdge(ctx, taskID, sourceID, intentNode.ID, model.EdgeSpawnedIntent, 0.82, map[string]any{"intentId": intent.ID, "sourceNodeIds": sourceNodeIDs})
		}
		if parentNodeID != 0 {
			_ = o.blackboard.AddEdge(ctx, taskID, parentNodeID, intentNode.ID, model.EdgeSpawnedIntent, 0.76, map[string]any{"intentId": intent.ID, "reasonParent": true})
		}
	}
	return true
}

func capCodeAuditSnippets(snippets []CodeAuditSnippet, limit int) []CodeAuditSnippet {
	if limit <= 0 || len(snippets) <= limit {
		return snippets
	}
	return snippets[:limit]
}

func parseUintJSONList(raw []byte) []uint {
	if len(raw) == 0 {
		return nil
	}
	var uints []uint
	if err := json.Unmarshal(raw, &uints); err == nil {
		return uints
	}
	var stringsList []string
	if err := json.Unmarshal(raw, &stringsList); err != nil {
		return nil
	}
	result := make([]uint, 0, len(stringsList))
	for _, item := range stringsList {
		value, err := strconv.ParseUint(strings.TrimSpace(item), 10, 64)
		if err == nil {
			result = append(result, uint(value))
		}
	}
	return result
}

func blackboardNodeIDForEvidence(ctx context.Context, db *gorm.DB, taskID uint, evidenceID uint) uint {
	ref := fmt.Sprintf("%d", evidenceID)
	var node model.AIBlackboardNode
	if err := db.WithContext(ctx).
		Where("task_id = ? AND node_type = ? AND evidence_refs @> ?", taskID, "evidence", mustJSON([]string{ref})).
		Order("importance_score desc, id asc").
		First(&node).Error; err == nil {
		return node.ID
	}
	return 0
}

func blackboardNodeIDForIntent(ctx context.Context, db *gorm.DB, taskID uint, intentID uint) uint {
	var node model.AIBlackboardNode
	if err := db.WithContext(ctx).
		Where("task_id = ? AND node_type = ? AND source_id = ?", taskID, "intent", fmt.Sprintf("%d", intentID)).
		Order("importance_score desc, id asc").
		First(&node).Error; err == nil {
		return node.ID
	}
	return 0
}

func (o *AgentOrchestrator) validReasonSourceNodeIDs(ctx context.Context, taskID uint, requested []uint) []uint {
	candidates := compactUintListForReason(requested)
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) > 6 {
		candidates = candidates[:6]
	}
	var nodes []model.AIBlackboardNode
	_ = o.db.WithContext(ctx).
		Where("task_id = ? AND id IN ? AND status = ?", taskID, candidates, model.BlackboardNodeStatusActive).
		Find(&nodes).Error
	valid := map[uint]struct{}{}
	for _, node := range nodes {
		valid[node.ID] = struct{}{}
	}
	result := make([]uint, 0, len(candidates))
	for _, id := range candidates {
		if _, ok := valid[id]; ok {
			result = append(result, id)
		}
	}
	return result
}

func graphReasonerHypothesisDraft(taskID uint, suggestion SecurityGraphIntentSuggestion, intentType string, sourceNodeIDs []uint) HypothesisDraft {
	title := firstNonEmpty(strings.TrimSpace(suggestion.Title), strings.TrimSpace(suggestion.Objective), strings.TrimSpace(suggestion.Hypothesis))
	description := firstNonEmpty(strings.TrimSpace(suggestion.Objective), strings.TrimSpace(suggestion.Hypothesis), strings.TrimSpace(suggestion.Title))
	sourceRefs := make([]string, 0, len(sourceNodeIDs))
	for _, id := range sourceNodeIDs {
		sourceRefs = append(sourceRefs, fmt.Sprintf("node:%d", id))
	}
	return HypothesisDraft{
		TaskID:                taskID,
		HypothesisType:        workerHypothesisTypeForIntent(intentType),
		Title:                 title,
		Description:           description,
		ConfidenceState:       model.ConfidencePlausible,
		SourceObservationRefs: sourceRefs,
		TargetEntity:          firstNonEmpty(strings.TrimSpace(suggestion.Objective), strings.TrimSpace(suggestion.Title)),
		ExpectedCapability:    graphExpectedCapabilityForIntent(intentType),
		IntentConstraints: map[string]any{
			"source":          "graph_reasoner",
			"source_node_ids": sourceNodeIDs,
		},
		ExpansionScore: graphReasonerPriority(suggestion.Priority),
	}
}

func graphExpectedCapabilityForIntent(intentType string) string {
	if strings.EqualFold(strings.TrimSpace(intentType), model.IntentAuthProbe) {
		return model.CapAuthenticatedSession
	}
	return workerExpectedCapabilityForIntent(intentType)
}

func graphReasonerPriority(priority int) float64 {
	if priority <= 0 {
		return 0.82
	}
	return clampRange(float64(priority)/100.0, 0.45, 0.95)
}

func defaultRequiredEvidence(values []string) []string {
	cleaned := compactStringListForModel(values)
	if len(cleaned) > 0 {
		return cleaned
	}
	return []string{"validation_result", "scope_statement", "safety_statement"}
}

func safeIntentID(intent *model.AIIntent) uint {
	if intent == nil {
		return 0
	}
	return intent.ID
}

func uintListKey(values []uint) string {
	ids := append([]uint(nil), values...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatUint(uint64(id), 10))
	}
	return strings.Join(parts, ",")
}

func compactUintListForReason(values []uint) []uint {
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

func graphIntentConstraints(parent *model.AIIntent, next SecurityGraphIntentSuggestion, sourceNodeIDs []uint) map[string]any {
	parentID := uint(0)
	if parent != nil {
		parentID = parent.ID
	}
	constraints := map[string]any{
		"source":            "graph_reasoner",
		"parentIntentId":    parentID,
		"requiredEvidence":  defaultRequiredEvidence(next.RequiredEvidence),
		"source_node_ids":   sourceNodeIDs,
		"hypothesis":        next.Hypothesis,
		"success_criteria":  next.SuccessCriteria,
		"failure_criteria":  next.FailureCriteria,
		"allowed_tools":     next.AllowedTools,
		"risk_level":        next.RiskLevel,
		"reasoner_priority": next.Priority,
	}
	text := strings.ToLower(next.Title + "\n" + next.Objective + "\n" + strings.Join(next.RequiredEvidence, "\n"))
	if strings.Contains(text, "marker") || strings.Contains(text, "parameter") || strings.Contains(text, "参数") || strings.Contains(text, "响应差异") {
		constraints["validation_candidates"] = []map[string]any{{
			"url":      "",
			"param":    "rabbit_validation",
			"method":   "GET",
			"location": "query",
		}}
	}
	return constraints
}

func (o *AgentOrchestrator) loadEvidenceItems(ctx context.Context, evidenceIDs []uint) []model.AIEvidence {
	if len(evidenceIDs) == 0 {
		return nil
	}
	var items []model.AIEvidence
	_ = o.db.WithContext(ctx).Where("id IN ?", evidenceIDs).Order("id asc").Find(&items).Error
	return items
}

func (o *AgentOrchestrator) loadTaskEvidenceItems(ctx context.Context, taskID uint, limit int) []model.AIEvidence {
	if limit <= 0 || limit > 200 {
		limit = 80
	}
	var items []model.AIEvidence
	_ = o.db.WithContext(ctx).
		Where("task_id = ?", taskID).
		Order("created_at desc, id desc").
		Limit(limit).
		Find(&items).Error
	return items
}

func evidenceIDsFromItems(items []model.AIEvidence) []uint {
	ids := make([]uint, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

func (o *AgentOrchestrator) buildCodeAuditSnippets(task *model.AISecurityTask, items []model.AIEvidence, limit int) []CodeAuditSnippet {
	if limit <= 0 {
		limit = o.codeAuditMaxSnippets()
	}
	root := filepath.Join(o.cfg.WorkspaceRoot, fmt.Sprintf("task-%d", task.ID), "input", "extracted")
	ordered := prioritizedSliceTargets(items, limit*2)
	snippets := make([]CodeAuditSnippet, 0, limit)
	seen := map[string]struct{}{}
	for _, item := range ordered {
		if item.FilePath == "" || item.LineStart == nil {
			continue
		}
		center := *item.LineStart
		key := fmt.Sprintf("%s:%d", strings.ToLower(filepath.Clean(item.FilePath)), center/90)
		if _, ok := seen[key]; ok {
			continue
		}
		radius := codeSliceRadiusForEvidence(item)
		content, startLine, endLine, ok := readCodeAuditWindow(root, item.FilePath, center, radius, 9000)
		if !ok {
			continue
		}
		seen[key] = struct{}{}
		snippets = append(snippets, CodeAuditSnippet{
			EvidenceID: item.ID,
			FilePath:   item.FilePath,
			LineStart:  startLine,
			LineEnd:    endLine,
			Summary:    item.Summary,
			Content:    content,
		})
		if len(snippets) >= limit {
			return snippets
		}
	}
	return snippets
}

func readCodeAuditWindow(root, filePath string, center, radius, maxBytes int) (string, int, int, bool) {
	if center <= 0 {
		center = 1
	}
	if radius <= 0 {
		radius = 40
	}
	cleanPath := filepath.Clean(strings.TrimPrefix(strings.ReplaceAll(filePath, "\\", "/"), "/"))
	candidates := []string{cleanPath}
	if strings.HasPrefix(cleanPath, "extracted"+string(filepath.Separator)) || strings.HasPrefix(cleanPath, "extracted/") {
		candidates = append(candidates, strings.TrimPrefix(strings.TrimPrefix(cleanPath, "extracted"+string(filepath.Separator)), "extracted/"))
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", 0, 0, false
	}
	for _, candidate := range candidates {
		targetAbs, err := filepath.Abs(filepath.Join(rootAbs, candidate))
		if err != nil {
			continue
		}
		if targetAbs != rootAbs && !strings.HasPrefix(targetAbs, rootAbs+string(filepath.Separator)) {
			continue
		}
		raw, err := os.ReadFile(targetAbs)
		if err != nil {
			continue
		}
		lines := strings.Split(string(raw), "\n")
		if len(lines) == 0 {
			return "", 0, 0, false
		}
		startLine := maxInt(1, center-radius)
		endLine := center + radius
		if endLine > len(lines) {
			endLine = len(lines)
		}
		var builder strings.Builder
		for lineNo := startLine; lineNo <= endLine; lineNo++ {
			builder.WriteString(fmt.Sprintf("%5d | %s", lineNo, strings.TrimRight(lines[lineNo-1], "\r")))
			if lineNo < endLine {
				builder.WriteByte('\n')
			}
			if maxBytes > 0 && builder.Len() >= maxBytes {
				builder.WriteString("\n...[truncated]")
				break
			}
		}
		return builder.String(), startLine, endLine, true
	}
	return "", 0, 0, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func intPtrValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (o *AgentOrchestrator) finishIteration(ctx context.Context, iteration *model.AIAgentLoopIteration, status string, cause error) error {
	now := time.Now().UTC()
	iteration.Status = status
	iteration.FinishedAt = &now
	if cause != nil {
		iteration.ErrorMessage = cause.Error()
	}
	if err := o.db.WithContext(ctx).Save(iteration).Error; err != nil {
		return err
	}
	if iteration.CurrentIntentID != nil {
		updates := map[string]any{"status": model.IntentStatusCompleted, "finished_at": now, "updated_at": now}
		if status != "completed" {
			updates["status"] = model.IntentStatusFailed
		}
		_ = o.db.WithContext(ctx).Model(&model.AIIntent{}).Where("id = ?", *iteration.CurrentIntentID).Updates(updates).Error
	}
	return cause
}

func (o *AgentOrchestrator) failTask(ctx context.Context, task *model.AISecurityTask, cause error) error {
	now := time.Now().UTC()
	task.Status = model.TaskStatusFailed
	task.ProgressStage = "执行失败：" + cause.Error()
	task.FinishedAt = &now
	_ = o.db.WithContext(ctx).Save(task).Error
	appendAuditEvent(ctx, o.db, &task.ID, "agent.failed", "agent-runtime", cause.Error(), nil)
	return cause
}

// runFingerprint executes the fingerprint tool against a target and returns the outcome.
func (o *AgentOrchestrator) runFingerprint(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, target string) (ToolRunOutcome, error) {
	return o.toolRuns.Execute(ctx, ToolRunRequest{
		Task:        *task,
		IterationID: &iteration.ID,
		IntentID:    &intent.ID,
		ToolName:    "fingerprint",
		ImageName:   "runner-pentest",
		Input: map[string]any{
			"taskId": task.ID,
			"target": target,
			"mode":   "full",
		},
	})
}

// isFailedPath checks if a file path has a recorded negative_fact (previous failure).
// Used to avoid generating new Intents targeting files that already failed.
func (o *AgentOrchestrator) isFailedPath(ctx context.Context, taskID uint, filePath string) bool {
	var count int64
	_ = o.db.WithContext(ctx).
		Model(&model.AIBlackboardNode{}).
		Where("task_id = ? AND node_type = ? AND status = ? AND title LIKE ?",
			taskID, "negative_fact", model.BlackboardNodeStatusActive, "%"+filePath+"%").
		Count(&count).Error
	return count > 0
}

// hasFullFileSlice checks if a full-file slice already exists for a given file.
func (o *AgentOrchestrator) hasFullFileSlice(ctx context.Context, taskID uint, filePath string) bool {
	var count int64
	_ = o.db.WithContext(ctx).
		Model(&model.AIEvidence{}).
		Where("task_id = ? AND file_path = ? AND relation_type = ?",
			taskID, filePath, "code_source").
		Count(&count).Error
	return count > 0
}
