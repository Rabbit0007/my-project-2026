package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shenji/backend/internal/model"
	"shenji/backend/internal/runner"
	"shenji/backend/internal/tools"

	"gorm.io/datatypes"
)

type workerAgentOutput struct {
	Accepted bool            `json:"accepted"`
	Reason   string          `json:"reason"`
	Data     workerAgentData `json:"data"`
}

func (o *workerAgentOutput) UnmarshalJSON(data []byte) error {
	type workerAgentOutputAlias struct {
		Accepted   bool             `json:"accepted"`
		Reason     string           `json:"reason"`
		Data       workerAgentData  `json:"data"`
		GraphDelta workerGraphDelta `json:"graph_delta"`
	}
	var raw workerAgentOutputAlias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	o.Accepted = raw.Accepted
	o.Reason = raw.Reason
	o.Data = raw.Data
	if raw.GraphDelta.hasContent() {
		o.Data = raw.GraphDelta.toWorkerAgentData(raw.Data)
	}
	return nil
}

type workerAgentData struct {
	Summary               string                          `json:"summary"`
	Facts                 []string                        `json:"facts"`
	Evidence              []workerAgentEvidence           `json:"evidence"`
	CapabilityCandidates  []workerAgentCapability         `json:"capability_candidates"`
	NegativeFacts         []workerAgentNegativeFact       `json:"negative_facts"`
	UnverifiedRisks       []workerAgentUnverifiedRisk     `json:"unverified_risks"`
	NextIntentSuggestions []SecurityGraphIntentSuggestion `json:"next_intent_suggestions"`
}

type workerGraphDelta struct {
	NewFacts                []json.RawMessage         `json:"new_facts"`
	UpdatedFacts            []json.RawMessage         `json:"updated_facts"`
	NewIntents              []json.RawMessage         `json:"new_intents"`
	NewEvidence             []workerAgentEvidence     `json:"new_evidence"`
	NewNegativeFacts        []workerAgentNegativeFact `json:"new_negative_facts"`
	NewCapabilityCandidates []workerAgentCapability   `json:"new_capability_candidates"`
	VerifiedCapabilities    []workerAgentCapability   `json:"verified_capabilities"`
	Diagnostics             []string                  `json:"diagnostics"`
	Errors                  []string                  `json:"errors"`
}

func (d workerGraphDelta) hasContent() bool {
	return len(d.NewFacts)+len(d.UpdatedFacts)+len(d.NewIntents)+len(d.NewEvidence)+len(d.NewNegativeFacts)+len(d.NewCapabilityCandidates)+len(d.VerifiedCapabilities)+len(d.Diagnostics)+len(d.Errors) > 0
}

func (d workerGraphDelta) toWorkerAgentData(existing workerAgentData) workerAgentData {
	out := existing
	out.Facts = append(out.Facts, normalizeWorkerGraphFacts(d.NewFacts)...)
	out.Facts = append(out.Facts, normalizeWorkerGraphFacts(d.UpdatedFacts)...)
	out.Evidence = append(out.Evidence, d.NewEvidence...)
	out.CapabilityCandidates = append(out.CapabilityCandidates, d.NewCapabilityCandidates...)
	out.CapabilityCandidates = append(out.CapabilityCandidates, d.VerifiedCapabilities...)
	out.NegativeFacts = append(out.NegativeFacts, d.NewNegativeFacts...)
	out.NextIntentSuggestions = append(out.NextIntentSuggestions, normalizeWorkerNextIntentSuggestions(d.NewIntents)...)
	if out.Summary == "" {
		out.Summary = firstNonEmpty(strings.Join(d.Diagnostics, "; "), strings.Join(d.Errors, "; "), "Worker returned GraphDelta.")
	}
	return out
}

func normalizeWorkerGraphFacts(rawItems []json.RawMessage) []string {
	items := make([]string, 0, len(rawItems))
	for _, raw := range rawItems {
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			text = strings.TrimSpace(text)
			if text != "" {
				items = append(items, text)
			}
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		candidate := firstNonEmpty(
			stringFromMap(obj, "summary"),
			stringFromMap(obj, "subject"),
			stringFromMap(obj, "title"),
			stringFromMap(obj, "kind"),
		)
		if candidate != "" {
			items = append(items, candidate)
		}
	}
	return items
}

func stringFromMap(values map[string]any, key string) string {
	if value, ok := values[key]; ok && value != nil {
		return strings.TrimSpace(fmt.Sprint(value))
	}
	return ""
}

func (d *workerAgentData) UnmarshalJSON(data []byte) error {
	type workerAgentDataAlias struct {
		Summary               string                      `json:"summary"`
		Facts                 []string                    `json:"facts"`
		Evidence              []workerAgentEvidence       `json:"evidence"`
		CapabilityCandidates  []workerAgentCapability     `json:"capability_candidates"`
		NegativeFacts         []workerAgentNegativeFact   `json:"negative_facts"`
		UnverifiedRisks       []workerAgentUnverifiedRisk `json:"unverified_risks"`
		NextIntentSuggestions []json.RawMessage           `json:"next_intent_suggestions"`
	}
	var raw workerAgentDataAlias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d.Summary = raw.Summary
	d.Facts = raw.Facts
	d.Evidence = raw.Evidence
	d.CapabilityCandidates = raw.CapabilityCandidates
	d.NegativeFacts = raw.NegativeFacts
	d.UnverifiedRisks = raw.UnverifiedRisks
	d.NextIntentSuggestions = normalizeWorkerNextIntentSuggestions(raw.NextIntentSuggestions)
	return nil
}

type workerAgentEvidence struct {
	Type         string `json:"type"`
	Title        string `json:"title"`
	Summary      string `json:"summary"`
	Raw          string `json:"raw"`
	ArtifactPath string `json:"artifact_path"`
	Target       string `json:"target"`
	RelationType string `json:"relation_type"`
}

type workerAgentCapability struct {
	CapabilityType string `json:"capability_type"`
	Name           string `json:"name"`
	Target         string `json:"target"`
	Strength       string `json:"strength"`
	ProofSummary   string `json:"proof_summary"`
	Summary        string `json:"summary"`
}

type workerAgentNegativeFact struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Target  string `json:"target"`
}

type workerAgentUnverifiedRisk struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Target  string `json:"target"`
	Reason  string `json:"reason"`
}

type workerGraphIngestSummary struct {
	FactsCreated           int `json:"factsCreated"`
	CapabilitiesCreated    int `json:"capabilitiesCreated"`
	CapabilitiesSkipped    int `json:"capabilitiesSkipped"`
	NegativeFactsCreated   int `json:"negativeFactsCreated"`
	UnverifiedRisksCreated int `json:"unverifiedRisksCreated"`
	NextIntentsCreated     int `json:"nextIntentsCreated"`
	NextIntentsSkipped     int `json:"nextIntentsSkipped"`
}

type workerFactQuality struct {
	Score                     float64  `json:"score"`
	PersistedEvidenceCount    int      `json:"persistedEvidenceCount"`
	StructuredEvidenceCount   int      `json:"structuredEvidenceCount"`
	FactCount                 int      `json:"factCount"`
	CapabilityCandidateCount  int      `json:"capabilityCandidateCount"`
	NegativeFactCount         int      `json:"negativeFactCount"`
	UnverifiedRiskCount       int      `json:"unverifiedRiskCount"`
	NextIntentSuggestionCount int      `json:"nextIntentSuggestionCount"`
	Reasons                   []string `json:"reasons"`
}

const (
	maxWorkerFacts                 = 12
	maxWorkerEvidenceItems         = 8
	maxWorkerCapabilityCandidates  = 4
	maxWorkerNegativeFacts         = 8
	maxWorkerUnverifiedRisks       = 8
	maxWorkerNextIntentSuggestions = 3
	maxWorkerOutputTextLength      = 60000
	defaultPiWorkerMaxToolCalls    = 6
)

type workerPhaseContract struct {
	BrainResponsibilities    []string `json:"brain_responsibilities"`
	WorkerResponsibilities   []string `json:"worker_responsibilities"`
	ToolResponsibilities     []string `json:"tool_responsibilities"`
	DeliveryResponsibilities []string `json:"delivery_responsibilities"`
	ForbiddenWorkerDecisions []string `json:"forbidden_worker_decisions"`
}

func (o *AgentOrchestrator) runExternalWorkerIntent(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, agentContext AgentContext, worker WorkerRuntimeSelection) (bool, []ToolRunOutcome, error) {
	var options modelRuntimeOptions
	_ = unmarshalJSON(worker.Config.OptionsJSON, &options)
	driver := normalizeWorkerDriver(options.WorkerDriver)
	options.WorkerDriver = driver
	if driver == "" || driver == "native" {
		return false, nil, nil
	}
	if driver == "pi_container_kali" {
		outcome, err := o.runPiContainerKaliWorkerIntent(ctx, task, intent, iteration, agentContext, worker, options)
		if err != nil {
			appendAuditEvent(ctx, o.db, &task.ID, "agent.pi_worker_failed", "worker-runtime",
				err.Error(), map[string]any{"intentId": intent.ID, "workerId": worker.WorkerID, "driver": driver})
			if outcome.ToolRun.ID == 0 {
				return true, nil, err
			}
			return true, []ToolRunOutcome{outcome}, nil
		}
		return true, []ToolRunOutcome{outcome}, nil
	}
	return true, nil, fmt.Errorf("unsupported worker driver %q", options.WorkerDriver)
}

func (o *AgentOrchestrator) runPiContainerKaliWorkerIntent(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, iteration *model.AIAgentLoopIteration, agentContext AgentContext, worker WorkerRuntimeSelection, options modelRuntimeOptions) (ToolRunOutcome, error) {
	apiKey, err := resolveModelSecret(worker.Config.APIKeyRef, options.RequiresOpenAIAuth)
	if err != nil {
		return ToolRunOutcome{}, err
	}
	hostAgentDir := filepath.Join(o.cfg.WorkspaceRoot, fmt.Sprintf("task-%d", task.ID), "work", "pi-workers", fmt.Sprintf("%d", worker.Config.ID))
	containerAgentDir := filepath.ToSlash(filepath.Join("/workspace/work/pi-workers", fmt.Sprintf("%d", worker.Config.ID)))
	containerSessionDir := filepath.ToSlash(filepath.Join(containerAgentDir, "sessions"))
	if err := os.MkdirAll(filepath.Join(hostAgentDir, "sessions"), 0o755); err != nil {
		return ToolRunOutcome{}, err
	}
	modelsJSON, err := piModelsJSON(worker.Config, options, apiKey)
	if err != nil {
		return ToolRunOutcome{}, err
	}
	if err := os.WriteFile(filepath.Join(hostAgentDir, "models.json"), []byte(modelsJSON), 0o600); err != nil {
		return ToolRunOutcome{}, err
	}
	phaseContract := buildWorkerPhaseContract()
	snapshotPath, err := writePiWorkerRuntimeSnapshot(hostAgentDir, *task, *intent, agentContext, worker, options, "pi_container_kali", phaseContract)
	if err != nil {
		return ToolRunOutcome{}, err
	}
	containerSnapshotPath := containerPathForTaskWork(task.ID, snapshotPath)
	prompt := buildPiContainerWorkerPrompt(*task, *intent, containerSnapshotPath, phaseContract)
	toolsArg := strings.Join(normalizePiWorkerTools(options.WorkerTools), ",")
	args := []string{
		"sh",
		"-lc",
		fmt.Sprintf(`exec env PI_CODING_AGENT_DIR=%s pi --no-extensions --no-skills --no-prompt-templates --no-themes --no-context-files --tools %s --provider rabbit --model %s --mode json --session-dir %s --no-session -p "$RABBIT_PI_PROMPT"`,
			shellQuote(containerAgentDir),
			shellQuote(toolsArg),
			shellQuote(worker.Config.Model),
			shellQuote(containerSessionDir),
		),
	}
	input := map[string]any{
		"driver":         "pi_container_kali",
		"workerId":       worker.WorkerID,
		"modelId":        worker.Config.ID,
		"model":          worker.Config.Model,
		"intentId":       intent.ID,
		"intentType":     intent.IntentType,
		"tools":          normalizePiWorkerTools(options.WorkerTools),
		"snapshot":       containerSnapshotPath,
		"runtime":        "kali_worker_container",
		"containerImage": o.cfg.PiWorkerImage,
		"phases":         phaseContract,
	}
	inputRaw, _ := json.Marshal(input)
	now := time.Now().UTC()
	toolRun := model.AIToolRun{
		TaskID:             task.ID,
		IterationID:        &iteration.ID,
		IntentID:           &intent.ID,
		RunnerType:         "worker_agent",
		ToolName:           "pi_worker",
		InputJSON:          datatypes.JSON(inputRaw),
		CommandPreview:     "docker exec <task-kali-worker> pi --mode json -p <worker-intent>",
		WorkspacePath:      hostAgentDir,
		NetworkPolicy:      firstNonEmpty(o.cfg.PiWorkerNetworkMode, safePolicyFromTask(*task).NetworkPolicy),
		ResourceLimits:     mustJSON(map[string]any{"driver": "pi_container_kali", "workerId": worker.WorkerID, "containerImage": o.cfg.PiWorkerImage, "timeoutSeconds": int(o.piWorkerTimeout().Seconds())}),
		Status:             model.ToolRunStatusRunning,
		SafePolicySnapshot: mustJSON(safePolicyFromTask(*task)),
		StartedAt:          now,
		CreatedAt:          now,
	}
	if err := o.db.WithContext(ctx).Create(&toolRun).Error; err != nil {
		return ToolRunOutcome{}, err
	}
	contextRef, contextErr := o.persistWorkerExecutionContext(ctx, task, intent, toolRun.ID, agentContext, worker, options)
	if contextErr != nil {
		appendAuditEvent(ctx, o.db, &task.ID, "agent.worker_context_store_failed", "worker-runtime", contextErr.Error(), map[string]any{"intentId": intent.ID, "workerId": worker.WorkerID, "driver": "pi_container_kali"})
	} else if contextRef != "" {
		toolRun.ArtifactRefs = mustJSON(map[string]string{"worker_execution_context": contextRef})
		_ = o.db.WithContext(ctx).Save(&toolRun).Error
	}
	workerCallStarted := time.Now()
	result, runErr := runner.NewRunnerManager(o.cfg).ExecInTaskWorkerContainer(ctx, runner.WorkerContainerExecRequest{
		TaskID:        task.ID,
		Command:       args,
		Env:           []string{"RABBIT_PI_PROMPT=" + prompt},
		Timeout:       o.piWorkerTimeout(),
		WorkingDir:    "/workspace/work",
		NetworkPolicy: firstNonEmpty(o.cfg.PiWorkerNetworkMode, safePolicyFromTask(*task).NetworkPolicy),
	})
	finished := time.Now().UTC()
	stdout := result.Stdout
	stderrText := result.Stderr
	if runErr == nil && result.Status != "success" {
		runErr = fmt.Errorf("pi container worker exited with status %s code %d", result.Status, result.ExitCode)
	}
	if o.models != nil {
		o.models.logModelCall(ctx, &task.ID, worker.Config.Model, worker.Config.Provider, "worker", workerCallStarted, runErr)
	}
	toolRun.FinishedAt = &finished
	toolRun.ContainerID = result.ContainerID
	toolRun.ImageName = result.ImageName
	toolRun.CommandPreview = result.CommandPreview
	toolRun.StdoutRef, _, _ = o.toolRuns.store.PutText(ctx, fmt.Sprintf("task-%d/toolruns/%d-stdout.txt", task.ID, toolRun.ID), stdout)
	toolRun.StderrRef, _, _ = o.toolRuns.store.PutText(ctx, fmt.Sprintf("task-%d/toolruns/%d-stderr.txt", task.ID, toolRun.ID), stderrText)
	if runErr != nil {
		toolRun.Status = model.ToolRunStatusFailed
		toolRun.BlockReason = runErr.Error()
		_ = o.db.WithContext(ctx).Save(&toolRun).Error
		return ToolRunOutcome{ToolRun: toolRun, Result: &tools.ToolResult{Status: "failed", Summary: "Pi Kali worker execution failed", Stdout: stdout, Stderr: stderrText, Metadata: map[string]any{"driver": "pi_container_kali"}}}, runErr
	}
	return o.finalizePiWorkerOutcome(ctx, task, intent, toolRun, stdout, stderrText, now, finished, "pi_container_kali")
}

func (o *AgentOrchestrator) finalizePiWorkerOutcome(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, toolRun model.AIToolRun, stdout string, stderrText string, started time.Time, finished time.Time, driver string) (ToolRunOutcome, error) {
	outputText := extractPiAssistantText(stdout)
	outputRepaired := false
	parsed, err := parseWorkerAgentOutput(outputText)
	if err != nil {
		repaired, repairErr := repairWorkerAgentOutput(outputText)
		if repairErr != nil {
			toolRun.Status = model.ToolRunStatusFailed
			toolRun.BlockReason = err.Error()
			_ = o.db.WithContext(ctx).Save(&toolRun).Error
			return ToolRunOutcome{ToolRun: toolRun, Result: &tools.ToolResult{Status: "failed", Summary: "Pi worker returned invalid structured output", Stdout: stdout, Stderr: stderrText, Metadata: map[string]any{"driver": driver}}}, err
		}
		parsed = repaired
		outputRepaired = true
		appendAuditEvent(ctx, o.db, &task.ID, "agent.pi_worker_output_repaired", "worker-runtime", "Pi worker returned unstructured text; Rabbit captured it as observation-only evidence.", map[string]any{"intentId": intent.ID, "driver": driver})
	}
	if err := validateWorkerAgentOutput(outputText, parsed); err != nil {
		toolRun.Status = model.ToolRunStatusFailed
		toolRun.BlockReason = err.Error()
		_ = o.db.WithContext(ctx).Save(&toolRun).Error
		return ToolRunOutcome{ToolRun: toolRun, Result: &tools.ToolResult{Status: "failed", Summary: "Pi worker returned invalid exploration output", Stdout: stdout, Stderr: stderrText, Metadata: map[string]any{"driver": driver}}}, err
	}
	if !parsed.Accepted {
		toolRun.Status = model.ToolRunStatusBlocked
		toolRun.BlockReason = firstNonEmpty(parsed.Reason, "pi worker rejected intent")
		_ = o.db.WithContext(ctx).Save(&toolRun).Error
		return ToolRunOutcome{ToolRun: toolRun, Result: &tools.ToolResult{Status: "blocked", Summary: toolRun.BlockReason, Stdout: stdout, Stderr: stderrText, Metadata: map[string]any{"driver": driver}}}, errors.New(toolRun.BlockReason)
	}
	toolRun.Status = model.ToolRunStatusSuccess
	if err := o.db.WithContext(ctx).Save(&toolRun).Error; err != nil {
		return ToolRunOutcome{}, err
	}
	evidenceItems, err := o.persistWorkerEvidence(ctx, task.ID, toolRun.ID, parsed)
	if err != nil {
		return ToolRunOutcome{ToolRun: toolRun}, err
	}
	quality := scoreWorkerAgentOutput(parsed, evidenceItems)
	ingestSummary, err := o.ingestWorkerGraphOutput(ctx, task.ID, intent.ID, toolRun.ID, parsed, evidenceItems)
	if err != nil {
		return ToolRunOutcome{ToolRun: toolRun, Evidence: evidenceItems}, err
	}
	appendAuditEvent(ctx, o.db, &task.ID, "agent.pi_worker_completed", "worker-runtime",
		firstNonEmpty(parsed.Data.Summary, "Pi worker completed intent."), map[string]any{"intentId": intent.ID, "driver": driver, "evidenceCount": len(evidenceItems), "graphIngest": ingestSummary, "factQuality": quality})
	return ToolRunOutcome{
		ToolRun:  toolRun,
		Evidence: evidenceItems,
		Result: &tools.ToolResult{
			Status:      "success",
			Summary:     firstNonEmpty(parsed.Data.Summary, "Pi worker returned structured evidence."),
			Stdout:      outputText,
			Stderr:      stderrText,
			CommandHint: "pi worker",
			Metadata: map[string]any{
				"driver":                 driver,
				"workerNegativeFacts":    ingestSummary.NegativeFactsCreated,
				"workerUnverifiedRisks":  ingestSummary.UnverifiedRisksCreated,
				"workerCapabilities":     ingestSummary.CapabilitiesCreated,
				"workerNextIntents":      ingestSummary.NextIntentsCreated,
				"workerFactQualityScore": quality.Score,
				"workerFactQuality":      quality,
				"workerOutputRepaired":   outputRepaired,
			},
			StartedAt:  started,
			FinishedAt: finished,
		},
	}, nil
}

func (o *AgentOrchestrator) persistWorkerEvidence(ctx context.Context, taskID uint, toolRunID uint, output workerAgentOutput) ([]model.AIEvidence, error) {
	drafts := []tools.EvidenceDraft{}
	for _, item := range output.Data.Evidence {
		evidenceType := firstNonEmpty(item.Type, "worker_observation")
		title := firstNonEmpty(item.Title, "Worker evidence")
		summary := firstNonEmpty(item.Summary, output.Data.Summary)
		raw := firstNonEmpty(item.Raw, item.ArtifactPath, summary)
		if strings.TrimSpace(item.ArtifactPath) != "" && !strings.Contains(raw, item.ArtifactPath) {
			raw = strings.TrimSpace(raw) + "\nartifact_path: " + strings.TrimSpace(item.ArtifactPath)
		}
		drafts = append(drafts, tools.EvidenceDraft{
			Type:         evidenceType,
			Title:        title,
			Summary:      summary,
			Raw:          raw,
			Target:       item.Target,
			RelationType: firstNonEmpty(item.RelationType, "worker_result"),
		})
	}
	if len(drafts) == 0 && (strings.TrimSpace(output.Data.Summary) != "" || len(output.Data.Facts) > 0) {
		rawBytes, _ := json.MarshalIndent(output.Data, "", "  ")
		drafts = append(drafts, tools.EvidenceDraft{
			Type:         "worker_observation",
			Title:        "Worker explored intent",
			Summary:      firstNonEmpty(output.Data.Summary, strings.Join(output.Data.Facts, "\n")),
			Raw:          string(rawBytes),
			RelationType: "worker_result",
		})
	}
	items := make([]model.AIEvidence, 0, len(drafts))
	for _, draft := range drafts {
		item, err := o.toolRuns.evidence.CreateFromDraft(ctx, taskID, &toolRunID, draft)
		if err != nil {
			return items, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (o *AgentOrchestrator) persistWorkerExecutionContext(ctx context.Context, task *model.AISecurityTask, intent *model.AIIntent, toolRunID uint, agentContext AgentContext, worker WorkerRuntimeSelection, options modelRuntimeOptions) (string, error) {
	if o.toolRuns == nil || o.toolRuns.store == nil {
		return "", nil
	}
	driver := strings.ToLower(strings.TrimSpace(options.WorkerDriver))
	if driver == "" {
		driver = "native"
	}
	packet := map[string]any{
		"driver":     driver,
		"workerId":   worker.WorkerID,
		"modelId":    worker.Config.ID,
		"model":      worker.Config.Model,
		"provider":   worker.Config.Provider,
		"intent":     intent,
		"taskId":     task.ID,
		"taskType":   task.TaskType,
		"objective":  task.Objective,
		"tools":      normalizePiWorkerTools(options.WorkerTools),
		"safePolicy": safePolicyFromTask(*task),
		"context":    agentContext,
		"runtime": map[string]any{
			"driver":      driver,
			"workerImage": o.cfg.PiWorkerImage,
			"networkMode": o.cfg.PiWorkerNetworkMode,
			"execution":   "task-scoped container exec",
		},
		"phases":    buildWorkerPhaseContract(),
		"createdAt": time.Now().UTC(),
	}
	raw, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		return "", err
	}
	ref, _, err := o.toolRuns.store.PutText(ctx, fmt.Sprintf("task-%d/toolruns/%d-worker-context.json", task.ID, toolRunID), string(raw))
	return ref, err
}

func (o *AgentOrchestrator) ingestWorkerGraphOutput(ctx context.Context, taskID uint, intentID uint, toolRunID uint, output workerAgentOutput, evidenceItems []model.AIEvidence) (workerGraphIngestSummary, error) {
	summary := workerGraphIngestSummary{}
	evidenceIDs := evidenceIDsFromItems(evidenceItems)
	quality := scoreWorkerAgentOutput(output, evidenceItems)
	workerFactImportance := workerFactImportanceScore(quality.Score)
	now := time.Now().UTC()
	hypothesisID := o.workerIntentHypothesisID(ctx, intentID)

	for _, fact := range output.Data.Facts {
		text := strings.TrimSpace(fact)
		if text == "" {
			continue
		}
		_, _ = o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        model.NodeBehaviorFact,
			Title:           truncateString(text, 240),
			Summary:         text,
			Content:         map[string]any{"fact": text, "source": "worker_agent", "intentId": intentID, "toolRunId": toolRunID},
			DedupSeed:       fmt.Sprintf("worker-fact-%d-%s", taskID, stableTextKey(text)),
			ImportanceScore: workerFactImportance,
			SourceType:      "worker-agent",
			SourceID:        fmt.Sprintf("toolrun-%d", toolRunID),
			EvidenceRefs:    evidenceIDs,
		})
		summary.FactsCreated++
	}

	cairn := NewCairnLoop(o.db, o.blackboard, o.intents, o.toolRuns, o.findings, o.contracts, o.models, o.reports, o.compactor)
	for _, candidate := range output.Data.CapabilityCandidates {
		if len(evidenceIDs) == 0 {
			summary.CapabilitiesSkipped++
			continue
		}
		capType := normalizeWorkerCapabilityType(firstNonEmpty(candidate.CapabilityType, candidate.Name))
		target := strings.TrimSpace(candidate.Target)
		proof := strings.TrimSpace(firstNonEmpty(candidate.ProofSummary, candidate.Summary))
		if capType == "" || target == "" || proof == "" {
			summary.CapabilitiesSkipped++
			continue
		}
		strength := workerCapabilityStrength(candidate.Strength)
		canAdvanceGoal := false
		if o.workerCapabilityCandidateIsVerified(ctx, taskID, intentID, capType, output, evidenceItems) {
			strength = model.StrengthVerified
			canAdvanceGoal = true
			proof = o.workerDeliveryProofSummary(ctx, taskID, intentID, capType, evidenceIDs, proof)
		}
		cap, err := cairn.WriteCapability(ctx, taskID, CapabilityDraft{
			CapabilityType: capType,
			Target:         target,
			Strength:       strength,
			ProofSummary:   proof,
			EvidenceIDs:    evidenceIDs,
			CanAdvanceGoal: canAdvanceGoal,
		}, &intentID)
		if err != nil {
			return summary, err
		}
		if cap.ID != 0 {
			summary.CapabilitiesCreated++
		}
	}

	for _, item := range output.Data.NegativeFacts {
		title := firstNonEmpty(strings.TrimSpace(item.Title), "Worker refuted explored path")
		reason := firstNonEmpty(strings.TrimSpace(item.Summary), title)
		target := strings.TrimSpace(item.Target)
		var existing int64
		_ = o.db.WithContext(ctx).Model(&model.AINegativeFact{}).
			Where("task_id = ? AND title = ? AND tested_path = ?", taskID, title, target).
			Count(&existing).Error
		if existing > 0 {
			continue
		}
		nf := model.AINegativeFact{
			TaskID:              taskID,
			HypothesisID:        hypothesisID,
			Title:               truncateString(title, 280),
			TestedPath:          target,
			Reason:              sanitizeUTF8(reason),
			EvidenceRefs:        mustJSON(evidenceIDs),
			SimilarPatternKey:   stableTextKey("worker-negative:" + target + ":" + title),
			CreatedFromIntentID: &intentID,
			CreatedAt:           now,
		}
		if err := o.db.WithContext(ctx).Create(&nf).Error; err != nil {
			return summary, err
		}
		node, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        model.NodeNegativeFact,
			Title:           nf.Title,
			Summary:         nf.Reason,
			Content:         nf,
			DedupSeed:       fmt.Sprintf("worker-negative-fact-%d", nf.ID),
			ImportanceScore: 0.52,
			SourceType:      "worker-agent",
			SourceID:        fmt.Sprintf("toolrun-%d", toolRunID),
			EvidenceRefs:    evidenceIDs,
		})
		if parentID := blackboardNodeIDForIntent(ctx, o.db, taskID, intentID); parentID != 0 && node.ID != 0 {
			_ = o.blackboard.AddEdge(ctx, taskID, node.ID, parentID, model.EdgeRefutes, 0.76, map[string]any{"negativeFactId": nf.ID, "intentId": intentID})
		}
		summary.NegativeFactsCreated++
	}

	for _, item := range output.Data.UnverifiedRisks {
		title := firstNonEmpty(strings.TrimSpace(item.Title), "Worker could not verify explored path")
		detail := firstNonEmpty(strings.TrimSpace(item.Summary), title)
		reason := firstNonEmpty(strings.TrimSpace(item.Reason), "worker_inconclusive")
		var existing int64
		_ = o.db.WithContext(ctx).Model(&model.AIUnverifiedRisk{}).
			Where("task_id = ? AND title = ? AND reason = ?", taskID, title, reason).
			Count(&existing).Error
		if existing > 0 {
			continue
		}
		risk := model.AIUnverifiedRisk{
			TaskID:            taskID,
			HypothesisID:      hypothesisID,
			Title:             truncateString(title, 280),
			Reason:            truncateString(reason, 80),
			Detail:            sanitizeUTF8(detail),
			ObservationRefs:   mustJSON([]string{fmt.Sprintf("worker_toolrun:%d", toolRunID)}),
			EvidenceRefs:      mustJSON(evidenceIDs),
			BlockedByIntentID: &intentID,
			CreatedAt:         now,
		}
		if err := o.db.WithContext(ctx).Create(&risk).Error; err != nil {
			return summary, err
		}
		node, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        model.NodeUnverifiedRisk,
			Title:           risk.Title,
			Summary:         risk.Detail,
			Content:         risk,
			DedupSeed:       fmt.Sprintf("worker-unverified-risk-%d", risk.ID),
			ImportanceScore: 0.62,
			SourceType:      "worker-agent",
			SourceID:        fmt.Sprintf("toolrun-%d", toolRunID),
			EvidenceRefs:    evidenceIDs,
		})
		if parentID := blackboardNodeIDForIntent(ctx, o.db, taskID, intentID); parentID != 0 && node.ID != 0 {
			_ = o.blackboard.AddEdge(ctx, taskID, node.ID, parentID, model.EdgeBlocks, 0.74, map[string]any{"unverifiedRiskId": risk.ID, "intentId": intentID})
		}
		summary.UnverifiedRisksCreated++
	}

	requested := len(output.Data.NextIntentSuggestions)
	if requested > 0 {
		decision := NewExplorationBudgetManager(o.db).AllowIntentGenerationFor(ctx, taskID, requested, DefaultExplorationBudgetConfig(), "worker_agent")
		if !decision.Allowed {
			summary.NextIntentsSkipped += requested
			appendAuditEvent(ctx, o.db, &taskID, "worker_agent.next_intents_blocked", "exploration-budget-manager", decision.Reason, map[string]any{"intentId": intentID, "decision": decision})
		} else {
			allowed := decision.MaxToGenerate
			for _, suggestion := range output.Data.NextIntentSuggestions {
				if allowed <= 0 {
					summary.NextIntentsSkipped++
					continue
				}
				created, skipped := o.createWorkerSuggestedIntent(ctx, taskID, intentID, toolRunID, suggestion, evidenceIDs, quality)
				if skipped {
					summary.NextIntentsSkipped++
					continue
				}
				if created {
					summary.NextIntentsCreated++
					allowed--
				}
			}
		}
	}
	o.scoreWorkerGeneratedIntents(ctx, taskID)

	appendAuditEvent(ctx, o.db, &taskID, "worker_agent.graph_ingested", "worker-runtime", "Worker facts and evidence were ingested into Rabbit graph state.", map[string]any{"intentId": intentID, "toolRunId": toolRunID, "summary": summary, "factQuality": quality})
	return summary, nil
}

func (o *AgentOrchestrator) createWorkerSuggestedIntent(ctx context.Context, taskID uint, parentIntentID uint, toolRunID uint, suggestion SecurityGraphIntentSuggestion, evidenceIDs []uint, quality workerFactQuality) (bool, bool) {
	title := firstNonEmpty(strings.TrimSpace(suggestion.Title), strings.TrimSpace(suggestion.Objective))
	objective := firstNonEmpty(strings.TrimSpace(suggestion.Objective), title)
	if title == "" || objective == "" {
		return false, true
	}
	if NewCairnLoop(o.db, o.blackboard, o.intents, o.toolRuns, o.findings, o.contracts, o.models, o.reports, o.compactor).intentMatchesNegativeFact(ctx, taskID, title, objective) {
		return false, true
	}
	intentType, ok := workerSuggestedIntentType(suggestion.IntentType)
	if !ok {
		appendAuditEvent(ctx, o.db, &taskID, "worker_agent.unsupported_intent_skipped", "worker-runtime", "Worker suggested an unsupported intent type; skipped.", map[string]any{"parentIntentId": parentIntentID, "intentType": suggestion.IntentType})
		return false, true
	}
	var existing int64
	_ = o.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("task_id = ? AND intent_type = ? AND objective = ? AND status IN ?", taskID, intentType, objective, []string{model.IntentStatusPending, model.IntentStatusRunning, model.IntentStatusCompleted}).
		Count(&existing).Error
	if existing > 0 {
		return false, true
	}
	parentNodeID := blackboardNodeIDForIntent(ctx, o.db, taskID, parentIntentID)
	lifecycle := NewHypothesisLifecycleService(o.db, o.blackboard)
	hypothesis, err := lifecycle.FormHypothesis(ctx, workerSuggestionHypothesisDraft(taskID, parentIntentID, toolRunID, parentNodeID, suggestion, evidenceIDs))
	if err != nil {
		return false, true
	}
	intent, err := lifecycle.CreateValidationIntent(ctx, hypothesis, intentType, "worker_suggested_followup", 0.68)
	if err != nil {
		return false, true
	}
	intent.CreatedBy = "worker-agent"
	intent.CreatedReason = "Worker suggested follow-up exploration from observed evidence; StateExpansionPlanner and NextPending still control execution."
	intent.RequiredEvidence = mustJSON(suggestion.RequiredEvidence)
	intent.Objective = objective
	values := map[string]any{}
	_ = json.Unmarshal(intent.ConstraintsJSON, &values)
	values["source"] = "worker_agent"
	values["parentIntentId"] = parentIntentID
	values["toolRunId"] = toolRunID
	values["evidenceIds"] = evidenceIDs
	values["workerFactQualityScore"] = quality.Score
	intent.ConstraintsJSON = mustJSON(values)
	intent.UpdatedAt = time.Now().UTC()
	if err := o.db.WithContext(ctx).Save(&intent).Error; err != nil {
		return false, true
	}
	intentNode, _ := o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeIntent,
		Title:           intent.Title,
		Summary:         intent.Objective,
		Content:         intent,
		DedupSeed:       fmt.Sprintf("intent-%d", intent.ID),
		ImportanceScore: intent.PriorityScore,
		SourceType:      "worker-agent",
		SourceID:        fmt.Sprintf("%d", intent.ID),
		EvidenceRefs:    evidenceIDs,
	})
	if parentNodeID != 0 && intentNode.ID != 0 {
		_ = o.blackboard.AddEdge(ctx, taskID, parentNodeID, intentNode.ID, model.EdgeSpawnedIntent, 0.78, map[string]any{"parentIntentId": parentIntentID, "intentId": intent.ID, "toolRunId": toolRunID})
	}
	return true, false
}

func (o *AgentOrchestrator) workerIntentHypothesisID(ctx context.Context, intentID uint) *uint {
	var intent model.AIIntent
	if err := o.db.WithContext(ctx).First(&intent, intentID).Error; err != nil {
		return nil
	}
	return intent.HypothesisID()
}

func scoreWorkerAgentOutput(output workerAgentOutput, evidenceItems []model.AIEvidence) workerFactQuality {
	quality := workerFactQuality{
		PersistedEvidenceCount:    len(evidenceItems),
		StructuredEvidenceCount:   len(output.Data.Evidence),
		FactCount:                 len(output.Data.Facts),
		CapabilityCandidateCount:  len(output.Data.CapabilityCandidates),
		NegativeFactCount:         len(output.Data.NegativeFacts),
		UnverifiedRiskCount:       len(output.Data.UnverifiedRisks),
		NextIntentSuggestionCount: len(output.Data.NextIntentSuggestions),
	}
	score := 0.25
	if output.Accepted {
		score += 0.08
	}
	if strings.TrimSpace(output.Data.Summary) != "" {
		score += 0.08
		quality.Reasons = append(quality.Reasons, "summary")
	}
	if len(evidenceItems) > 0 {
		score += 0.18
		quality.Reasons = append(quality.Reasons, "persisted_evidence")
	}
	if detailedWorkerEvidenceCount(output.Data.Evidence) > 0 {
		score += 0.16
		quality.Reasons = append(quality.Reasons, "detailed_evidence")
	}
	if len(output.Data.Facts) > 0 {
		score += 0.08
		quality.Reasons = append(quality.Reasons, "facts")
	}
	if len(output.Data.CapabilityCandidates) > 0 && len(evidenceItems) > 0 {
		score += 0.07
		quality.Reasons = append(quality.Reasons, "evidence_backed_capability_candidate")
	}
	if len(output.Data.NegativeFacts) > 0 || len(output.Data.UnverifiedRisks) > 0 {
		score += 0.07
		quality.Reasons = append(quality.Reasons, "resolution_facts")
	}
	if len(output.Data.NextIntentSuggestions) > 0 && len(output.Data.NextIntentSuggestions) <= maxWorkerNextIntentSuggestions {
		score += 0.04
		quality.Reasons = append(quality.Reasons, "bounded_next_intents")
	}
	if len(output.Data.CapabilityCandidates) > 0 && len(evidenceItems) == 0 {
		score -= 0.14
		quality.Reasons = append(quality.Reasons, "capability_candidate_without_evidence")
	}
	if len(output.Data.Evidence) == 0 && len(output.Data.Facts) == 0 && strings.TrimSpace(output.Data.Summary) != "" {
		score -= 0.06
		quality.Reasons = append(quality.Reasons, "summary_only")
	}
	quality.Score = clampRange(score, 0.20, 0.90)
	return quality
}

func detailedWorkerEvidenceCount(items []workerAgentEvidence) int {
	count := 0
	for _, item := range items {
		if strings.TrimSpace(item.Title) != "" &&
			strings.TrimSpace(item.Summary) != "" &&
			strings.TrimSpace(firstNonEmpty(item.Raw, item.Target)) != "" {
			count++
		}
	}
	return count
}

func workerFactImportanceScore(qualityScore float64) float64 {
	return clampRange(0.42+(qualityScore*0.38), 0.45, 0.78)
}

func (o *AgentOrchestrator) scoreWorkerGeneratedIntents(ctx context.Context, taskID uint) {
	var task model.AISecurityTask
	if err := o.db.WithContext(ctx).First(&task, taskID).Error; err != nil {
		return
	}
	_ = NewStateExpansionPlannerService(o.db).ScorePendingValidationIntents(ctx, task)
}

func workerSuggestionHypothesisDraft(taskID uint, parentIntentID uint, toolRunID uint, parentNodeID uint, suggestion SecurityGraphIntentSuggestion, evidenceIDs []uint) HypothesisDraft {
	title := firstNonEmpty(suggestion.Title, suggestion.Objective)
	description := firstNonEmpty(suggestion.Objective, suggestion.Title)
	sourceRefs := []string{fmt.Sprintf("worker_intent:%d", parentIntentID), fmt.Sprintf("worker_toolrun:%d", toolRunID)}
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

func writePiWorkerRuntimeSnapshot(agentDir string, task model.AISecurityTask, intent model.AIIntent, agentContext AgentContext, worker WorkerRuntimeSelection, options modelRuntimeOptions, driver string, phaseContract workerPhaseContract) (string, error) {
	contextDir := filepath.Join(agentDir, "context")
	if err := os.MkdirAll(contextDir, 0o755); err != nil {
		return "", err
	}
	snapshotPath := filepath.Join(contextDir, fmt.Sprintf("intent-%d-context.json", intent.ID))
	packet := map[string]any{
		"task": map[string]any{
			"id":            task.ID,
			"type":          task.TaskType,
			"objective":     task.Objective,
			"scope":         task.ScopeJSON,
			"authorization": task.AuthorizationJSON,
		},
		"intent":         intent,
		"graph":          agentContext,
		"graph_summary":  agentContext.GraphSummary,
		"safe_policy":    safePolicyFromTask(task),
		"phase_contract": phaseContract,
		"runtime": map[string]any{
			"driver":        driver,
			"container":     "task-scoped Kali-capable worker container",
			"tools":         normalizePiWorkerTools(options.WorkerTools),
			"tool_policy":   "Pi may use local bash and installed Kali tools inside the task worker container.",
			"turn_policy":   fmt.Sprintf("Bounded worker turn: execute the current intent, prefer one compact script for repeated checks, use at most %d tool calls, then return compact JSON facts/evidence.", defaultPiWorkerMaxToolCalls),
			"timeout":       map[string]any{"bash_command_max_seconds": 60},
			"output_policy": "Return structured facts and evidence only; Rabbit Brain judges graph state and delivery artifacts.",
		},
		"worker": map[string]any{
			"id":             worker.WorkerID,
			"model_config":   worker.Config.ID,
			"model":          worker.Config.Model,
			"max_running":    worker.MaxRunning,
			"current_load":   worker.Running,
			"driver":         driver,
			"task_types":     worker.TaskTypes,
			"ownership_note": "This worker owns only the current intent. Other workers may explore other intents, but not this clue.",
		},
		"contract": map[string]any{
			"role": "Explore the current intent and return a GraphDelta-style packet. Rabbit Brain judges graph state, hypothesis resolution, Finding, Contract, and Report.",
			"forbidden_outputs": []string{
				"finding",
				"report",
				"contract",
				"task_completion_decision",
				"proof_packet",
			},
		},
		"created_at": time.Now().UTC(),
	}
	raw, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(snapshotPath, raw, 0o600); err != nil {
		return "", err
	}
	return snapshotPath, nil
}

func containerPathForTaskWork(taskID uint, hostPath string) string {
	taskWork := filepath.Join("task-"+fmt.Sprint(taskID), "work")
	parts := strings.Split(filepath.ToSlash(hostPath), filepath.ToSlash(taskWork)+"/")
	if len(parts) != 2 {
		return hostPath
	}
	return filepath.ToSlash(filepath.Join("/workspace/work", parts[1]))
}

func buildWorkerPhaseContract() workerPhaseContract {
	return workerPhaseContract{
		BrainResponsibilities: []string{
			"Read graph state and decide which Hypothesis or Intent should exist next.",
			"Score and budget branch expansion before execution.",
			"Resolve Hypothesis state from evidence, blocked runs, NegativeFacts, and UnverifiedRisks.",
			"Promote evidence-backed validated capabilities into delivery artifacts when appropriate.",
		},
		WorkerResponsibilities: []string{
			"Claim and execute exactly one current Intent.",
			"Use controlled tools to observe or validate only within authorized scope.",
			"Return incremental facts, evidence, NegativeFacts, UnverifiedRisks, capability candidates, or follow-up intent suggestions.",
			"Stop at fact production; Rabbit Brain performs graph judgment.",
		},
		ToolResponsibilities: []string{
			"Perform bounded observation or validation actions.",
			"Respect SafePolicy, scope, timeout, and workspace boundaries.",
			"Produce raw observations suitable for Evidence normalization.",
		},
		DeliveryResponsibilities: []string{
			"Generate Findings only from evidence-backed validated paths.",
			"Use Contract as report quality gate, not as exploration planner.",
			"Render reports after graph exploration produces sufficient facts.",
		},
		ForbiddenWorkerDecisions: []string{
			"Do not decide that the goal is complete.",
			"Do not mark a Hypothesis as validated or refuted.",
			"Do not create or confirm Findings.",
			"Do not run Contract checks or report formatting.",
			"Do not perform external CVE, PoC, ProofPacket, or repository lookup.",
		},
	}
}

func buildPiContainerWorkerPrompt(task model.AISecurityTask, intent model.AIIntent, snapshotPath string, phaseContract workerPhaseContract) string {
	intentRaw, _ := json.MarshalIndent(intent, "", "  ")
	phaseRaw, _ := json.MarshalIndent(phaseContract, "", "  ")
	return fmt.Sprintf(`You are a Rabbit Pi worker agent running inside a task-scoped Kali-capable worker container.

Rabbit is a Cairn-style state-space exploration system:
Fact / Observation / Evidence -> Hypothesis / Intent -> Worker Explore -> Evidence / New Fact -> Rabbit Brain decides the next Intent.

Your job is to explore only the Current Intent inside the authorized task scope. You may use local files, bash, and installed tools in this worker container to observe or validate the current Intent. You are not limited to a fixed Rabbit gateway action list.

Before exploring, read the full execution snapshot from:
%s

The snapshot contains GraphSummary, graph facts, evidence context, NegativeFacts, capability state, safe policy, phase boundaries, and the current Intent. Treat GraphSummary as the source of truth. The inline Intent below is only a quick routing copy.

Phase Responsibility Contract:
%s

Strict boundaries:
- Explore only the current Intent; do not take ownership of unrelated clues.
- Treat this as a short bounded worker turn, not an open-ended autonomous session.
- Prefer one compact bash/Python script when the Intent contains multiple URLs, payloads, candidates, or baseline/variant comparisons.
- Use at most %d tool calls before returning.
- If the Intent includes validation_candidates, candidate URLs, parameters, payloads, success_criteria, or failure_criteria, execute enough of those candidates to decide the current Intent instead of checking only the first obvious example.
- Do not stop on a weak partial observation. Stop when you have clear supporting evidence, a clear NegativeFact, or a concrete UnverifiedRisk explaining exactly what prevented validation.
- Every bash command that can touch network, scan, crawl, grep broad trees, or run a server-side probe must include its own timeout of 60 seconds or less.
- For port or service discovery, prefer targeted non-destructive checks with tight bounds such as --host-timeout, --max-retries 1, and version-light flags; if those bounds are insufficient, return an UnverifiedRisk instead of continuing.
- Return facts, evidence, NegativeFacts, UnverifiedRisks, capability candidates, or next_intent_suggestions only.
- Do not create Findings, Reports, Contracts, or task completion decisions.
- Do not turn this into external CVE/PoC repository lookup or ProofPacket-style side probing.
- Save long command output, scan output, request/response packets, or proof files under /workspace/evidence or /workspace/artifacts and reference the path in artifact_path.
- If a path is refuted, return a NegativeFact. If scope, authentication, state, timeout, or tooling prevents a reliable conclusion, return an UnverifiedRisk. Do not invent results.
- Your final output is a GraphDelta-style state change packet. Do not return natural-language conclusions that Rabbit must guess from.
- The final assistant message must be exactly one compact raw JSON object. Do not include thinking text, markdown, commentary, or tool transcripts outside that JSON object.

Return exactly one raw JSON object:
{
  "accepted": true,
  "data": {
    "summary": "short objective result",
    "facts": ["confirmed incremental fact"],
    "evidence": [
      {"type": "http_exchange|response_diff|command_output|scan_result|code_slice|worker_observation", "title": "...", "summary": "...", "raw": "important request/response/log excerpt", "artifact_path": "/workspace/evidence/...", "target": "...", "relation_type": "worker_result"}
    ],
    "capability_candidates": [],
    "negative_facts": [],
    "unverified_risks": [],
    "next_intent_suggestions": []
  }
}

Equivalent GraphDelta form is also accepted:
{"accepted":true,"graph_delta":{"new_facts":[],"new_evidence":[],"new_negative_facts":[],"new_capability_candidates":[],"new_intents":[],"diagnostics":[],"errors":[]}}

If you cannot safely or meaningfully execute the intent, return:
{"accepted": false, "reason": "brief reason"}

Task:
- id: %d
- type: %s
- objective: %s

Current Intent:
%s
`, snapshotPath, string(phaseRaw), defaultPiWorkerMaxToolCalls, task.ID, task.TaskType, task.Objective, string(intentRaw))
}

func piModelsJSON(config model.AIModelConfig, options modelRuntimeOptions, apiKey string) (string, error) {
	providerAPI := strings.TrimSpace(options.WireAPI)
	if providerAPI == "" || providerAPI == "chat_completions" {
		providerAPI = "openai-completions"
	}
	payload := map[string]any{
		"providers": map[string]any{
			"rabbit": map[string]any{
				"baseUrl": strings.TrimRight(config.BaseURL, "/"),
				"api":     providerAPI,
				"apiKey":  apiKey,
				"models": []map[string]any{{
					"id":   config.Model,
					"name": config.Model,
				}},
			},
		},
	}
	raw, err := json.Marshal(payload)
	return string(raw), err
}

func normalizePiWorkerTools(items []string) []string {
	if len(items) == 0 {
		return []string{"read", "write", "edit", "bash", "grep", "find", "ls"}
	}
	allowed := map[string]bool{"read": true, "write": true, "edit": true, "bash": true, "grep": true, "find": true, "ls": true}
	out := []string{}
	for _, item := range items {
		text := strings.ToLower(strings.TrimSpace(item))
		if allowed[text] {
			out = append(out, text)
		}
	}
	if len(out) == 0 {
		return []string{"read", "grep", "find", "ls"}
	}
	return out
}

func extractPiAssistantText(stdout string) string {
	type messagePart struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type message struct {
		Role    string        `json:"role"`
		Content []messagePart `json:"content"`
	}
	var assistant *message
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		var eventType string
		_ = json.Unmarshal(event["type"], &eventType)
		if eventType == "turn_end" {
			var msg message
			if err := json.Unmarshal(event["message"], &msg); err == nil && msg.Role == "assistant" {
				copy := msg
				assistant = &copy
			}
		}
		if eventType == "agent_end" {
			var payload struct {
				Messages []message `json:"messages"`
			}
			if err := json.Unmarshal(event["messages"], &payload.Messages); err != nil {
				_ = json.Unmarshal([]byte(line), &payload)
			}
			for i := len(payload.Messages) - 1; i >= 0; i-- {
				if payload.Messages[i].Role == "assistant" {
					copy := payload.Messages[i]
					assistant = &copy
					break
				}
			}
		}
	}
	if assistant == nil {
		return stdout
	}
	parts := []string{}
	for _, part := range assistant.Content {
		if part.Type == "text" && strings.TrimSpace(part.Text) != "" {
			parts = append(parts, part.Text)
		}
	}
	if len(parts) == 0 {
		return stdout
	}
	return strings.Join(parts, "\n")
}

func parseWorkerAgentOutput(raw string) (workerAgentOutput, error) {
	var output workerAgentOutput
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return output, fmt.Errorf("worker returned empty output")
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
	return output, fmt.Errorf("worker returned non-json output")
}

func normalizeWorkerNextIntentSuggestions(rawItems []json.RawMessage) []SecurityGraphIntentSuggestion {
	if len(rawItems) == 0 {
		return nil
	}
	items := make([]SecurityGraphIntentSuggestion, 0, len(rawItems))
	for _, raw := range rawItems {
		var suggestion SecurityGraphIntentSuggestion
		if err := json.Unmarshal(raw, &suggestion); err == nil {
			if strings.TrimSpace(suggestion.Title) != "" || strings.TrimSpace(suggestion.Objective) != "" {
				items = append(items, suggestion)
				continue
			}
		}
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			text = strings.TrimSpace(text)
			if text != "" {
				items = append(items, SecurityGraphIntentSuggestion{
					Title:      truncateString(text, 180),
					Objective:  text,
					IntentType: model.IntentBehaviorProbe,
				})
			}
		}
	}
	return items
}

func repairWorkerAgentOutput(raw string) (workerAgentOutput, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return workerAgentOutput{}, fmt.Errorf("worker returned empty output")
	}
	return workerAgentOutput{
		Accepted: true,
		Data: workerAgentData{
			Summary: "Pi worker returned unstructured output; captured as observation-only evidence.",
			Evidence: []workerAgentEvidence{{
				Type:         "worker_observation",
				Title:        "Unstructured Pi worker observation",
				Summary:      "Worker output could not be parsed as structured JSON, so Rabbit preserved it as evidence without creating capabilities or follow-up intents.",
				Raw:          text,
				RelationType: "worker_result",
			}},
		},
	}, nil
}

func validateWorkerAgentOutput(raw string, output workerAgentOutput) error {
	if !output.Accepted {
		return nil
	}
	if len(raw) > maxWorkerOutputTextLength {
		return fmt.Errorf("worker output is too large; return compact facts and store large observations in artifacts")
	}
	if hasDisallowedWorkerOutputField(raw) {
		return fmt.Errorf("worker output contains delivery or external-lookup fields; workers must return only facts, evidence, graph state, and next intent suggestions")
	}
	if len(output.Data.Facts) > maxWorkerFacts ||
		len(output.Data.Evidence) > maxWorkerEvidenceItems ||
		len(output.Data.CapabilityCandidates) > maxWorkerCapabilityCandidates ||
		len(output.Data.NegativeFacts) > maxWorkerNegativeFacts ||
		len(output.Data.UnverifiedRisks) > maxWorkerUnverifiedRisks ||
		len(output.Data.NextIntentSuggestions) > maxWorkerNextIntentSuggestions {
		return fmt.Errorf("worker output exceeds bounded exploration packet limits; return only high-signal incremental facts for the current intent")
	}
	if hasDisallowedWorkerDecisionText(output.Data.Summary) {
		return fmt.Errorf("worker summary crosses phase boundary; return observations, not delivery or brain decisions")
	}
	for i, fact := range output.Data.Facts {
		if hasDisallowedWorkerDecisionText(fact) {
			return fmt.Errorf("worker fact %d crosses phase boundary; facts must be objective observations only", i)
		}
	}
	if len(output.Data.CapabilityCandidates) > 0 && len(output.Data.Evidence) == 0 {
		return fmt.Errorf("worker capability candidates require supporting evidence items")
	}
	for i, item := range output.Data.Evidence {
		if strings.TrimSpace(item.Title) == "" && strings.TrimSpace(item.Summary) == "" && strings.TrimSpace(item.Raw) == "" {
			return fmt.Errorf("worker evidence item %d must include title, summary, or raw content", i)
		}
		if hasDisallowedWorkerDecisionText(item.Title) || hasDisallowedWorkerDecisionText(item.Summary) {
			return fmt.Errorf("worker evidence item %d title/summary crosses phase boundary", i)
		}
	}
	for i, item := range output.Data.CapabilityCandidates {
		capType := normalizeWorkerCapabilityType(firstNonEmpty(item.CapabilityType, item.Name))
		proof := strings.TrimSpace(firstNonEmpty(item.ProofSummary, item.Summary))
		if capType == "" || strings.TrimSpace(item.Target) == "" || proof == "" {
			return fmt.Errorf("worker capability candidate %d must include capability_type, target, and proof_summary", i)
		}
		if hasDisallowedWorkerDecisionText(capType) || hasDisallowedWorkerDecisionText(proof) {
			return fmt.Errorf("worker capability candidate %d crosses phase boundary", i)
		}
	}
	for i, item := range output.Data.NegativeFacts {
		if hasDisallowedWorkerDecisionText(item.Title) || hasDisallowedWorkerDecisionText(item.Summary) {
			return fmt.Errorf("worker negative fact %d crosses phase boundary", i)
		}
	}
	for i, item := range output.Data.UnverifiedRisks {
		if hasDisallowedWorkerDecisionText(item.Title) || hasDisallowedWorkerDecisionText(item.Summary) || hasDisallowedWorkerDecisionText(item.Reason) {
			return fmt.Errorf("worker unverified risk %d crosses phase boundary", i)
		}
	}
	for i, suggestion := range output.Data.NextIntentSuggestions {
		if strings.TrimSpace(suggestion.IntentType) != "" {
			if _, ok := workerSuggestedIntentType(suggestion.IntentType); !ok {
				return fmt.Errorf("worker next intent suggestion %d uses unsupported intent type %q", i, suggestion.IntentType)
			}
		}
		if strings.TrimSpace(suggestion.Title) == "" && strings.TrimSpace(suggestion.Objective) == "" {
			return fmt.Errorf("worker next intent suggestion %d must include title or objective", i)
		}
		if hasDisallowedWorkerDecisionText(suggestion.Title) || hasDisallowedWorkerDecisionText(suggestion.Objective) {
			return fmt.Errorf("worker next intent suggestion %d crosses phase boundary", i)
		}
	}
	return nil
}

func hasDisallowedWorkerDecisionText(value string) bool {
	text := strings.ToLower(strings.TrimSpace(value))
	if text == "" {
		return false
	}
	compact := strings.NewReplacer("_", " ", "-", " ", ".", " ").Replace(text)
	for _, phrase := range []string{
		"cve search",
		"poc search",
		"external poc",
		"exploit db",
		"proofpacket",
		"proof packet",
		"safeprobe",
		"safe probe",
		"repo source",
		"github poc",
		"create finding",
		"confirmed finding",
		"finding confirmed",
		"contract passed",
		"contract failed",
		"report ready",
		"goal complete",
		"goal completed",
		"task complete",
		"task completed",
		"hypothesis validated",
		"hypothesis refuted",
		"validated hypothesis",
		"refuted hypothesis",
	} {
		if strings.Contains(text, phrase) || strings.Contains(compact, phrase) {
			return true
		}
	}
	return false
}

func hasDisallowedWorkerOutputField(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end > start {
		trimmed = trimmed[start : end+1]
	}
	var payload any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return false
	}
	return hasDisallowedWorkerOutputKey(payload)
}

func hasDisallowedWorkerOutputKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.TrimSpace(key))
			switch normalized {
			case "finding", "findings", "report", "reports", "contract", "contracts", "contract_check", "contract_checks",
				"cve", "cves", "poc", "pocs", "complete", "completion", "goal_complete", "goal_completed",
				"hypothesis_status", "validated_hypothesis", "refuted_hypothesis":
				return true
			}
			if strings.Contains(normalized, "proof") && strings.Contains(normalized, "packet") {
				return true
			}
			if strings.Contains(normalized, "safe") && strings.Contains(normalized, "probe") {
				return true
			}
			if hasDisallowedWorkerOutputKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if hasDisallowedWorkerOutputKey(child) {
				return true
			}
		}
	}
	return false
}

func workerCapabilityStrength(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case model.StrengthSuspected:
		return model.StrengthSuspected
	case model.StrengthObserved, model.StrengthVerified:
		// External workers report candidate state. Rabbit's own hypothesis
		// resolution path is responsible for upgrading a capability to verified.
		return model.StrengthObserved
	default:
		return model.StrengthObserved
	}
}

func normalizeWorkerCapabilityType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("-", "_", " ", "_").Replace(normalized)
	switch {
	case normalized == model.CapSQLInjection,
		strings.Contains(normalized, "sql_injection"),
		strings.Contains(normalized, "sqli"):
		return model.CapSQLInjection
	case normalized == "public_git_metadata_access",
		normalized == "git_metadata_access",
		strings.Contains(normalized, "source_code"):
		return model.CapSourceCodeRead
	default:
		return strings.TrimSpace(value)
	}
}

func (o *AgentOrchestrator) workerCapabilityCandidateIsVerified(ctx context.Context, taskID uint, intentID uint, capType string, output workerAgentOutput, evidenceItems []model.AIEvidence) bool {
	_ = ctx
	_ = taskID
	_ = intentID
	if len(evidenceItems) == 0 || strings.TrimSpace(capType) == "" {
		return false
	}
	text := strings.ToLower(workerCapabilityEvidenceText(output, evidenceItems))
	if containsSQLiProofSignal(text) {
		return true
	}
	for _, item := range evidenceItems {
		relation := strings.ToLower(strings.TrimSpace(item.RelationType))
		if relation == "validation" || relation == "observed_signal" || relation == "strong_static_proof" || relation == "reproduction_step" {
			return true
		}
	}
	for _, item := range output.Data.Evidence {
		relation := strings.ToLower(strings.TrimSpace(item.RelationType))
		if relation == "validation" || relation == "observed_signal" || relation == "strong_static_proof" || relation == "reproduction_step" {
			return true
		}
	}
	return false
}

func workerCapabilityEvidenceText(output workerAgentOutput, evidenceItems []model.AIEvidence) string {
	parts := []string{output.Data.Summary}
	parts = append(parts, output.Data.Facts...)
	for _, item := range output.Data.Evidence {
		parts = append(parts, item.Title, item.Summary, item.Raw, item.Target)
	}
	for _, item := range evidenceItems {
		parts = append(parts, item.Title, item.Summary, item.Target, string(item.RequestSnapshot), string(item.ResponseSnapshot))
	}
	return strings.Join(parts, "\n")
}

func (o *AgentOrchestrator) workerDeliveryProofSummary(ctx context.Context, taskID uint, intentID uint, capType string, evidenceIDs []uint, fallback string) string {
	var task model.AISecurityTask
	var intent model.AIIntent
	if err := o.db.WithContext(ctx).First(&task, taskID).Error; err != nil {
		return fallback
	}
	if err := o.db.WithContext(ctx).First(&intent, intentID).Error; err != nil {
		return fallback
	}
	proof := o.deliveryProofSummaryForCapability(ctx, task, intent, capType, evidenceIDs)
	if strings.TrimSpace(proof) == "" {
		return fallback
	}
	return proof
}

func workerSuggestedIntentType(value string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return model.IntentBehaviorProbe, true
	}
	if _, ok := runtimeIntentTypes[normalized]; ok {
		return normalized, true
	}
	return "", false
}

func workerHypothesisTypeForIntent(intentType string) string {
	switch strings.ToLower(strings.TrimSpace(intentType)) {
	case model.IntentBootstrapGraph, model.IntentExploreEntrypoint, model.IntentInspectDataflow, model.IntentInspectGuard,
		model.IntentValidateHypothesis, model.IntentRunTool, model.IntentResolveUnknown, model.IntentCompareBehavior,
		model.IntentExpandAttackSurface, model.IntentPromoteCapability:
		return model.HypothesisTypeInfoDisclosureCandidate
	case model.IntentAuthProbe:
		return model.HypothesisTypeAuthzBypassCandidate
	case model.IntentIDORProbe, model.IntentObjectOwnerCheck, model.IntentEntryToAuthzTrace:
		return model.HypothesisTypeIDORCandidate
	case model.IntentMassAssignmentProbe, model.IntentMassAssignTrace:
		return model.HypothesisTypeMassAssignmentCandidate
	case model.IntentSQLiProbe, model.IntentSQLConstructTrace:
		return model.HypothesisTypeInjectionCandidate
	case model.IntentPathTraversalProbe, model.IntentFilePathControl:
		return model.HypothesisTypeFileReadCandidate
	case model.IntentSSRFProbe, model.IntentSSRFURLControl:
		return model.HypothesisTypeSSRFCandidate
	case model.IntentUploadProbe, model.IntentUploadToExec:
		return model.HypothesisTypeUploadBypassCandidate
	case model.IntentXSSProbe:
		return model.HypothesisTypeXSSCandidate
	case model.IntentSSTIProbe, model.IntentTemplateRenderTrace:
		return model.HypothesisTypeSSTICandidate
	case model.IntentCommandInjProbe:
		return model.HypothesisTypeCommandExecutionCandidate
	case model.IntentSecretVerify, model.IntentSecretToAPI:
		return model.HypothesisTypeSecretReuseCandidate
	case model.IntentBusinessLogicProbe, model.IntentBusinessStateTrace:
		return model.HypothesisTypeBusinessLogicCandidate
	case model.IntentCodeSliceAnalysis, model.IntentDataflowTrace, model.IntentRouteToSinkTrace:
		return model.HypothesisTypeInfoDisclosureCandidate
	default:
		return model.HypothesisTypeInfoDisclosureCandidate
	}
}

func workerExpectedCapabilityForIntent(intentType string) string {
	switch strings.ToLower(strings.TrimSpace(intentType)) {
	case model.IntentBootstrapGraph, model.IntentExploreEntrypoint, model.IntentInspectDataflow, model.IntentInspectGuard,
		model.IntentValidateHypothesis, model.IntentRunTool, model.IntentResolveUnknown, model.IntentCompareBehavior,
		model.IntentExpandAttackSurface:
		return ""
	case model.IntentPromoteCapability:
		return model.CapInternalServiceAccess
	case model.IntentAuthProbe:
		return model.CapAdminAccess
	case model.IntentIDORProbe, model.IntentObjectOwnerCheck, model.IntentEntryToAuthzTrace:
		return model.CapCrossUserObjectAccess
	case model.IntentMassAssignmentProbe, model.IntentMassAssignTrace:
		return model.CapBusinessValueTamper
	case model.IntentSQLiProbe, model.IntentSQLConstructTrace:
		return model.CapSQLInjection
	case model.IntentPathTraversalProbe, model.IntentFilePathControl:
		return model.CapFileRead
	case model.IntentSSRFProbe, model.IntentSSRFURLControl:
		return model.CapSSRFInternalAccess
	case model.IntentUploadProbe:
		return model.CapUploadWrite
	case model.IntentUploadToExec:
		return model.CapCommandExecution
	case model.IntentXSSProbe, model.IntentSSTIProbe, model.IntentTemplateRenderTrace:
		return model.CapBrowserExecution
	case model.IntentCommandInjProbe:
		return model.CapCommandExecution
	case model.IntentSecretVerify, model.IntentSecretToAPI:
		return model.CapSecretDiscovered
	case model.IntentBusinessLogicProbe, model.IntentBusinessStateTrace:
		return model.CapUnauthorizedState
	case model.IntentCapabilityExpand, model.IntentGoalAttempt:
		return model.CapInternalServiceAccess
	default:
		return model.CapInternalServiceAccess
	}
}

func stableTextKey(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])[:32]
}

func truncateString(value string, limit int) string {
	if limit <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
