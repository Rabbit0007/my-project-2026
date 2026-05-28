package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"shenji/backend/internal/model"
	"shenji/backend/internal/storage"
	"shenji/backend/internal/tools"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type fixtureE2ECase struct {
	Name                 string
	Dir                  string
	ExpectedCapability   string
	ExpectedSummaryToken string
}

type fixtureGroundTruth struct {
	ExpectedCapability struct {
		Summary        string `json:"summary"`
		Classification struct {
			VulnerabilityType string `json:"vulnerability_type"`
			CWE               string `json:"cwe"`
		} `json:"classification"`
	} `json:"expected_capability"`
	ExpectedGraph struct {
		EntrypointOrExposure struct {
			File  string `json:"file"`
			Match string `json:"match"`
		} `json:"entrypoint_or_exposure"`
		ImpactSinkOrSecurityEffect struct {
			File  string `json:"file"`
			Match string `json:"match"`
		} `json:"impact_sink_or_security_effect"`
		RequiredEvidenceRelations []string `json:"required_evidence_relations"`
	} `json:"expected_graph"`
}

type fixtureCodeHit struct {
	File    string
	Line    int
	Kind    string
	Snippet string
}

func TestGraphSearchFixtureRawQueryControlProducesVerifiedCapability(t *testing.T) {
	runGraphSearchFixtureE2E(t, fixtureE2ECase{
		Name:                 "raw-query-control",
		Dir:                  "raw-query-control",
		ExpectedCapability:   model.CapSQLInjection,
		ExpectedSummaryToken: "raw query",
	})
}

func TestGraphSearchFixtureFilePathControlProducesVerifiedCapability(t *testing.T) {
	runGraphSearchFixtureE2E(t, fixtureE2ECase{
		Name:                 "file-path-control",
		Dir:                  "file-path-control",
		ExpectedCapability:   model.CapFileWrite,
		ExpectedSummaryToken: "file write path",
	})
}

func TestGraphSearchFixtureObjectAccessControlProducesVerifiedCapability(t *testing.T) {
	runGraphSearchFixtureE2E(t, fixtureE2ECase{
		Name:                 "object-access-control",
		Dir:                  "object-access-control",
		ExpectedCapability:   model.CapCrossUserObjectAccess,
		ExpectedSummaryToken: "object id",
	})
}

func runGraphSearchFixtureE2E(t *testing.T, fx fixtureE2ECase) {
	t.Helper()
	t.Setenv("GRAPH_DELTA_STRICT_MODE", "true")
	ctx := context.Background()
	db := newRegressionTestDB(t)
	store, err := storage.NewLocalStore(t.TempDir(), "")
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}
	blackboard := NewBlackboardService(db)
	intents := NewIntentService(db)
	evidenceSvc := NewEvidenceService(db, store)
	findings := NewFindingService(db)
	contracts := NewContractService(db, blackboard, nil)
	loop := NewCairnLoop(db, blackboard, intents, nil, findings, contracts, nil, nil, nil)

	root := fixtureRoot(t, fx.Dir)
	groundTruth := readFixtureGroundTruth(t, root)
	taskID := uint(9000 + len(fx.Name))
	task := model.AISecurityTask{
		ID:          taskID,
		WorkspaceID: 1,
		Name:        "fixture " + fx.Name,
		TaskType:    model.TaskTypeCodeAudit,
		Status:      model.TaskStatusRunning,
		Objective:   "Find evidence-backed security impact paths in the uploaded project.",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}

	bootstrapDelta := GraphDelta{
		NewFacts: []GraphFact{{
			NodeType: model.NodeOrigin,
			Title:    "Fixture workspace loaded",
			Summary:  "Workspace root contains a small source project for graph search.",
		}},
		NewIntents: []IntentSuggestion{{
			IntentType:      model.IntentExploreEntrypoint,
			Objective:       "Explore entrypoints and security-relevant effects in the uploaded source workspace.",
			AllowedTools:    []string{"code_search"},
			SuccessCriteria: "Evidence-backed entrypoint or a NegativeFact explaining why none exists.",
			Priority:        90,
		}},
		Diagnostics: []string{"bootstrap created initial graph state"},
	}
	if fx.Name == "raw-query-control" {
		bootstrapDelta.UpdatedCoverage = []CoverageUpdate{
			{SurfaceType: "query_flow", Entrypoint: "GET /user/search", Status: model.CoverageStatusUnexplored, Priority: model.CoveragePriorityHigh, Reason: "fixture route accepts query sorting input"},
			{SurfaceType: "admin_flow", Entrypoint: "GET /admin/export", Status: model.CoverageStatusUnexplored, Priority: model.CoveragePriorityHigh, Reason: "fixture route remains unresolved after first capability"},
		}
	}
	assertStrictGraphDeltaPacket(t, bootstrapDelta)
	if err := loop.ApplyGraphDelta(ctx, taskID, bootstrapDelta); err != nil {
		t.Fatalf("apply bootstrap delta: %v", err)
	}
	assertNoFindings(t, db, taskID, "bootstrap must not create finding")
	loop.EmitGraphSearchDiagnostic(ctx, GraphSearchLoopDiagnostic{TaskID: taskID, Iteration: 1, Phase: "bootstrap", GoalStatus: "not_satisfied", GraphDeltaSummary: SummarizeGraphDelta(bootstrapDelta)})

	summary := loop.BuildGraphSummary(ctx, task, 1, 20)
	if len(summary.ConfirmedFacts) == 0 || len(summary.OpenIntents) == 0 {
		t.Fatalf("expected non-empty GraphSummary after bootstrap: %+v", summary)
	}
	loop.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{
		IntentType:      model.IntentInspectDataflow,
		Objective:       "Inspect whether externally controlled values reach security-sensitive effects and whether controls are present.",
		AllowedTools:    []string{"code_search", "code_slice"},
		SuccessCriteria: "GraphDelta with evidence relations covering exposure, effect, reachability, controls, validation, and recheck path.",
		Priority:        95,
	})
	intent, err := intents.NextPending(ctx, taskID)
	if err != nil {
		t.Fatalf("select next intent: %v", err)
	}
	if intent == nil {
		t.Fatalf("expected generic intent")
	}
	if isLegacyVulnIntent(intent.IntentType) {
		t.Fatalf("main fixture intent must be generic, got %s", intent.IntentType)
	}
	if intent.IntentType != model.IntentExploreEntrypoint && intent.IntentType != model.IntentInspectDataflow {
		t.Fatalf("expected generic fixture driver intent, got %s", intent.IntentType)
	}

	graphDelta, toolsCalled, gate := runFixtureExploreWorker(t, ctx, db, store, evidenceSvc, loop, task, *intent, root, fx)
	assertStrictGraphDeltaPacket(t, graphDelta)
	if err := loop.ApplyGraphDelta(ctx, taskID, graphDelta); err != nil {
		t.Fatalf("apply explore graph delta: %v", err)
	}
	loop.EmitGraphSearchDiagnostic(ctx, GraphSearchLoopDiagnostic{
		TaskID:              taskID,
		Iteration:           2,
		Phase:               "explore",
		GoalStatus:          "partially_satisfied",
		SelectedIntent:      &GraphIntentSummary{ID: intent.ID, Kind: intent.IntentType, Goal: intent.Objective, Reason: intent.CreatedReason, Priority: intent.PriorityScore, Status: intent.Status},
		ToolsCalled:         toolsCalled,
		GraphDeltaSummary:   SummarizeGraphDelta(graphDelta),
		PromotionGateResult: &gate,
	})

	var candidates []model.AICapability
	if err := db.Where("task_id = ? AND capability_type = ?", taskID, fx.ExpectedCapability).Find(&candidates).Error; err != nil {
		t.Fatalf("load capability candidates: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatalf("expected capability candidate for %s", fx.ExpectedCapability)
	}
	preGate := loop.EvaluateCapabilityPromotionGate(ctx, candidates[0])
	if !preGate.Allowed {
		t.Fatalf("expected candidate to pass structured gate before verification, missing=%v relations=%v", preGate.Missing, preGate.Relations)
	}
	if err := loop.VerifyCapabilityCandidatesFromEvidence(ctx, taskID); err != nil {
		t.Fatalf("verify candidate capability: %v", err)
	}
	var verified model.AICapability
	if err := db.Where("task_id = ? AND capability_type = ? AND strength = ?", taskID, fx.ExpectedCapability, model.StrengthVerified).First(&verified).Error; err != nil {
		t.Fatalf("expected verified capability: %v", err)
	}
	gate = loop.EvaluateCapabilityPromotionGate(ctx, verified)
	if !gate.Allowed {
		t.Fatalf("expected verified capability gate allowed, missing=%v relations=%v", gate.Missing, gate.Relations)
	}
	if fx.Name == "raw-query-control" {
		coverage := loop.BuildCoverageState(ctx, task, 3)
		if coverage.UnresolvedHighPrioritySurfaces != 1 {
			t.Fatalf("expected raw-query fixture to keep one high-priority surface unresolved after first capability, got %+v", coverage)
		}
		if loop.ShouldFinalize(ctx, task, 6, 20, 0) {
			t.Fatal("raw-query fixture must not finalize after single capability while admin export surface remains unresolved")
		}
		loop.CreateIntentFromSuggestion(ctx, taskID, IntentSuggestion{IntentType: model.IntentInspectAuthBoundary, Objective: "Inspect GET /admin/export authorization boundary after resolving GET /user/search.", Priority: 80})
		next, err := intents.NextPending(ctx, taskID)
		if err != nil {
			t.Fatalf("select continued coverage intent: %v", err)
		}
		if next == nil || isLegacyVulnIntent(next.IntentType) {
			t.Fatalf("expected generic continued coverage intent, got %+v", next)
		}
	}
	assertNoFindings(t, db, taskID, "finding must not exist before PromoteCapabilitiesToFindings")
	if err := loop.PromoteCapabilitiesToFindings(ctx, task); err != nil {
		t.Fatalf("promote verified capability: %v", err)
	}
	var finding model.AIFinding
	if err := db.Where("task_id = ? AND vulnerability_type = ?", taskID, fx.ExpectedCapability).First(&finding).Error; err != nil {
		t.Fatalf("expected finding promoted from verified capability: %v", err)
	}
	if finding.ValidationStatus != model.ValidationDynamicallyValidated {
		t.Fatalf("expected dynamically validated finding, got %s", finding.ValidationStatus)
	}

	assertFixtureEvidenceRelations(t, db, taskID, groundTruth.ExpectedGraph.RequiredEvidenceRelations)
	assertFixtureEvidenceUsesRealContent(t, ctx, db, store, taskID, groundTruth)
	assertToolRunsCalled(t, db, taskID, "code_search", "code_slice")
	assertGraphSearchDiagnosticExists(t, db, taskID, "bootstrap")
	assertGraphSearchDiagnosticExists(t, db, taskID, "explore")
}

func runFixtureExploreWorker(t *testing.T, ctx context.Context, db *gorm.DB, store storage.ArtifactStore, evidenceSvc *EvidenceService, loop *CairnLoop, task model.AISecurityTask, intent model.AIIntent, root string, fx fixtureE2ECase) (GraphDelta, []string, CapabilityPromotionGate) {
	t.Helper()
	hits := fixtureCodeSearch(t, root)
	if len(hits) == 0 {
		return GraphDelta{IntentID: intent.ID, Errors: []string{"code_search found no security-relevant source or effect"}}, []string{"code_search"}, CapabilityPromotionGate{Allowed: false, Missing: []string{"code_search_hits"}}
	}
	toolRunSearch := createFixtureToolRun(t, ctx, db, store, task.ID, &intent.ID, "code_search", root, fixtureHitsJSON(t, hits))
	evidenceItems := []model.AIEvidence{}
	selected := selectFixtureEvidenceHits(hits)
	if len(selected) == 0 {
		return GraphDelta{IntentID: intent.ID, Errors: []string{"no selected evidence hits"}}, []string{"code_search"}, CapabilityPromotionGate{Allowed: false, Missing: []string{"selected_hits"}}
	}
	for relation, hit := range selected {
		slice := fixtureCodeSlice(t, root, hit.File, hit.Line, 3)
		toolRunSlice := createFixtureToolRun(t, ctx, db, store, task.ID, &intent.ID, "code_slice", root, slice)
		item, err := evidenceSvc.CreateFromDraft(ctx, task.ID, &toolRunSlice.ID, tools.EvidenceDraft{
			Type:         "code_snippet",
			Title:        relation + " evidence",
			Summary:      fmt.Sprintf("%s:%d shows %s", hit.File, hit.Line, relation),
			Raw:          slice,
			Target:       hit.Snippet,
			FilePath:     hit.File,
			LineStart:    &hit.Line,
			LineEnd:      &hit.Line,
			RelationType: relation,
			Redacted:     true,
		})
		if err != nil {
			t.Fatalf("create evidence %s: %v", relation, err)
		}
		evidenceItems = append(evidenceItems, item)
		_ = toolRunSearch
	}
	capType := inferCapabilityTypeFromEvidence(selected)
	if capType != fx.ExpectedCapability {
		t.Fatalf("fixture worker inferred unexpected capability type: got=%s want=%s selected=%+v", capType, fx.ExpectedCapability, selected)
	}
	evidenceIDs := evidenceIDsFromItems(evidenceItems)
	proof := fixtureProofSummary(fx, selected, evidenceIDs)
	delta := GraphDelta{
		IntentID:         intent.ID,
		NewEvidence:      evidenceItems,
		NewFacts:         fixtureFactsFromEvidence(selected),
		NewIntents:       []IntentSuggestion{{IntentType: model.IntentValidateHypothesis, Objective: "Re-check the structured evidence chain and promotion gate before delivery.", Priority: 70}},
		Diagnostics:      []string{"fixture worker produced graph_delta from real code_search/code_slice outputs"},
		CompletedIntents: []uint{intent.ID},
		NewCapabilityCandidates: []CapabilityDraft{{
			CapabilityType: capType,
			Target:         fixtureCapabilityTarget(selected),
			Strength:       model.StrengthObserved,
			ProofSummary:   proof,
			EvidenceIDs:    evidenceIDs,
			CanAdvanceGoal: true,
		}},
	}
	if fx.Name == "raw-query-control" {
		delta.UpdatedCoverage = []CoverageUpdate{{SurfaceType: "query_flow", Entrypoint: "GET /user/search", Status: model.CoverageStatusResolvedVerified, Priority: model.CoveragePriorityHigh, Reason: "resolved by evidence-backed raw query capability", EvidenceRefs: evidenceIDs}}
	}
	gate := CapabilityPromotionGate{Allowed: true, EvidenceRefs: evidenceIDs}
	return delta, []string{"code_search", "code_slice"}, gate
}

func fixtureRoot(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve fixture path: runtime caller unavailable")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "vuln-labs", name)
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture %s not found: %v", name, err)
	}
	return root
}

func readFixtureGroundTruth(t *testing.T, root string) fixtureGroundTruth {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "ground_truth.json"))
	if err != nil {
		t.Fatalf("read ground truth: %v", err)
	}
	var gt fixtureGroundTruth
	if err := json.Unmarshal(raw, &gt); err != nil {
		t.Fatalf("unmarshal ground truth: %v", err)
	}
	return gt
}

func fixtureCodeSearch(t *testing.T, root string) []fixtureCodeHit {
	t.Helper()
	hits := []fixtureCodeHit{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !fixtureAuditableFile(path) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(content), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if kind := fixtureLineKind(trimmed); kind != "" {
				hits = append(hits, fixtureCodeHit{File: filepath.ToSlash(rel), Line: i + 1, Kind: kind, Snippet: trimmed})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fixture code search: %v", err)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if fixtureKindPriority(hits[i].Kind) == fixtureKindPriority(hits[j].Kind) {
			if hits[i].File == hits[j].File {
				return hits[i].Line < hits[j].Line
			}
			return hits[i].File < hits[j].File
		}
		return fixtureKindPriority(hits[i].Kind) > fixtureKindPriority(hits[j].Kind)
	})
	return hits
}

func fixtureAuditableFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".java", ".xml":
		return !strings.HasSuffix(path, "ground_truth.json")
	default:
		return false
	}
}

func fixtureLineKind(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "getparameter(") || strings.Contains(lower, "getoriginalfilename()") || strings.Contains(lower, "c.param("):
		return "entrypoint_or_exposure"
	case strings.Contains(line, "${") || strings.Contains(lower, "files.write(") || strings.Contains(lower, "getdocument(id)"):
		return "impact_sink_or_security_effect"
	case strings.Contains(lower, ".search(") || strings.Contains(lower, "fileservice.save") || strings.Contains(lower, "storedocument") || strings.Contains(lower, "store.getdocument"):
		return "reachability_or_trigger_path"
	case strings.Contains(lower, "canonical") || strings.Contains(lower, "normalize") || strings.Contains(lower, "allowlist") || strings.Contains(lower, "ownerid ==") || strings.Contains(lower, "tenantid =="):
		return "guard_present"
	default:
		return ""
	}
}

func fixtureKindPriority(kind string) int {
	switch kind {
	case "entrypoint_or_exposure":
		return 100
	case "impact_sink_or_security_effect":
		return 95
	case "reachability_or_trigger_path":
		return 70
	default:
		return 10
	}
}

func fixtureHitsJSON(t *testing.T, hits []fixtureCodeHit) string {
	t.Helper()
	raw, err := json.MarshalIndent(hits, "", "  ")
	if err != nil {
		t.Fatalf("marshal hits: %v", err)
	}
	return string(raw)
}

func createFixtureToolRun(t *testing.T, ctx context.Context, db *gorm.DB, store storage.ArtifactStore, taskID uint, intentID *uint, toolName string, root string, stdout string) model.AIToolRun {
	t.Helper()
	stdoutRef, _, err := store.PutText(ctx, fmt.Sprintf("task-%d/toolruns/%d-%s-stdout.txt", taskID, time.Now().UnixNano(), toolName), stdout)
	if err != nil {
		t.Fatalf("store tool stdout: %v", err)
	}
	now := time.Now().UTC()
	run := model.AIToolRun{
		TaskID:         taskID,
		IntentID:       intentID,
		RunnerType:     "code_audit",
		ToolName:       toolName,
		InputJSON:      datatypes.JSON([]byte(`{}`)),
		CommandPreview: toolName + " <fixture workspace>",
		WorkspacePath:  root,
		NetworkPolicy:  "none",
		Status:         model.ToolRunStatusSuccess,
		StdoutRef:      stdoutRef,
		StartedAt:      now,
		FinishedAt:     &now,
		CreatedAt:      now,
	}
	if err := db.WithContext(ctx).Create(&run).Error; err != nil {
		t.Fatalf("create tool run %s: %v", toolName, err)
	}
	return run
}

func selectFixtureEvidenceHits(hits []fixtureCodeHit) map[string]fixtureCodeHit {
	selected := map[string]fixtureCodeHit{}
	for _, hit := range hits {
		if hit.Kind == "guard_present" {
			continue
		}
		if _, exists := selected[hit.Kind]; !exists {
			selected[hit.Kind] = hit
		}
	}
	if _, ok := selected["entrypoint_or_exposure"]; ok {
		if _, ok := selected["impact_sink_or_security_effect"]; ok {
			if preferred, ok := preferredFixtureEntrypointForSink(hits, selected["impact_sink_or_security_effect"]); ok {
				selected["entrypoint_or_exposure"] = preferred
			}
			if _, ok := selected["reachability_or_trigger_path"]; !ok {
				selected["reachability_or_trigger_path"] = selected["entrypoint_or_exposure"]
			}
			selected["guard_or_control_analysis"] = fixtureCodeHit{
				File:    selected["impact_sink_or_security_effect"].File,
				Line:    selected["impact_sink_or_security_effect"].Line,
				Kind:    "guard_or_control_analysis",
				Snippet: "Relevant source/effect files contain no canonical path, allowlist, owner, tenant, or role guard before the effect.",
			}
			selected["validation_or_observed_signal"] = fixtureCodeHit{
				File:    selected["impact_sink_or_security_effect"].File,
				Line:    selected["impact_sink_or_security_effect"].Line,
				Kind:    "validation_or_observed_signal",
				Snippet: selected["entrypoint_or_exposure"].Snippet + " -> " + selected["impact_sink_or_security_effect"].Snippet,
			}
			selected["reproduction_or_recheck_path"] = fixtureCodeHit{
				File:    selected["entrypoint_or_exposure"].File,
				Line:    selected["entrypoint_or_exposure"].Line,
				Kind:    "reproduction_or_recheck_path",
				Snippet: "Re-check the entrypoint and sink snippets in the fixture workspace and confirm the same variable/call path remains unguarded.",
			}
		}
	}
	return selected
}

func preferredFixtureEntrypointForSink(hits []fixtureCodeHit, sink fixtureCodeHit) (fixtureCodeHit, bool) {
	sinkText := strings.ToLower(sink.Snippet)
	for _, hit := range hits {
		if hit.Kind != "entrypoint_or_exposure" {
			continue
		}
		entryText := strings.ToLower(hit.Snippet)
		switch {
		case strings.Contains(sinkText, "orderby") || strings.Contains(sinkText, "order by"):
			if strings.Contains(entryText, "orderby") {
				return hit, true
			}
		case strings.Contains(sinkText, "files.write"):
			if strings.Contains(entryText, "getoriginalfilename") {
				return hit, true
			}
		case strings.Contains(sinkText, "getdocument"):
			if strings.Contains(entryText, "c.param") {
				return hit, true
			}
		}
	}
	return fixtureCodeHit{}, false
}

func fixtureCodeSlice(t *testing.T, root string, rel string, line int, radius int) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture slice: %v", err)
	}
	lines := strings.Split(string(content), "\n")
	start := line - radius
	if start < 1 {
		start = 1
	}
	end := line + radius
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		prefix := "   "
		if i == line {
			prefix = ">> "
		}
		b.WriteString(fmt.Sprintf("%s%4d\t%s\n", prefix, i, lines[i-1]))
	}
	return b.String()
}

func inferCapabilityTypeFromEvidence(selected map[string]fixtureCodeHit) string {
	sink := strings.ToLower(selected["impact_sink_or_security_effect"].Snippet)
	entry := strings.ToLower(selected["entrypoint_or_exposure"].Snippet)
	switch {
	case strings.Contains(sink, "${") || strings.Contains(sink, "order by"):
		return model.CapSQLInjection
	case strings.Contains(sink, "files.write") || strings.Contains(entry, "getoriginalfilename"):
		return model.CapFileWrite
	case strings.Contains(sink, "getdocument"):
		return model.CapCrossUserObjectAccess
	default:
		return model.CapInternalServiceAccess
	}
}

func fixtureFactsFromEvidence(selected map[string]fixtureCodeHit) []GraphFact {
	facts := []GraphFact{}
	for relation, hit := range selected {
		nodeType := model.NodeCodeFact
		if relation == "entrypoint_or_exposure" {
			nodeType = model.NodeEntrypoint
		}
		if relation == "impact_sink_or_security_effect" {
			nodeType = model.NodeSink
		}
		if relation == "reachability_or_trigger_path" || relation == "validation_or_observed_signal" {
			nodeType = model.NodeDataflow
		}
		facts = append(facts, GraphFact{NodeType: nodeType, Title: relation + ": " + hit.File, Summary: hit.Snippet})
	}
	return facts
}

func fixtureCapabilityTarget(selected map[string]fixtureCodeHit) string {
	sink := selected["impact_sink_or_security_effect"]
	return fmt.Sprintf("%s:%d %s", sink.File, sink.Line, sink.Snippet)
}

func fixtureProofSummary(fx fixtureE2ECase, selected map[string]fixtureCodeHit, evidenceIDs []uint) string {
	entry := selected["entrypoint_or_exposure"]
	sink := selected["impact_sink_or_security_effect"]
	details := completeDeliveryDetails(fixtureCapabilityTarget(selected), fx.ExpectedCapability, evidenceIDs)
	details["entrypoint"] = fmt.Sprintf("%s:%d", entry.File, entry.Line)
	details["controlled_input"] = entry.Snippet
	details["propagation_path"] = selected["reachability_or_trigger_path"].Snippet
	details["sensitive_sink_or_behavior"] = sink.Snippet
	details["trigger_payload_or_action"] = selected["validation_or_observed_signal"].Snippet
	details["baseline_evidence"] = entry.Snippet
	details["validation_evidence"] = selected["validation_or_observed_signal"].Snippet
	details["observed_result"] = selected["guard_or_control_analysis"].Snippet
	details["request_packet"] = selected["reproduction_or_recheck_path"].Snippet
	raw, _ := json.Marshal(details)
	return string(raw)
}

func assertStrictGraphDeltaPacket(t *testing.T, delta GraphDelta) {
	t.Helper()
	payload := map[string]any{"accepted": true, "graph_delta": delta}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal graph_delta packet: %v", err)
	}
	parsed, err := parseWorkerAgentOutput(string(raw))
	if err != nil {
		t.Fatalf("parse strict graph_delta packet: %v", err)
	}
	if !parsed.HasGraphDelta {
		t.Fatalf("expected graph_delta path to be used")
	}
	if err := validateWorkerAgentOutput(string(raw), parsed); err != nil {
		t.Fatalf("validate strict graph_delta packet: %v", err)
	}
}

func assertFixtureEvidenceRelations(t *testing.T, db *gorm.DB, taskID uint, expected []string) {
	t.Helper()
	var evidence []model.AIEvidence
	if err := db.Where("task_id = ?", taskID).Find(&evidence).Error; err != nil {
		t.Fatalf("load evidence: %v", err)
	}
	seen := map[string]bool{}
	for _, item := range evidence {
		seen[item.RelationType] = true
	}
	for _, relation := range expected {
		if !seen[relation] {
			t.Fatalf("expected evidence relation %s, got %v", relation, seen)
		}
	}
}

func assertFixtureEvidenceUsesRealContent(t *testing.T, ctx context.Context, db *gorm.DB, store storage.ArtifactStore, taskID uint, gt fixtureGroundTruth) {
	t.Helper()
	var evidence []model.AIEvidence
	if err := db.Where("task_id = ?", taskID).Find(&evidence).Error; err != nil {
		t.Fatalf("load evidence: %v", err)
	}
	combined := strings.Builder{}
	for _, item := range evidence {
		raw, _ := store.ReadText(ctx, item.RawRef)
		combined.WriteString(raw)
		combined.WriteString("\n")
	}
	content := combined.String()
	for _, expected := range []string{
		gt.ExpectedGraph.EntrypointOrExposure.Match,
		gt.ExpectedGraph.ImpactSinkOrSecurityEffect.Match,
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected persisted evidence to contain real fixture snippet %q", expected)
		}
	}
}

func assertToolRunsCalled(t *testing.T, db *gorm.DB, taskID uint, names ...string) {
	t.Helper()
	for _, name := range names {
		var count int64
		db.Model(&model.AIToolRun{}).Where("task_id = ? AND tool_name = ? AND status = ?", taskID, name, model.ToolRunStatusSuccess).Count(&count)
		if count == 0 {
			t.Fatalf("expected tool %s to be called", name)
		}
	}
}

func assertGraphSearchDiagnosticExists(t *testing.T, db *gorm.DB, taskID uint, phase string) {
	t.Helper()
	var count int64
	db.Model(&model.AIAuditEvent{}).
		Where("task_id = ? AND event_type = ? AND summary = ?", taskID, "graph_search.loop_diagnostic", phase).
		Count(&count)
	if count == 0 {
		t.Fatalf("expected graph search diagnostic phase %s", phase)
	}
}

func isLegacyVulnIntent(intentType string) bool {
	_, ok := legacyVulnIntentNormalization[intentType]
	return ok
}
