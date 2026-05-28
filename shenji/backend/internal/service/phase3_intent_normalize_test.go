package service

import (
	"strings"
	"testing"

	"shenji/backend/internal/config"
	"shenji/backend/internal/model"
)

func TestPhase3_TaskServiceInitialIntent_Normalized(t *testing.T) {
	// Simulate what task_service does: create an intent with legacy type
	// and verify normalizeIntentBeforeCreate converts it at phase >= 3
	intent := model.AIIntent{
		IntentType: "code_trace",
		Title:      "启动授权安全验证",
		Objective:  "Collect first-layer facts",
	}
	normalized, orig, hint := normalizeIntentBeforeCreate(&intent, 3)
	if !normalized {
		t.Fatal("expected normalization at phase 3")
	}
	if orig != "code_trace" {
		t.Errorf("expected original=code_trace, got %s", orig)
	}
	if hint != "code_trace" {
		t.Errorf("expected hint=code_trace, got %s", hint)
	}
	if intent.IntentType != model.IntentClueChainExtend {
		t.Errorf("expected IntentType=%s, got %s", model.IntentClueChainExtend, intent.IntentType)
	}
}

func TestPhase3_TaskServiceInitialIntent_NotNormalized_Phase0(t *testing.T) {
	intent := model.AIIntent{IntentType: "code_trace"}
	normalized, _, _ := normalizeIntentBeforeCreate(&intent, 0)
	if normalized {
		t.Error("should not normalize at phase 0")
	}
	if intent.IntentType != "code_trace" {
		t.Error("IntentType should remain unchanged at phase 0")
	}
}

func TestPhase3_HypothesisLifecycle_IntentNormalized(t *testing.T) {
	// hypothesis_lifecycle creates intents with types like "validate" or legacy types
	intent := model.AIIntent{
		IntentType: "validate",
		Title:      "Validate hypothesis",
	}
	normalized, _, hint := normalizeIntentBeforeCreate(&intent, 3)
	if !normalized {
		t.Fatal("expected normalization")
	}
	if intent.IntentType != model.IntentClueValidate {
		t.Errorf("expected %s, got %s", model.IntentClueValidate, intent.IntentType)
	}
	if hint != "validate" {
		t.Errorf("expected hint=validate, got %s", hint)
	}
}

func TestPhase3_FileIntent_Normalized(t *testing.T) {
	// agent_orchestrator creates file intents with type from initialIntentType
	intent := model.AIIntent{
		IntentType: "code_trace",
		Title:      "Analyze file security.go",
	}
	normalizeIntentBeforeCreate(&intent, 3)
	if intent.IntentType != model.IntentClueChainExtend {
		t.Errorf("expected %s, got %s", model.IntentClueChainExtend, intent.IntentType)
	}
}

func TestPhase3_ReconIntent_Normalized(t *testing.T) {
	intent := model.AIIntent{IntentType: "recon", Title: "Recon target"}
	normalizeIntentBeforeCreate(&intent, 3)
	if intent.IntentType != model.IntentScopeObservation {
		t.Errorf("expected %s, got %s", model.IntentScopeObservation, intent.IntentType)
	}
}

func TestPhase3_ModernIntent_NotChanged(t *testing.T) {
	intent := model.AIIntent{IntentType: model.IntentClueValidate, Title: "Already modern"}
	normalized, _, _ := normalizeIntentBeforeCreate(&intent, 3)
	if normalized {
		t.Error("modern intent should not be normalized")
	}
	if intent.IntentType != model.IntentClueValidate {
		t.Error("modern intent type should remain unchanged")
	}
}

func TestPhase3_LegacyHint_InConstraintsJSON(t *testing.T) {
	intent := model.AIIntent{
		IntentType:      "sql_injection_validation",
		Title:           "Test SQLi",
		ConstraintsJSON: mustJSON(map[string]any{"existing_key": "value"}),
	}
	normalizeIntentBeforeCreate(&intent, 3)

	var constraints map[string]any
	_ = unmarshalJSON(intent.ConstraintsJSON, &constraints)
	if constraints["legacy_hint"] != "sql_injection" {
		t.Errorf("expected legacy_hint=sql_injection, got %v", constraints["legacy_hint"])
	}
	if constraints["existing_key"] != "value" {
		t.Error("existing constraints should be preserved")
	}
}

func TestPhase3_PlannerPrompt_NoVulnTypeWords(t *testing.T) {
	task := model.AISecurityTask{TaskType: "pentest", Objective: "test"}
	ctx := AgentContext{}
	system, user := buildPlannerPromptWithPhase(task, nil, ctx, 3)

	// The prompt contains a prohibition sentence "Never reference vulnerability names (SQLi, XSS, ...)"
	// which is acceptable. We check that vuln-type words don't appear as TASK INSTRUCTIONS
	// (i.e., outside the prohibition rule).
	// Remove the prohibition line before checking
	systemWithoutProhibition := removeProhibitionLine(system)
	combined := strings.ToLower(systemWithoutProhibition + " " + user)

	vulnWords := []string{"sql_injection", "cross_site_scripting", "idor_test", "ssrf_test", "rce_test"}
	for _, word := range vulnWords {
		if strings.Contains(combined, strings.ToLower(word)) {
			t.Errorf("phase 3 planner prompt should not contain vuln-type intent word %q", word)
		}
	}
}

func TestPhase3_SecurityGraphPrompt_NoVulnTypeWords(t *testing.T) {
	task := model.AISecurityTask{Name: "test", TaskType: "code_audit", Objective: "audit"}
	packet := SecurityGraphAuditPacket{}
	system, user := buildSecurityGraphPromptWithPhase(task, packet, 3)

	systemWithoutProhibition := removeProhibitionLine(system)
	combined := strings.ToLower(systemWithoutProhibition + " " + user)

	vulnWords := []string{"sql_injection", "cross_site_scripting", "idor_test", "ssrf_test", "rce_test"}
	for _, word := range vulnWords {
		if strings.Contains(combined, strings.ToLower(word)) {
			t.Errorf("phase 3 graph prompt should not contain vuln-type intent word %q", word)
		}
	}
}

// removeProhibitionLine removes the "Never reference vulnerability names..." line
// from the prompt so we can check the rest for vuln-type words used as task instructions.
func removeProhibitionLine(prompt string) string {
	lines := strings.Split(prompt, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "never reference vulnerability") ||
			strings.Contains(lower, "do not emit fields named vuln_type") {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

func TestPhase3_PlannerPrompt_Phase0_Unchanged(t *testing.T) {
	task := model.AISecurityTask{TaskType: "pentest", Objective: "test"}
	ctx := AgentContext{}
	system, _ := buildPlannerPromptWithPhase(task, nil, ctx, 0)

	// Phase 0 should still have the old prompt style
	if !strings.Contains(system, "coverage-oriented graph reasoner") {
		t.Error("phase 0 should use legacy prompt")
	}
}

func TestPhase3_DeterministicFallback_NoVulnType(t *testing.T) {
	task := model.AISecurityTask{TaskType: "pentest", Objective: "test"}
	plan := deterministicIterationPlanClue(task, nil)

	vulnWords := []string{"sql", "xss", "idor", "ssrf", "rce", "injection", "vulnerability"}
	combined := strings.ToLower(plan.ThoughtSummary + " " + plan.PlannedAction + " " + plan.ModelName)
	for _, word := range vulnWords {
		if strings.Contains(combined, word) {
			t.Errorf("clue-driven fallback should not contain vuln word %q in: %s", word, combined)
		}
	}
}

func TestPhase3_AllIntentTypes_InModernSet(t *testing.T) {
	// Verify that all known legacy types normalize to modern set
	legacyTypes := []string{
		"sql_injection_validation", "idor_test", "xss_test", "ssrf_test",
		"rce_test", "lfi_test", "xxe_test", "recon", "fingerprint",
		"code_trace", "dataflow_trace", "inspect_auth_boundary",
		"inspect_owner_check", "validate_candidate_path",
		"collect_evidence", "validate",
	}
	for _, legacy := range legacyTypes {
		intent := model.AIIntent{IntentType: legacy, Title: "test"}
		normalizeIntentBeforeCreate(&intent, 3)
		if !model.IsModernIntentType(intent.IntentType) {
			t.Errorf("legacy type %q normalized to %q which is not in modern set", legacy, intent.IntentType)
		}
	}
}

func TestPhase3_ContractService_WhitelistNote(t *testing.T) {
	// contract_service creates intents with type "collect_evidence" which
	// normalizes to "clue_collect". This test documents that Phase 4 will
	// remove this path entirely. For now, if it were to run at phase >= 3,
	// it would still normalize correctly.
	intent := model.AIIntent{IntentType: "collect_evidence", Title: "补齐证据"}
	normalizeIntentBeforeCreate(&intent, 3)
	if intent.IntentType != model.IntentClueCollect {
		t.Errorf("contract intent should normalize to %s, got %s", model.IntentClueCollect, intent.IntentType)
	}
}

func TestPhase3_GlobalIntentTypeAssertion(t *testing.T) {
	db := newRegressionTestDB(t)
	_ = db

	// Create a task (this creates initial intent)
	// We can't fully run Create without workspace, but we can verify
	// normalizeIntentBeforeCreate works on all known initial intent types
	for _, taskType := range []string{"code_audit", "pentest"} {
		intentType := initialIntentType(taskType)
		intent := model.AIIntent{IntentType: intentType, Title: "test"}
		normalizeIntentBeforeCreate(&intent, 3)
		if !model.IsModernIntentType(intent.IntentType) {
			t.Errorf("task type %s initial intent %q → %q not in modern set",
				taskType, intentType, intent.IntentType)
		}
	}
}

func testConfigWithPhase(phase int) config.Config {
	cfg := config.Load()
	cfg.ClueDrivenPhase = phase
	return cfg
}
