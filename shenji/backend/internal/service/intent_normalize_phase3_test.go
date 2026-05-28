package service

import (
	"strings"
	"testing"

	"shenji/backend/internal/model"
)

func TestNormalizeIntentBeforeCreate_Phase3_NormalizesLegacy(t *testing.T) {
	intent := model.AIIntent{IntentType: "sql_injection_validation"}
	normalized, orig, hint := normalizeIntentBeforeCreate(&intent, 3)
	if !normalized {
		t.Fatal("expected normalization")
	}
	if intent.IntentType != model.IntentClueValidate {
		t.Errorf("IntentType = %q, want %q", intent.IntentType, model.IntentClueValidate)
	}
	if orig != "sql_injection_validation" {
		t.Errorf("orig = %q", orig)
	}
	if hint != "sql_injection" {
		t.Errorf("hint = %q", hint)
	}
	// Check legacy_hint in ConstraintsJSON
	if !strings.Contains(string(intent.ConstraintsJSON), `"legacy_hint"`) {
		t.Error("expected legacy_hint in ConstraintsJSON")
	}
}

func TestNormalizeIntentBeforeCreate_Phase2_NoOp(t *testing.T) {
	intent := model.AIIntent{IntentType: "sql_injection_validation"}
	normalized, _, _ := normalizeIntentBeforeCreate(&intent, 2)
	if normalized {
		t.Error("phase 2 should not normalize")
	}
	if intent.IntentType != "sql_injection_validation" {
		t.Error("IntentType should be unchanged in phase 2")
	}
}

func TestNormalizeIntentBeforeCreate_Phase3_ModernPassthrough(t *testing.T) {
	intent := model.AIIntent{IntentType: model.IntentClueCollect}
	normalized, _, _ := normalizeIntentBeforeCreate(&intent, 3)
	if normalized {
		t.Error("modern intent should not be normalized")
	}
	if intent.IntentType != model.IntentClueCollect {
		t.Error("IntentType should be unchanged for modern type")
	}
}

func TestPlannerPromptPhase3_NoVulnTypeWords(t *testing.T) {
	task := model.AISecurityTask{TaskType: "pentest", Objective: "test"}
	sys, user := buildPlannerPromptWithPhase(task, nil, AgentContext{}, 3)

	// Exclude prohibition lines that legitimately mention vuln names as examples of what NOT to do
	sysFiltered := removeProhibitionLine(sys)
	vulnWords := []string{"sql_injection", "cross_site_scripting", "idor_test", "ssrf_test", "rce_test"}
	combined := strings.ToLower(sysFiltered + user)
	for _, word := range vulnWords {
		if strings.Contains(combined, strings.ToLower(word)) {
			t.Errorf("phase 3 planner prompt contains vuln-type intent word %q", word)
		}
	}
}

func TestSecurityGraphPromptPhase3_NoVulnTypeWords(t *testing.T) {
	task := model.AISecurityTask{Name: "test", TaskType: "code_audit", Objective: "audit"}
	sys, user := buildSecurityGraphPromptWithPhase(task, SecurityGraphAuditPacket{}, 3)

	sysFiltered := removeProhibitionLine(sys)
	vulnWords := []string{"sql_injection", "cross_site_scripting", "idor_test", "ssrf_test", "rce_test"}
	combined := strings.ToLower(sysFiltered + user)
	for _, word := range vulnWords {
		if strings.Contains(combined, strings.ToLower(word)) {
			t.Errorf("phase 3 graph prompt contains vuln-type intent word %q", word)
		}
	}
}

func TestPlannerPromptPhase2_PreservesLegacy(t *testing.T) {
	task := model.AISecurityTask{TaskType: "pentest", Objective: "test"}
	sys, _ := buildPlannerPromptWithPhase(task, nil, AgentContext{}, 2)

	// Phase 2 should still have the old prompt style (contains "inspect_sink_reachability")
	if !strings.Contains(sys, "inspect_sink_reachability") {
		t.Error("phase 2 planner prompt should preserve legacy prompt")
	}
}

func TestDeterministicFallbackClue_NoVulnType(t *testing.T) {
	task := model.AISecurityTask{TaskType: "pentest", Objective: "test"}
	plan := deterministicIterationPlanClue(task, nil)

	combined := strings.ToLower(plan.ThoughtSummary + plan.PlannedAction + plan.ModelName)
	vulnWords := []string{"sqli", "xss", "idor", "ssrf", "rce", "sql_injection", "vulnerability"}
	for _, word := range vulnWords {
		if strings.Contains(combined, word) {
			t.Errorf("clue-driven fallback contains vuln-type word %q", word)
		}
	}
	if plan.ModelName != "clue-driven-fallback" {
		t.Errorf("ModelName = %q, want clue-driven-fallback", plan.ModelName)
	}
}
