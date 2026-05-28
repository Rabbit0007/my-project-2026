package service

import (
	"testing"

	"shenji/backend/internal/model"
)

func TestSanitizer_Phase2_Passthrough(t *testing.T) {
	parsed := plannerOutput{
		ThoughtSummary: "found sql injection",
		PlannedAction:  "exploit it",
		NextIntents: []flexSecurityGraphIntentOutput{
			{IntentType: "sql_injection_validation", Title: "test sqli"},
		},
	}
	out := SanitizePlannerOutput(parsed, 2)
	// Phase < 3: no sanitization
	if out.ThoughtSummary != "found sql injection" {
		t.Error("phase 2 should pass through thought")
	}
	if len(out.AuditEvents) != 0 {
		t.Error("phase 2 should not generate audit events")
	}
}

func TestSanitizer_Phase3_NormalizesLegacyIntent(t *testing.T) {
	parsed := plannerOutput{
		ThoughtSummary: "observe endpoint",
		PlannedAction:  "collect clue",
		NextIntents: []flexSecurityGraphIntentOutput{
			{IntentType: "sql_injection_validation", Title: "test param"},
			{IntentType: "idor_test", Title: "check access"},
			{IntentType: "clue_validate", Title: "already modern"},
		},
	}
	out := SanitizePlannerOutput(parsed, 3)

	for _, intent := range out.NextIntents {
		if !model.IsModernIntentType(intent.IntentType) {
			t.Errorf("intent type %q should have been normalized", intent.IntentType)
		}
	}
	// Should have 2 normalization audit events (sql_injection_validation + idor_test)
	normalizeCount := 0
	for _, evt := range out.AuditEvents {
		if evt.EventType == "agent.legacy_intent_normalized" {
			normalizeCount++
		}
	}
	if normalizeCount != 2 {
		t.Errorf("expected 2 legacy_intent_normalized events, got %d", normalizeCount)
	}
}

func TestSanitizer_Phase3_DemotesReportStyleThought(t *testing.T) {
	parsed := plannerOutput{
		ThoughtSummary: "综上所述，本次任务发现的全部漏洞如下：1. SQL注入 2. XSS 3. IDOR",
		PlannedAction:  "collect clue from endpoint",
	}
	out := SanitizePlannerOutput(parsed, 3)

	if out.ThoughtSummary == parsed.ThoughtSummary {
		t.Error("report-style thought should have been demoted")
	}
	found := false
	for _, evt := range out.AuditEvents {
		if evt.EventType == "agent.llm_output_sanitized" {
			found = true
		}
	}
	if !found {
		t.Error("expected llm_output_sanitized audit event")
	}
}

func TestSanitizer_Phase3_PreservesValidClueFields(t *testing.T) {
	parsed := plannerOutput{
		ThoughtSummary: "observed differential response on /api/users",
		PlannedAction:  "extend clue chain with authorization check",
		NextIntents: []flexSecurityGraphIntentOutput{
			{IntentType: "clue_chain_extend", Title: "check auth", Objective: "verify owner check"},
		},
	}
	out := SanitizePlannerOutput(parsed, 3)

	if out.ThoughtSummary != parsed.ThoughtSummary {
		t.Error("valid thought should not be modified")
	}
	if out.PlannedAction != parsed.PlannedAction {
		t.Error("valid action should not be modified")
	}
	if len(out.NextIntents) != 1 {
		t.Fatal("expected 1 intent preserved")
	}
	if out.NextIntents[0].IntentType != model.IntentClueChainExtend {
		t.Errorf("expected clue_chain_extend, got %s", out.NextIntents[0].IntentType)
	}
}

func TestSanitizeRawJSON_StripsVulnTypeFields(t *testing.T) {
	raw := map[string]any{
		"thought_summary": "observe",
		"vuln_type":       "sql_injection",
		"cwe":             "CWE-89",
		"severity":        "high",
		"finding_title":   "SQL Injection in /search",
		"planned_action":  "collect clue",
	}
	cleaned, audits := SanitizeRawJSON(raw, 3)

	for _, field := range []string{"vuln_type", "cwe", "severity", "finding_title"} {
		if _, ok := cleaned[field]; ok {
			t.Errorf("field %q should have been stripped", field)
		}
	}
	// Valid fields preserved
	if cleaned["thought_summary"] != "observe" {
		t.Error("thought_summary should be preserved")
	}
	if cleaned["planned_action"] != "collect clue" {
		t.Error("planned_action should be preserved")
	}
	if len(audits) != 4 {
		t.Errorf("expected 4 vuln_type_field_ignored events, got %d", len(audits))
	}
}

func TestSanitizeRawJSON_Phase2_NoOp(t *testing.T) {
	raw := map[string]any{"vuln_type": "xss", "thought": "ok"}
	cleaned, audits := SanitizeRawJSON(raw, 2)
	if _, ok := cleaned["vuln_type"]; !ok {
		t.Error("phase 2 should not strip fields")
	}
	if len(audits) != 0 {
		t.Error("phase 2 should not generate audits")
	}
}

func TestSanitizer_DoesNotDropValidClueFacts(t *testing.T) {
	// Ensure sanitizer preserves new_clue_facts in raw JSON
	raw := map[string]any{
		"new_clue_facts": []any{
			map[string]any{"node_kind": "clue_observation", "title": "response diff", "roles": []any{"verification_or_observation"}},
		},
		"vuln_type": "should_be_stripped",
	}
	cleaned, audits := SanitizeRawJSON(raw, 3)
	if _, ok := cleaned["new_clue_facts"]; !ok {
		t.Error("new_clue_facts should NOT be stripped by sanitizer")
	}
	if _, ok := cleaned["vuln_type"]; ok {
		t.Error("vuln_type should be stripped")
	}
	if len(audits) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(audits))
	}
}

func TestCheckMissingClueFields_Phase3(t *testing.T) {
	intents := []SecurityGraphIntentSuggestion{
		{IntentType: "clue_validate", Title: "test", SourceNodeIDs: []uint{1}},
		{IntentType: "", Title: "missing type"},
		{IntentType: "clue_collect", Title: "no refs"},
	}
	audits := CheckMissingClueFields(intents, 3)
	if len(audits) != 2 {
		t.Errorf("expected 2 missing-field audit events, got %d", len(audits))
	}
}

func TestCheckMissingClueFields_Phase2_NoOp(t *testing.T) {
	intents := []SecurityGraphIntentSuggestion{{IntentType: "", Title: "x"}}
	audits := CheckMissingClueFields(intents, 2)
	if len(audits) != 0 {
		t.Error("phase 2 should not check missing fields")
	}
}

func TestSanitizeGraphDecision_NormalizesIntents(t *testing.T) {
	parsed := securityGraphDecisionOutput{
		Facts: []SecurityGraphFactSuggestion{{NodeType: "clue_observation", Title: "obs", Summary: "s"}},
		NextIntents: []flexSecurityGraphIntentOutput{
			{IntentType: "xss_test", Title: "test xss"},
			{IntentType: "clue_collect", Title: "collect"},
		},
	}
	decision, audits := SanitizeGraphDecisionOutput(parsed, 3)
	for _, intent := range decision.NextIntents {
		if !model.IsModernIntentType(intent.IntentType) {
			t.Errorf("intent %q not normalized", intent.IntentType)
		}
	}
	if len(audits) != 1 {
		t.Errorf("expected 1 normalize audit, got %d", len(audits))
	}
}
