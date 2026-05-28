package service

import (
	"encoding/json"
	"strings"

	"shenji/backend/internal/model"
)

// SanitizedOutput is the result of sanitizing LLM output before it enters the graph.
type SanitizedOutput struct {
	// Sanitized fields (safe to use)
	ThoughtSummary string
	PlannedAction  string
	NextIntents    []SecurityGraphIntentSuggestion
	NewClueFacts   []ClueFact
	ClueChainLinks []ClueChainLink
	RefutedClues   []ClueRefutation
	Diagnostics    []string

	// Audit trail
	AuditEvents []SanitizerAuditEvent
}

// SanitizerAuditEvent records a sanitization action for audit logging.
type SanitizerAuditEvent struct {
	EventType string
	Detail    map[string]any
}

// prohibitedVulnFields are field names that must be stripped from LLM output
// before entering the Reason/Explore path.
var prohibitedVulnFields = []string{
	"vuln_type", "vulnerability_type", "cwe", "severity",
	"finding_title", "finding_type", "vulnerability_name",
}

// reportStylePatterns are phrases that indicate report-style output
// which should be demoted to diagnostics only.
var reportStylePatterns = []string{
	"综上所述", "本次任务发现的全部漏洞", "漏洞汇总",
	"executive summary", "findings summary", "vulnerability report",
	"in conclusion", "total vulnerabilities found",
}

// SanitizePlannerOutput sanitizes the parsed planner output, stripping
// prohibited fields and normalizing legacy intents.
// This function is safe to call even when ClueDrivenPhase < 3 (it becomes a no-op).
func SanitizePlannerOutput(parsed plannerOutput, phase int) SanitizedOutput {
	if phase < 3 {
		// Phase < 3: pass through without sanitization
		return SanitizedOutput{
			ThoughtSummary: parsed.ThoughtSummary,
			PlannedAction:  parsed.PlannedAction,
			NextIntents:    normalizeSecurityGraphIntents(parsed.NextIntents),
		}
	}

	output := SanitizedOutput{
		ThoughtSummary: parsed.ThoughtSummary,
		PlannedAction:  parsed.PlannedAction,
	}

	// Rule 3: Demote report-style language in thought/action
	if isReportStyleText(parsed.ThoughtSummary) {
		output.Diagnostics = append(output.Diagnostics, "report-style thought demoted: "+truncateForAudit(parsed.ThoughtSummary, 100))
		output.ThoughtSummary = "Clue-driven exploration step."
		output.AuditEvents = append(output.AuditEvents, SanitizerAuditEvent{
			EventType: "agent.llm_output_sanitized",
			Detail:    map[string]any{"field": "thought_summary", "reason": "report-style"},
		})
	}
	if isReportStyleText(parsed.PlannedAction) {
		output.Diagnostics = append(output.Diagnostics, "report-style action demoted: "+truncateForAudit(parsed.PlannedAction, 100))
		output.PlannedAction = "Execute clue-driven intent."
		output.AuditEvents = append(output.AuditEvents, SanitizerAuditEvent{
			EventType: "agent.llm_output_sanitized",
			Detail:    map[string]any{"field": "planned_action", "reason": "report-style"},
		})
	}

	// Rule 2: Normalize legacy intent types
	for _, raw := range parsed.NextIntents {
		intent := flexToSecurityGraphIntent(raw)
		modern, hint := model.NormalizeIntentType(intent.IntentType)
		if hint != "" {
			output.AuditEvents = append(output.AuditEvents, SanitizerAuditEvent{
				EventType: "agent.legacy_intent_normalized",
				Detail:    map[string]any{"original": intent.IntentType, "modern": modern, "hint": hint},
			})
			intent.IntentType = modern
		}
		output.NextIntents = append(output.NextIntents, intent)
	}

	return output
}

// SanitizeGraphDecisionOutput sanitizes the parsed security graph decision,
// stripping vuln-type fields and normalizing intents.
func SanitizeGraphDecisionOutput(parsed securityGraphDecisionOutput, phase int) (SecurityGraphDecision, []SanitizerAuditEvent) {
	if phase < 3 {
		intents := normalizeSecurityGraphIntents(parsed.NextIntents)
		if len(intents) == 0 {
			intents = normalizeSecurityGraphIntents(parsed.Selected)
		}
		return SecurityGraphDecision{
			Facts:       parsed.Facts,
			NextIntents: intents,
			StopReason:  parsed.StopReason,
		}, nil
	}

	var audits []SanitizerAuditEvent
	decision := SecurityGraphDecision{
		Facts:      parsed.Facts,
		StopReason: parsed.StopReason,
	}

	// Normalize intents
	allRaw := parsed.NextIntents
	if len(allRaw) == 0 {
		allRaw = parsed.Selected
	}
	for _, raw := range allRaw {
		intent := flexToSecurityGraphIntent(raw)
		modern, hint := model.NormalizeIntentType(intent.IntentType)
		if hint != "" {
			audits = append(audits, SanitizerAuditEvent{
				EventType: "agent.legacy_intent_normalized",
				Detail:    map[string]any{"original": intent.IntentType, "modern": modern, "hint": hint},
			})
			intent.IntentType = modern
		}
		decision.NextIntents = append(decision.NextIntents, intent)
	}

	return decision, audits
}

// SanitizeRawJSON strips prohibited vuln-type fields from a raw JSON map.
// Returns the cleaned map and any audit events generated.
func SanitizeRawJSON(raw map[string]any, phase int) (map[string]any, []SanitizerAuditEvent) {
	if phase < 3 || raw == nil {
		return raw, nil
	}
	var audits []SanitizerAuditEvent
	for _, field := range prohibitedVulnFields {
		if val, ok := raw[field]; ok {
			audits = append(audits, SanitizerAuditEvent{
				EventType: "agent.vuln_type_field_ignored",
				Detail:    map[string]any{"field": field, "value_hash": truncateForAudit(jsonString(val), 50)},
			})
			delete(raw, field)
		}
	}
	// Also check nested next_intents for prohibited fields
	if intents, ok := raw["next_intents"].([]any); ok {
		for _, item := range intents {
			if m, ok := item.(map[string]any); ok {
				for _, field := range prohibitedVulnFields {
					if val, ok := m[field]; ok {
						audits = append(audits, SanitizerAuditEvent{
							EventType: "agent.vuln_type_field_ignored",
							Detail:    map[string]any{"field": "next_intents." + field, "value_hash": truncateForAudit(jsonString(val), 50)},
						})
						delete(m, field)
					}
				}
			}
		}
	}
	return raw, audits
}

// CheckMissingClueFields checks if the LLM output is missing expected clue-driven
// fields and returns audit events for tracking.
func CheckMissingClueFields(intents []SecurityGraphIntentSuggestion, phase int) []SanitizerAuditEvent {
	if phase < 3 {
		return nil
	}
	var audits []SanitizerAuditEvent
	for _, intent := range intents {
		missing := []string{}
		if intent.IntentType == "" {
			missing = append(missing, "intent_type")
		}
		if len(intent.SourceNodeIDs) == 0 {
			missing = append(missing, "target_clue_refs")
		}
		if len(missing) > 0 {
			audits = append(audits, SanitizerAuditEvent{
				EventType: "agent.legacy_intent_schema_observed",
				Detail:    map[string]any{"missing": missing, "title": intent.Title},
			})
		}
	}
	return audits
}

func isReportStyleText(text string) bool {
	lower := strings.ToLower(text)
	for _, pattern := range reportStylePatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	// Heuristic: if text contains multiple "finding" references in list form
	if strings.Count(lower, "finding") >= 3 || strings.Count(lower, "漏洞") >= 3 {
		return true
	}
	return false
}

func truncateForAudit(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func jsonString(val any) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func flexToSecurityGraphIntent(raw flexSecurityGraphIntentOutput) SecurityGraphIntentSuggestion {
	return SecurityGraphIntentSuggestion{
		Title:            strings.TrimSpace(raw.Title),
		Objective:        strings.TrimSpace(raw.Objective),
		IntentType:       strings.TrimSpace(raw.IntentType),
		RequiredEvidence: normalizeStringListAny(raw.RequiredEvidence),
		SourceNodeIDs:    normalizeUintListAny(raw.SourceNodeIDs),
		Hypothesis:       strings.TrimSpace(raw.Hypothesis),
		SuccessCriteria:  strings.TrimSpace(raw.SuccessCriteria),
		FailureCriteria:  strings.TrimSpace(raw.FailureCriteria),
		AllowedTools:     normalizeStringListAny(raw.AllowedTools),
		RiskLevel:        strings.TrimSpace(raw.RiskLevel),
		Priority:         normalizeIntAny(raw.Priority),
	}
}
