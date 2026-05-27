package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"shenji/backend/internal/model"
)

func (s *HypothesisLifecycleService) ExpandFromEvidence(ctx context.Context, taskID uint, evidence []model.AIEvidence, budget ExpansionBudget) ([]model.AIHypothesisNode, error) {
	decision := NewExplorationBudgetManager(s.db).AllowIntentGenerationFor(ctx, taskID, budget.MaxGeneratedPerRound, budget.toConfig(), "evidence_expansion")
	if !decision.Allowed {
		appendAuditEvent(ctx, s.db, &taskID, "dynamic_expander.throttled", "exploration-budget-manager", decision.Reason, map[string]any{"evidenceCount": len(evidence), "metrics": decision.Metrics})
		return nil, nil
	}
	drafts := []HypothesisDraft{}
	for _, item := range evidence {
		drafts = append(drafts, hypothesisDraftsFromEvidence(taskID, item)...)
	}
	sortHypothesisDraftsByExpansionValue(drafts)
	created := []model.AIHypothesisNode{}
	for _, draft := range drafts {
		if len(created) >= decision.MaxToGenerate {
			break
		}
		if s.hasActiveHypothesisForDraft(ctx, draft) {
			continue
		}
		h, err := s.FormHypothesis(ctx, draft)
		if err != nil {
			continue
		}
		created = append(created, h)
		_, _ = s.CreateValidationIntent(ctx, h, intentTypeForCapability(h.ExpectedCapability), "evidence_triggered_validation", evidenceHypothesisPriority(h), draft.IntentConstraints)
	}
	if len(created) > 0 {
		appendAuditEvent(ctx, s.db, &taskID, "dynamic_expander.evidence_completed", "dynamic-intent-expander", "Evidence-triggered hypothesis expansion completed.", map[string]any{"generatedHypotheses": len(created), "evidenceCount": len(evidence)})
	}
	return created, nil
}

func (s *HypothesisLifecycleService) hasActiveHypothesisForDraft(ctx context.Context, draft HypothesisDraft) bool {
	var existing model.AIHypothesisNode
	err := s.db.WithContext(ctx).
		Where("task_id = ? AND hypothesis_type = ? AND lower(title) = lower(?) AND target_entity = ? AND status IN ?",
			draft.TaskID, draft.HypothesisType, draft.Title, draft.TargetEntity,
			[]string{model.HypothesisStatusPending, model.HypothesisStatusValidating, model.HypothesisStatusValidated}).
		First(&existing).Error
	return err == nil
}

func sortHypothesisDraftsByExpansionValue(drafts []HypothesisDraft) {
	sort.SliceStable(drafts, func(i, j int) bool {
		left := draftExpectedPriority(drafts[i])
		right := draftExpectedPriority(drafts[j])
		if left == right {
			return drafts[i].Title < drafts[j].Title
		}
		return left > right
	})
}

func draftExpectedPriority(draft HypothesisDraft) float64 {
	if draft.ExpansionScore > 0 {
		return draft.ExpansionScore
	}
	switch draft.ExpectedCapability {
	case model.CapCommandExecution, model.CapAdminAccess:
		return 1.0
	case model.CapCredentialObtained, model.CapSQLInjection, model.CapFileWrite:
		return 0.9
	case model.CapFileRead, model.CapSecretDiscovered, model.CapInternalServiceAccess:
		return 0.82
	case model.CapAuthenticatedSession, model.CapArbitraryObjectAccess:
		return 0.76
	default:
		return 0.5
	}
}

func (s *HypothesisLifecycleService) hasExpansionCapacity(ctx context.Context, taskID uint, budget ExpansionBudget) bool {
	return NewExplorationBudgetManager(s.db).AllowIntentGeneration(ctx, taskID, budget.MaxGeneratedPerRound, budget.toConfig()).Allowed
}

func hypothesisDraftsFromEvidence(taskID uint, item model.AIEvidence) []HypothesisDraft {
	text := strings.ToLower(strings.Join([]string{item.EvidenceType, item.Title, item.Summary, item.FilePath, item.Target, item.RelationType}, "\n"))
	sourceRefs := []string{fmt.Sprintf("evidence:%d", item.ID)}
	target := firstNonEmpty(item.FilePath, item.Target, item.Title)
	drafts := []HypothesisDraft{}
	add := func(hType, title, desc, expected string, confidence string) {
		drafts = append(drafts, HypothesisDraft{
			TaskID:                taskID,
			HypothesisType:        hType,
			Title:                 title,
			Description:           desc,
			ConfidenceState:       confidence,
			SourceObservationRefs: sourceRefs,
			TargetEntity:          target,
			ExpectedCapability:    expected,
		})
	}

	drafts = append(drafts, httpSurfaceHypothesisDrafts(taskID, item, sourceRefs)...)
	if strings.Contains(text, "dynamic_sql") || strings.Contains(text, "sql_template") || strings.Contains(text, "database_query_sink") || strings.Contains(text, "sql injection") {
		add(model.HypothesisTypeInjectionCandidate,
			"Potential SQL injection path requires validation",
			"Evidence indicates user-controlled data may reach dynamic SQL construction or query execution; validate source-to-sink reachability and exploitability before producing a finding.",
			model.CapSQLInjection,
			model.ConfidencePlausible)
	}
	if strings.Contains(text, "dynamic_code_execution") || strings.Contains(text, "command") && strings.Contains(text, "sink") {
		add(model.HypothesisTypeCommandExecutionCandidate,
			"Potential command execution path requires validation",
			"Evidence indicates user-controlled input may reach command execution behavior; validate with safe proof-only evidence before capability acquisition.",
			model.CapCommandExecution,
			model.ConfidencePlausible)
	}
	if strings.Contains(text, "file_read_sink") || strings.Contains(text, "path traversal") || strings.Contains(text, "download") {
		add(model.HypothesisTypeFileReadCandidate,
			"Potential arbitrary file read path requires validation",
			"Evidence suggests a file read or download path may be influenced by input; validate path control and readable target boundaries.",
			model.CapFileRead,
			model.ConfidencePlausible)
	}
	if strings.Contains(text, "file_write_sink") {
		add(model.HypothesisTypeFileWriteCandidate,
			"Potential arbitrary file write path requires validation",
			"Evidence suggests input may influence file write behavior; validate write target control without destructive operations.",
			model.CapFileWrite,
			model.ConfidencePlausible)
	}
	if strings.Contains(text, "file_upload_sink") || strings.Contains(text, "file_upload_source") {
		add(model.HypothesisTypeUploadBypassCandidate,
			"Potential upload bypass path requires validation",
			"Evidence shows upload sources or sinks; validate extension, content, path, and execution constraints before promoting risk.",
			model.CapUploadWrite,
			model.ConfidencePlausible)
	}
	if strings.Contains(text, "outbound_request_sink") || strings.Contains(text, "ssrf") || strings.Contains(text, "url/fetch") || strings.Contains(text, "webhook") {
		add(model.HypothesisTypeSSRFCandidate,
			"Potential SSRF path requires validation",
			"Evidence indicates user-controllable outbound request behavior; validate with authorized safe callbacks or internal-reachability proof.",
			model.CapInternalServiceAccess,
			model.ConfidencePlausible)
	}
	if strings.Contains(text, "xxe_parser_sink") || strings.Contains(text, "xmlinputfactory") || strings.Contains(text, "documentbuilderfactory") {
		add(model.HypothesisTypeXXECandidate,
			"Potential XXE parser path requires validation",
			"Evidence indicates XML parsing behavior that may need entity-handling validation under safe constraints.",
			model.CapFileRead,
			model.ConfidencePlausible)
	}
	if strings.Contains(text, "deserialization_sink") || strings.Contains(text, "unserialize") || strings.Contains(text, "objectinputstream") {
		add(model.HypothesisTypeDeserializationCandidate,
			"Potential unsafe deserialization path requires validation",
			"Evidence indicates deserialization behavior; validate attacker reachability and gadget constraints before treating it as exploitable.",
			model.CapCommandExecution,
			model.ConfidenceSuspected)
	}
	if strings.Contains(text, "idor") || strings.Contains(text, "owner") && strings.Contains(text, "check") {
		add(model.HypothesisTypeIDORCandidate,
			"Potential object authorization boundary requires validation",
			"Evidence indicates object ownership or ID-based access behavior; validate cross-object access with authorized accounts or safe fixtures.",
			model.CapArbitraryObjectAccess,
			model.ConfidencePlausible)
	}
	if strings.Contains(text, "set-cookie") || strings.Contains(text, "jwt") || strings.Contains(text, "session") {
		add(model.HypothesisTypeSessionWeaknessCandidate,
			"Session mechanism may have security-relevant weakness",
			"Evidence reveals session or token handling; validate whether it enables authenticated state expansion or session abuse.",
			model.CapAuthenticatedSession,
			model.ConfidenceSuspected)
	}
	return drafts
}

func httpSurfaceHypothesisDrafts(taskID uint, item model.AIEvidence, sourceRefs []string) []HypothesisDraft {
	if item.Title != "HTTP input surface discovery" && item.EvidenceType != "http_surface" {
		return nil
	}
	raw := strings.TrimSpace(string(item.ResponseSnapshot))
	if raw == "" || raw == "{}" || raw == "null" {
		return nil
	}
	var surface struct {
		BaseURL string `json:"baseUrl"`
	}
	if err := json.Unmarshal([]byte(raw), &surface); err != nil {
		return nil
	}
	baseURL := firstNonEmpty(surface.BaseURL, item.Target)
	candidates := httpSurfaceValidationCandidatesFromJSON(baseURL, raw, validationProbeSQLi)
	if len(candidates) == 0 {
		return nil
	}
	groups := map[string][]httpValidationCandidate{}
	order := []string{}
	for _, candidate := range candidates {
		key := validationCandidateBranchKey(candidate)
		if key == "" {
			continue
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], candidate)
	}
	drafts := make([]HypothesisDraft, 0, len(order))
	for idx, key := range order {
		candidates := groups[key]
		first := candidates[0]
		title := fmt.Sprintf("Input %s on %s requires behavior validation", first.Param, endpointWithoutPayload(first.URL))
		drafts = append(drafts, HypothesisDraft{
			TaskID:                taskID,
			HypothesisType:        model.HypothesisTypeInjectionCandidate,
			Title:                 title,
			Description:           fmt.Sprintf("HTTP surface evidence identified %s parameter %q on %s. Validate this specific input path with authorized non-destructive behavior checks before promoting any capability.", first.Location, first.Param, first.URL),
			ConfidenceState:       model.ConfidencePlausible,
			SourceObservationRefs: sourceRefs,
			TargetEntity:          key,
			ExpectedCapability:    model.CapSQLInjection,
			IntentConstraints: map[string]any{
				"surface_fact_evidence_id": item.ID,
				"validation_candidates":    validationCandidateConstraintList(candidates),
				"branch_key":               key,
				"branch_kind":              "http_input_surface",
			},
			ExpansionScore: 0.89 - float64(idx)*0.001,
		})
	}
	return drafts
}

func validationCandidateBranchKey(candidate httpValidationCandidate) string {
	if strings.TrimSpace(candidate.URL) == "" || strings.TrimSpace(candidate.Param) == "" {
		return ""
	}
	return strings.ToUpper(firstNonEmpty(candidate.Method, "GET")) + "|" + endpointWithoutPayload(candidate.URL) + "|" + strings.ToLower(firstNonEmpty(candidate.Location, "query")) + "|" + candidate.Param
}

func validationCandidateConstraintList(candidates []httpValidationCandidate) []map[string]any {
	items := make([]map[string]any, 0, len(candidates))
	for _, candidate := range candidates {
		items = append(items, map[string]any{
			"url":      candidate.URL,
			"param":    candidate.Param,
			"method":   firstNonEmpty(candidate.Method, "GET"),
			"location": firstNonEmpty(candidate.Location, "query"),
			"payload":  candidate.Payload,
		})
	}
	return items
}

func evidenceHypothesisPriority(h model.AIHypothesisNode) float64 {
	switch h.ExpectedCapability {
	case model.CapCommandExecution, model.CapFileWrite, model.CapAdminAccess:
		return 0.9
	case model.CapSQLInjection, model.CapFileRead, model.CapInternalServiceAccess:
		return 0.84
	case model.CapAuthenticatedSession, model.CapArbitraryObjectAccess:
		return 0.8
	default:
		return 0.72
	}
}
