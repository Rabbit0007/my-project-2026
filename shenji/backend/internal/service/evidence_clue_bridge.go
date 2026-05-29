package service

import (
	"context"
	"fmt"
	"strings"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

// EvidenceClueBridge bridges Evidence items to clue_observation nodes in the
// blackboard. This is Phase 5-C: when ToolRun succeeds and Evidence is produced,
// automatically create clue_observation nodes so the ClueChain can form without
// requiring the Pi Worker to return structured new_clue_facts.
//
// This bridge does NOT:
// - Create Capabilities
// - Create Findings
// - Write vulnerability_type / CWE / severity
// - Modify the Pi Worker output
type EvidenceClueBridge struct {
	db              *gorm.DB
	blackboard      *BlackboardService
	clueDrivenPhase int
}

func NewEvidenceClueBridge(db *gorm.DB, blackboard *BlackboardService, phase int) *EvidenceClueBridge {
	return &EvidenceClueBridge{db: db, blackboard: blackboard, clueDrivenPhase: phase}
}

// BridgeEvidence creates a clue_observation node for each evidence item.
// Only active when clueDrivenPhase >= 3. Idempotent: won't create duplicates.
func (b *EvidenceClueBridge) BridgeEvidence(ctx context.Context, taskID uint, evidence []model.AIEvidence, toolRunID *uint, intentID *uint) {
	if b.clueDrivenPhase < 3 || b.blackboard == nil || len(evidence) == 0 {
		return
	}

	for _, item := range evidence {
		roles := inferEvidenceClueRoles(item)
		if len(roles) == 0 {
			roles = []string{model.RoleVerificationOrObservation}
		}

		content := map[string]any{
			"roles":              roles,
			"evidence_refs":      []uint{item.ID},
			"evidence_kind":      item.EvidenceType,
			"source_tool_run_id": toolRunID,
			"source_intent_id":   intentID,
			"summary":            item.Summary,
			"confidence":         "tool_observed",
		}

		dedupSeed := fmt.Sprintf("clue-bridge-evidence-%d", item.ID)

		node, err := b.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        model.NodeClueObservation,
			Title:           clueObservationTitle(item),
			Summary:         item.Summary,
			Content:         content,
			DedupSeed:       dedupSeed,
			ImportanceScore: evidenceClueImportance(item),
			SourceType:      "evidence-bridge",
			SourceID:        fmt.Sprintf("evidence-%d", item.ID),
			EvidenceRefs:    []uint{item.ID},
		})
		if err != nil || node.ID == 0 {
			continue
		}

		// Write clue_supports edge from the clue_observation to any parent intent node
		if intentID != nil && *intentID != 0 {
			parentNodeID := blackboardNodeIDForIntent(ctx, b.db, taskID, *intentID)
			if parentNodeID != 0 {
				_ = b.blackboard.AddEdge(ctx, taskID, parentNodeID, node.ID, model.EdgeClueSupports, 0.7, map[string]any{
					"evidence_id":  item.ID,
					"tool_run_id":  toolRunID,
					"bridge":       "evidence_to_clue",
				})
			}
		}
	}
}

// inferEvidenceClueRoles infers clue roles from evidence type and content.
func inferEvidenceClueRoles(item model.AIEvidence) []string {
	roles := []string{}
	typeLower := strings.ToLower(item.EvidenceType)
	titleLower := strings.ToLower(item.Title)
	summaryLower := strings.ToLower(item.Summary)
	combined := typeLower + " " + titleLower + " " + summaryLower

	// code_snippet / file_manifest / code_search -> reachability_or_relation
	if typeLower == "code_snippet" || typeLower == "code_slice" || typeLower == "file_manifest" ||
		strings.Contains(combined, "code") || strings.Contains(combined, "file manifest") {
		roles = append(roles, model.RoleReachabilityOrRelation)
	}

	// http_exchange / response_diff / runtime output -> verification_or_observation
	if typeLower == "http_exchange" || typeLower == "response_diff" || typeLower == "runtime_output" ||
		typeLower == "worker_observation" || strings.Contains(combined, "response") ||
		strings.Contains(combined, "runtime") || strings.Contains(combined, "observation") {
		roles = append(roles, model.RoleVerificationOrObservation)
	}

	// request parameter / input / payload -> trigger_or_control
	if strings.Contains(combined, "input") || strings.Contains(combined, "parameter") ||
		strings.Contains(combined, "payload") || strings.Contains(combined, "source") ||
		strings.Contains(combined, "user-controlled") || strings.Contains(combined, "controllable") {
		roles = append(roles, model.RoleTriggerOrControl)
	}

	// sensitive operation / data access / file write / command execution -> security_effect_or_impact
	if strings.Contains(combined, "sink") || strings.Contains(combined, "exec") ||
		strings.Contains(combined, "write") || strings.Contains(combined, "query") ||
		strings.Contains(combined, "injection") || strings.Contains(combined, "sensitive") ||
		strings.Contains(combined, "impact") || strings.Contains(combined, "unsafe") {
		roles = append(roles, model.RoleSecurityEffectOrImpact)
	}

	// auth check / owner check / validation / sanitizer -> control_state_or_missing_control
	if strings.Contains(combined, "auth") || strings.Contains(combined, "owner") ||
		strings.Contains(combined, "check") || strings.Contains(combined, "guard") ||
		strings.Contains(combined, "sanitiz") || strings.Contains(combined, "filter") ||
		strings.Contains(combined, "missing control") || strings.Contains(combined, "no validation") {
		roles = append(roles, model.RoleControlStateOrMissingControl)
	}

	// scope / endpoint / route / entry -> origin_or_entry
	if strings.Contains(combined, "endpoint") || strings.Contains(combined, "route") ||
		strings.Contains(combined, "entry") || strings.Contains(combined, "surface") ||
		strings.Contains(combined, "url") || strings.Contains(combined, "path") ||
		strings.Contains(combined, "manifest") || strings.Contains(combined, "enumerat") {
		roles = append(roles, model.RoleOriginOrEntry)
	}

	// Deduplicate
	seen := map[string]bool{}
	unique := []string{}
	for _, r := range roles {
		if !seen[r] {
			seen[r] = true
			unique = append(unique, r)
		}
	}
	return unique
}

func clueObservationTitle(item model.AIEvidence) string {
	if item.Title != "" {
		return "Clue: " + item.Title
	}
	return fmt.Sprintf("Clue observation from %s evidence", item.EvidenceType)
}

func evidenceClueImportance(item model.AIEvidence) float64 {
	switch item.EvidenceType {
	case "code_snippet", "code_slice":
		return 0.75
	case "http_exchange", "response_diff":
		return 0.8
	case "worker_observation":
		return 0.65
	default:
		return 0.7
	}
}
