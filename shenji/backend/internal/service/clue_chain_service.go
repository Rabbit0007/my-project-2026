package service

import (
	"context"
	"encoding/json"
	"strings"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

// ClueChainService evaluates ClueChain role coverage for Capability promotion.
// It implements the Evidence Gate's chain evaluation logic as defined in the
// clue-driven exploration design.
//
// This service does NOT:
// - Call tools
// - Create Findings / Reports
// - Reference vulnerability type names for gating decisions
type ClueChainService struct {
	db *gorm.DB
}

// ClueChainEval is the result of evaluating a Capability's supporting ClueChain.
type ClueChainEval struct {
	Allowed         bool              `json:"allowed"`
	Strength        string            `json:"strength"` // suspected / observed / verified
	Missing         []string          `json:"missing"`
	EvidenceRefs    []uint            `json:"evidence_refs"`
	NodeRefs        []uint            `json:"node_refs"`
	Relations       []string          `json:"relations"`
	RoleCoverage    map[string][]uint `json:"role_coverage"`    // role -> node IDs
	RoleEvidence    map[string][]uint `json:"role_evidence"`    // role -> evidence IDs
	NegativeRefutes []uint            `json:"negative_refutes"` // active NegativeFact IDs refuting this chain
}

func NewClueChainService(db *gorm.DB) *ClueChainService {
	return &ClueChainService{db: db}
}

// EvaluateCapability evaluates whether a Capability's supporting evidence and
// blackboard nodes satisfy the required clue role coverage for promotion.
//
// This is the clue-driven replacement for the legacy delivery-proof-based gate.
// It checks:
// 1. All requiredClueRoles are covered by at least one node
// 2. Each covered role has at least one evidence ref
// 3. All supporting nodes are active
// 4. No active NegativeFact refutes the chain
func (s *ClueChainService) EvaluateCapability(ctx context.Context, cap model.AICapability) ClueChainEval {
	eval := ClueChainEval{
		EvidenceRefs: uintListFromJSON(cap.EvidenceRefs),
		NodeRefs:     uintListFromJSON(cap.SourceNodeIDs),
		RoleCoverage: make(map[string][]uint),
		RoleEvidence: make(map[string][]uint),
	}

	// Load supporting nodes
	nodes := s.loadNodes(ctx, cap.TaskID, eval.NodeRefs)
	// Load evidence items
	evidenceItems := s.loadEvidence(ctx, cap.TaskID, eval.EvidenceRefs)

	// Build role coverage from nodes
	for _, node := range nodes {
		roles := nodeRoles(node)
		for _, role := range roles {
			eval.RoleCoverage[role] = appendUniqueUint(eval.RoleCoverage[role], node.ID)
		}
	}

	// Also infer roles from evidence (evidence can cover verification_or_observation)
	for _, item := range evidenceItems {
		roles := evidenceRoles(item)
		for _, role := range roles {
			eval.RoleCoverage[role] = appendUniqueUint(eval.RoleCoverage[role], item.ID+1000000) // offset to distinguish from node IDs
			eval.RoleEvidence[role] = appendUniqueUint(eval.RoleEvidence[role], item.ID)
		}
	}

	// Map evidence to roles based on node association
	for _, node := range nodes {
		nodeEvidenceRefs := uintListFromJSON(node.EvidenceRefs)
		roles := nodeRoles(node)
		for _, role := range roles {
			for _, eID := range nodeEvidenceRefs {
				eval.RoleEvidence[role] = appendUniqueUint(eval.RoleEvidence[role], eID)
			}
		}
	}
	// Also add direct capability evidence refs to all covered roles
	for role := range eval.RoleCoverage {
		for _, eID := range eval.EvidenceRefs {
			eval.RoleEvidence[role] = appendUniqueUint(eval.RoleEvidence[role], eID)
		}
	}

	// Collect edge relations
	eval.Relations = s.loadEdgeRelations(ctx, cap.TaskID, eval.NodeRefs)

	// Check for active NegativeFacts that refute this chain
	eval.NegativeRefutes = s.findRefutingNegativeFacts(ctx, cap)

	// Evaluate missing roles
	missing := []string{}
	for _, role := range model.RequiredClueRoles {
		if len(eval.RoleCoverage[role]) == 0 {
			missing = append(missing, role)
			continue
		}
		if len(eval.RoleEvidence[role]) == 0 {
			missing = append(missing, role+":evidence")
		}
	}

	// Check node activity
	for _, node := range nodes {
		if node.Status != model.BlackboardNodeStatusActive {
			missing = appendUniqueString(missing, "active_nodes")
			break
		}
	}

	// Check negative refutation
	if len(eval.NegativeRefutes) > 0 {
		missing = appendUniqueString(missing, "refuted_by_negative_fact")
	}

	// Basic sanity: must have evidence
	if len(eval.EvidenceRefs) == 0 {
		missing = appendUniqueString(missing, "evidence_refs")
	}

	// Must be goal-advancing
	if !cap.CanAdvanceGoal {
		missing = appendUniqueString(missing, "goal_advancing_capability")
	}

	eval.Missing = missing
	eval.Allowed = len(missing) == 0
	eval.Strength = classifyClueChainStrength(eval)
	return eval
}

// classifyClueChainStrength determines the Capability Strength based on role coverage.
//   - verified  = all roles covered with evidence, no refutation
//   - observed  = has verification/observation or security_effect support, but missing some roles
//   - suspected = only partial coverage, missing key roles or evidence
func classifyClueChainStrength(eval ClueChainEval) string {
	if eval.Allowed {
		return model.StrengthVerified
	}
	hasObservationalSupport := len(eval.RoleEvidence[model.RoleVerificationOrObservation]) > 0 ||
		len(eval.RoleCoverage[model.RoleSecurityEffectOrImpact]) > 0
	if hasObservationalSupport {
		return model.StrengthObserved
	}
	return model.StrengthSuspected
}

// nodeRoles extracts clue roles from a blackboard node.
// For new clue_* nodes, roles are in ContentJSON.roles.
// For legacy nodes, roles are inferred from the NodeType mapping.
func nodeRoles(node model.AIBlackboardNode) []string {
	// Try to read roles from ContentJSON
	var content struct {
		Roles []string `json:"roles"`
	}
	if len(node.ContentJSON) > 0 {
		_ = json.Unmarshal(node.ContentJSON, &content)
	}
	if len(content.Roles) > 0 {
		return content.Roles
	}
	// Legacy NodeType mapping (read-time normalization)
	return legacyNodeTypeToRoles(node)
}

// legacyNodeTypeToRoles maps legacy NodeTypes to default clue roles.
// This implements the read-time normalization defined in design.md.
func legacyNodeTypeToRoles(node model.AIBlackboardNode) []string {
	titleLower := strings.ToLower(node.Title)
	switch node.NodeType {
	case model.NodeClueOrigin:
		return []string{model.RoleOriginOrEntry}
	case model.NodeClueObservation:
		return []string{model.RoleVerificationOrObservation}
	case model.NodeClueLink:
		return []string{model.RoleReachabilityOrRelation}
	case model.NodeClueImpact:
		return []string{model.RoleSecurityEffectOrImpact}
	case model.NodeClueRefuted:
		return nil // refuted nodes don't contribute positive roles

	// Legacy types
	case "surface_fact", "fact":
		if strings.Contains(titleLower, "endpoint") || strings.Contains(titleLower, "url") ||
			strings.Contains(titleLower, "path") || strings.Contains(titleLower, "route") ||
			strings.Contains(titleLower, "surface") || strings.Contains(titleLower, "http") {
			return []string{model.RoleOriginOrEntry}
		}
		return []string{model.RoleReachabilityOrRelation}
	case "code_fact":
		roles := []string{model.RoleReachabilityOrRelation}
		if strings.Contains(titleLower, "source") || strings.Contains(titleLower, "input") ||
			strings.Contains(titleLower, "param") || strings.Contains(titleLower, "control") {
			roles = append(roles, model.RoleTriggerOrControl)
		}
		if strings.Contains(titleLower, "sink") || strings.Contains(titleLower, "exec") ||
			strings.Contains(titleLower, "write") || strings.Contains(titleLower, "query") {
			roles = append(roles, model.RoleSecurityEffectOrImpact)
		}
		return roles
	case "business_fact":
		return []string{model.RoleSecurityEffectOrImpact}
	case "secret_fact", "credential_fact":
		return []string{model.RoleSecurityEffectOrImpact}
	case "technology_fingerprint":
		return []string{model.RoleVerificationOrObservation}
	case "hypothesis":
		return []string{model.RoleReachabilityOrRelation}
	case "negative_fact":
		return nil // negative facts don't contribute positive roles
	case "origin", "goal":
		return []string{model.RoleOriginOrEntry}
	case model.NodeTestedPath:
		return []string{model.RoleVerificationOrObservation}
	default:
		// Unknown legacy type — treat as observation
		if titleLower != "" {
			return []string{model.RoleVerificationOrObservation}
		}
		return nil
	}
}

// evidenceRoles infers roles from evidence items.
// Evidence primarily covers verification_or_observation.
func evidenceRoles(item model.AIEvidence) []string {
	roles := []string{model.RoleVerificationOrObservation}
	typeLower := strings.ToLower(item.EvidenceType)
	summaryLower := strings.ToLower(item.Summary)
	if typeLower == "code_snippet" {
		if strings.Contains(summaryLower, "source") || strings.Contains(summaryLower, "input") {
			roles = append(roles, model.RoleTriggerOrControl)
		}
		if strings.Contains(summaryLower, "sink") || strings.Contains(summaryLower, "exec") {
			roles = append(roles, model.RoleSecurityEffectOrImpact)
		}
		roles = append(roles, model.RoleReachabilityOrRelation)
	}
	if typeLower == "http_exchange" || typeLower == "response_diff" {
		roles = append(roles, model.RoleOriginOrEntry)
	}
	return roles
}

func (s *ClueChainService) loadNodes(ctx context.Context, taskID uint, ids []uint) []model.AIBlackboardNode {
	if len(ids) == 0 {
		return nil
	}
	var nodes []model.AIBlackboardNode
	_ = s.db.WithContext(ctx).Where("task_id = ? AND id IN ?", taskID, ids).Find(&nodes).Error
	return nodes
}

func (s *ClueChainService) loadEvidence(ctx context.Context, taskID uint, ids []uint) []model.AIEvidence {
	if len(ids) == 0 {
		return nil
	}
	var items []model.AIEvidence
	_ = s.db.WithContext(ctx).Where("task_id = ? AND id IN ?", taskID, ids).Find(&items).Error
	return items
}

func (s *ClueChainService) loadEdgeRelations(ctx context.Context, taskID uint, nodeIDs []uint) []string {
	if len(nodeIDs) == 0 {
		return nil
	}
	var edges []model.AIBlackboardEdge
	_ = s.db.WithContext(ctx).
		Where("task_id = ? AND (from_id IN ? OR to_id IN ?)", taskID, nodeIDs, nodeIDs).
		Find(&edges).Error
	relations := []string{}
	for _, edge := range edges {
		if edge.EdgeType != "" {
			relations = appendUniqueString(relations, edge.EdgeType)
		}
	}
	return relations
}

func (s *ClueChainService) findRefutingNegativeFacts(ctx context.Context, cap model.AICapability) []uint {
	var negatives []model.AINegativeFact
	_ = s.db.WithContext(ctx).Where("task_id = ?", cap.TaskID).Find(&negatives).Error
	refuting := []uint{}
	targetLower := strings.ToLower(cap.Target + " " + cap.ProofSummary)
	for _, nf := range negatives {
		nfText := strings.ToLower(nf.TestedPath + " " + nf.Title + " " + nf.Reason)
		if strings.Contains(targetLower, strings.ToLower(nf.TestedPath)) ||
			strings.Contains(nfText, strings.ToLower(cap.Target)) {
			refuting = append(refuting, nf.ID)
		}
	}
	return refuting
}

func appendUniqueString(slice []string, value string) []string {
	for _, existing := range slice {
		if existing == value {
			return slice
		}
	}
	return append(slice, value)
}
