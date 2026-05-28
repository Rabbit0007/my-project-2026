package model

const (
	TaskTypeCodeAudit       = "code_audit"
	TaskTypePentest         = "pentest"
	TaskTypeInternalPentest = "internal_pentest"
	TaskTypeTerminalProof   = "terminal_proof"
	TaskTypeHybrid          = "hybrid"

	TaskStatusPending   = "pending"
	TaskStatusRunning   = "running"
	TaskStatusPaused    = "paused"
	TaskStatusCompleted = "completed"
	TaskStatusFailed    = "failed"
	TaskStatusCancelled = "cancelled"

	FindingStatusHypothesis           = "hypothesis"
	FindingStatusCandidate            = "candidate"
	FindingStatusCandidateIncomplete  = "candidate_incomplete"
	FindingStatusContractIncomplete   = "contract_incomplete"
	FindingStatusDynamicallyValidated = "dynamically_validated"
	FindingStatusHumanConfirmed       = "human_confirmed"
	FindingStatusFalsePositive        = "false_positive"
	FindingStatusAcceptedRisk         = "accepted_risk"
	FindingStatusFixed                = "fixed"
	FindingStatusRetested             = "retested"

	ValidationNotAttempted         = "not_attempted"
	ValidationToolObserved         = "tool_observed"
	ValidationContractIncomplete   = "contract_incomplete"
	ValidationDynamicallyValidated = "dynamically_validated"
	ValidationHumanConfirmed       = "human_confirmed"
	ContractStatusNotChecked       = "not_checked"
	ContractStatusPassed           = "passed"
	ContractStatusIncomplete       = "incomplete"
	ContractStatusFailed           = "failed"
	HumanReviewPending             = "pending"
	HumanReviewConfirmed           = "confirmed"
	HumanReviewFalsePositive       = "false_positive"
	HumanReviewAcceptedRisk        = "accepted_risk"
	IntentStatusPending            = "pending"
	IntentStatusClaimed            = "claimed"
	IntentStatusRunning            = "running"
	IntentStatusCompleted          = "completed"
	IntentStatusFailed             = "failed"
	IntentStatusCancelled          = "cancelled"
	IntentStatusSuppressed         = "suppressed"
	IntentStatusArchived           = "archived"
	ToolRunStatusPending           = "pending"
	ToolRunStatusRunning           = "running"
	ToolRunStatusSuccess           = "success"
	ToolRunStatusFailed            = "failed"
	ToolRunStatusTimeout           = "timeout"
	ToolRunStatusBlocked           = "blocked"
	BlackboardNodeStatusActive     = "active"
	BlackboardNodeStatusMerged     = "merged"
	BlackboardNodeStatusArchived   = "archived"
	BlackboardNodeStatusSuppressed = "suppressed"
	ReportStatusDraft              = "draft"
	ReportStatusReady              = "ready"
	ReportStatusFailed             = "failed"

	ModelPurposeBrain  = "brain"
	ModelPurposeWorker = "worker"
	ModelPurposeBoth   = "both"

	// --- Clue-Driven Exploration (Phase 0+) ---

	// Clue NodeTypes (new writes use these; legacy types remain readable via mapping)
	NodeClueOrigin      = "clue_origin"
	NodeClueObservation = "clue_observation"
	NodeClueLink        = "clue_link"
	NodeClueRefuted     = "clue_refuted"
	NodeClueImpact      = "clue_impact"
	NodeToolErrorClue   = "tool_error_clue"

	// Clue EdgeTypes
	EdgeClueSupports = "clue_supports"
	EdgeClueRefutes  = "clue_refutes"
	EdgeClueChainsTo = "clue_chains_to"

	// Clue IntentTypes (five universal verbs)
	IntentClueCollect     = "clue_collect"
	IntentClueValidate    = "clue_validate"
	IntentClueRefute      = "clue_refute"
	IntentClueChainExtend = "clue_chain_extend"
	IntentScopeObservation = "scope_observation"

	// Clue Roles (used by Capability Gate for role coverage evaluation)
	RoleOriginOrEntry              = "origin_or_entry"
	RoleTriggerOrControl           = "trigger_or_control"
	RoleReachabilityOrRelation     = "reachability_or_relation"
	RoleSecurityEffectOrImpact     = "security_effect_or_impact"
	RoleControlStateOrMissingControl = "control_state_or_missing_control"
	RoleVerificationOrObservation  = "verification_or_observation"
)

// RequiredClueRoles is the minimum set of roles that must be covered for a
// ClueChain to be considered closed (Capability Strength = verified).
var RequiredClueRoles = []string{
	RoleOriginOrEntry,
	RoleTriggerOrControl,
	RoleReachabilityOrRelation,
	RoleSecurityEffectOrImpact,
	RoleControlStateOrMissingControl,
	RoleVerificationOrObservation,
}
