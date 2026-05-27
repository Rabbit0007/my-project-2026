package model

import (
	"encoding/json"
	"strings"
	"time"

	"gorm.io/datatypes"
)

const (
	GoalTypeTerminal  = "terminal"
	GoalTypeCoverage  = "coverage"
	GoalTypeExpansion = "expansion"

	GoalModeCodeAudit     = "code_audit"
	GoalModeWebPentest    = "web_pentest"
	GoalModeInternal      = "internal_pentest"
	GoalModeTerminalProof = "terminal_proof"

	HypothesisTypeLegacy                    = "legacy_hypothesis"
	HypothesisTypeInjectionCandidate        = "injection_candidate"
	HypothesisTypeAuthzBypassCandidate      = "authz_bypass_candidate"
	HypothesisTypeIDORCandidate             = "idor_candidate"
	HypothesisTypeMassAssignmentCandidate   = "mass_assignment_candidate"
	HypothesisTypeFileReadCandidate         = "file_read_candidate"
	HypothesisTypeFileWriteCandidate        = "file_write_candidate"
	HypothesisTypeUploadBypassCandidate     = "upload_bypass_candidate"
	HypothesisTypeCommandExecutionCandidate = "command_execution_candidate"
	HypothesisTypeSSRFCandidate             = "ssrf_candidate"
	HypothesisTypeXSSCandidate              = "xss_candidate"
	HypothesisTypeSSTICandidate             = "ssti_candidate"
	HypothesisTypeXXECandidate              = "xxe_candidate"
	HypothesisTypeDeserializationCandidate  = "deserialization_candidate"
	HypothesisTypeSecretReuseCandidate      = "secret_reuse_candidate"
	HypothesisTypeCredentialReuseCandidate  = "credential_reuse_candidate"
	HypothesisTypeLateralAccessCandidate    = "lateral_access_candidate"
	HypothesisTypeBusinessLogicCandidate    = "business_logic_candidate"
	HypothesisTypeInfoDisclosureCandidate   = "information_disclosure_candidate"
	HypothesisTypeSessionWeaknessCandidate  = "session_weakness_candidate"
	HypothesisTypeDependencyVulnCandidate   = "dependency_vulnerability_candidate"

	ConfidenceSuspected    = "suspected"
	ConfidencePlausible    = "plausible"
	ConfidenceStrong       = "strong"
	ConfidenceValidated    = "validated"
	ConfidenceConfirmed    = "confirmed"
	ConfidenceRefuted      = "refuted"
	ConfidenceInconclusive = "inconclusive"
	ConfidenceUnknown      = "unknown"

	HypothesisStatusPending      = "pending"
	HypothesisStatusValidating   = "validating"
	HypothesisStatusValidated    = "validated"
	HypothesisStatusRefuted      = "refuted"
	HypothesisStatusInconclusive = "inconclusive"
	HypothesisStatusSuppressed   = "suppressed"

	UnverifiedReasonInsufficientAuthorization = "insufficient_authorization"
	UnverifiedReasonInsufficientBudget        = "insufficient_budget"
	UnverifiedReasonInsufficientCapability    = "insufficient_capability"
	UnverifiedReasonMissingCredentials        = "missing_credentials"
	UnverifiedReasonSafetyRestriction         = "safety_restriction"
	UnverifiedReasonInconclusiveEvidence      = "inconclusive_evidence"
	UnverifiedReasonMethodNotObservable       = "method_not_observable"
)

type AIGoalProfile struct {
	ID               uint           `gorm:"primaryKey" json:"id"`
	TaskID           uint           `gorm:"uniqueIndex;not null" json:"taskId"`
	GoalType         string         `gorm:"size:40;index;not null;default:coverage" json:"goalType"`
	Name             string         `gorm:"size:220;not null" json:"name"`
	Description      string         `gorm:"type:text" json:"description"`
	RawUserGoal      string         `gorm:"type:text" json:"rawUserGoal"`
	NormalizedGoal   string         `gorm:"type:text" json:"normalizedGoal"`
	Mode             string         `gorm:"size:40;index;not null;default:code_audit" json:"mode"`
	CompletionPolicy datatypes.JSON `gorm:"type:jsonb" json:"completionPolicy"`
	CreatedAt        time.Time      `json:"createdAt"`
	UpdatedAt        time.Time      `json:"updatedAt"`
}

type AIHypothesisNode struct {
	ID                     uint           `gorm:"primaryKey" json:"id"`
	TaskID                 uint           `gorm:"index;not null" json:"taskId"`
	HypothesisType         string         `gorm:"size:80;index;not null" json:"hypothesisType"`
	Title                  string         `gorm:"size:280;not null" json:"title"`
	Description            string         `gorm:"type:text" json:"description"`
	ConfidenceState        string         `gorm:"size:40;index;not null;default:suspected" json:"confidenceState"`
	Status                 string         `gorm:"size:40;index;not null;default:pending" json:"status"`
	SourceObservationRefs  datatypes.JSON `gorm:"type:jsonb" json:"sourceObservationRefs"`
	SupportingEvidenceRefs datatypes.JSON `gorm:"type:jsonb" json:"supportingEvidenceRefs"`
	TargetEntity           string         `gorm:"size:1200" json:"targetEntity"`
	ExpectedCapability     string         `gorm:"size:80;index" json:"expectedCapability"`
	ValidationIntentRefs   datatypes.JSON `gorm:"type:jsonb" json:"validationIntentRefs"`
	NegativeFactRefs       datatypes.JSON `gorm:"type:jsonb" json:"negativeFactRefs"`
	UnverifiedRiskRefs     datatypes.JSON `gorm:"type:jsonb" json:"unverifiedRiskRefs"`
	CreatedAt              time.Time      `json:"createdAt"`
	UpdatedAt              time.Time      `json:"updatedAt"`
	ValidatedAt            *time.Time     `json:"validatedAt"`
}

type AINegativeFact struct {
	ID                  uint           `gorm:"primaryKey" json:"id"`
	TaskID              uint           `gorm:"index;not null" json:"taskId"`
	HypothesisID        *uint          `gorm:"index" json:"hypothesisId"`
	Title               string         `gorm:"size:280;not null" json:"title"`
	TestedPath          string         `gorm:"size:1200" json:"testedPath"`
	Reason              string         `gorm:"type:text" json:"reason"`
	EvidenceRefs        datatypes.JSON `gorm:"type:jsonb" json:"evidenceRefs"`
	SimilarPatternKey   string         `gorm:"size:220;index" json:"similarPatternKey"`
	CreatedFromIntentID *uint          `gorm:"index" json:"createdFromIntentId"`
	CreatedAt           time.Time      `json:"createdAt"`
}

type AIUnverifiedRisk struct {
	ID                uint           `gorm:"primaryKey" json:"id"`
	TaskID            uint           `gorm:"index;not null" json:"taskId"`
	HypothesisID      *uint          `gorm:"index" json:"hypothesisId"`
	Title             string         `gorm:"size:280;not null" json:"title"`
	Reason            string         `gorm:"size:80;index;not null" json:"reason"`
	Detail            string         `gorm:"type:text" json:"detail"`
	ObservationRefs   datatypes.JSON `gorm:"type:jsonb" json:"observationRefs"`
	EvidenceRefs      datatypes.JSON `gorm:"type:jsonb" json:"evidenceRefs"`
	BlockedByIntentID *uint          `gorm:"index" json:"blockedByIntentId"`
	CreatedAt         time.Time      `json:"createdAt"`
}

type AICoverageItem struct {
	ID            uint           `gorm:"primaryKey" json:"id"`
	TaskID        uint           `gorm:"index;not null" json:"taskId"`
	GoalProfileID *uint          `gorm:"index" json:"goalProfileId"`
	Category      string         `gorm:"size:80;index;not null" json:"category"`
	Name          string         `gorm:"size:260;not null" json:"name"`
	TargetRef     string         `gorm:"size:1200" json:"targetRef"`
	RiskHint      string         `gorm:"size:180" json:"riskHint"`
	Status        string         `gorm:"size:40;index;not null;default:discovered" json:"status"`
	Reason        string         `gorm:"type:text" json:"reason"`
	EvidenceRefs  datatypes.JSON `gorm:"type:jsonb" json:"evidenceRefs"`
	NodeRefs      datatypes.JSON `gorm:"type:jsonb" json:"nodeRefs"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
}

type AIEnvironmentModel struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	TaskID      uint           `gorm:"uniqueIndex;not null" json:"taskId"`
	ModelJSON   datatypes.JSON `gorm:"type:jsonb" json:"modelJson"`
	UpdatedFrom string         `gorm:"size:120" json:"updatedFrom"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

type AIObjectiveLadder struct {
	ID             uint           `gorm:"primaryKey" json:"id"`
	TaskID         uint           `gorm:"index;not null" json:"taskId"`
	GoalProfileID  *uint          `gorm:"index" json:"goalProfileId"`
	Level          int            `gorm:"index;not null" json:"level"`
	Name           string         `gorm:"size:160;not null" json:"name"`
	Status         string         `gorm:"size:40;index;not null;default:pending" json:"status"`
	CapabilityRefs datatypes.JSON `gorm:"type:jsonb" json:"capabilityRefs"`
	HypothesisRefs datatypes.JSON `gorm:"type:jsonb" json:"hypothesisRefs"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
}

type ValidationIntentMetadata struct {
	HypothesisID               *uint          `json:"hypothesis_id,omitempty"`
	ValidationMethod           string         `json:"validation_method,omitempty"`
	ExpectedEvidence           string         `json:"expected_evidence,omitempty"`
	ExpectedCapability         string         `json:"expected_capability,omitempty"`
	SuccessCondition           string         `json:"success_condition,omitempty"`
	FailureCondition           string         `json:"failure_condition,omitempty"`
	SafetyLevel                string         `json:"safety_level,omitempty"`
	EnvironmentContextSnapshot map[string]any `json:"environment_context_snapshot,omitempty"`
}

type BranchValue struct {
	CapabilityUnlockScore     float64   `json:"capability_unlock_score"`
	GraphExpansionScore       float64   `json:"graph_expansion_score"`
	NoveltyScore              float64   `json:"novelty_score"`
	RiskValue                 float64   `json:"risk_value"`
	CoverageGain              float64   `json:"coverage_gain"`
	ExecutionCost             float64   `json:"execution_cost"`
	SafetyRisk                float64   `json:"safety_risk"`
	DuplicatePenalty          float64   `json:"duplicate_penalty"`
	EvidenceQuality           float64   `json:"evidence_quality"`
	GoalTypeBoost             float64   `json:"goal_type_boost"`
	EnvironmentAlignmentBoost float64   `json:"environment_alignment_boost"`
	FinalScore                float64   `json:"final_score"`
	Reason                    string    `json:"reason"`
	NegativeFactRefs          []uint    `json:"negative_fact_refs"`
	MatchedEnvironmentRefs    []string  `json:"matched_environment_refs"`
	ScoredAt                  time.Time `json:"scored_at"`
}

func (i AIIntent) ValidationMetadata() ValidationIntentMetadata {
	var all map[string]any
	if len(i.ConstraintsJSON) == 0 || json.Unmarshal(i.ConstraintsJSON, &all) != nil {
		return ValidationIntentMetadata{}
	}
	meta := ValidationIntentMetadata{
		ValidationMethod:   stringFromAny(all["validation_method"]),
		ExpectedEvidence:   stringFromAny(all["expected_evidence"]),
		ExpectedCapability: stringFromAny(all["expected_capability"]),
		SuccessCondition:   firstNonEmpty(stringFromAny(all["success_condition"]), stringFromAny(all["success_criteria"])),
		FailureCondition:   firstNonEmpty(stringFromAny(all["failure_condition"]), stringFromAny(all["failure_criteria"])),
		SafetyLevel:        stringFromAny(all["safety_level"]),
	}
	if id, ok := uintFromAny(all["hypothesis_id"]); ok {
		meta.HypothesisID = &id
	}
	if snapshot, ok := all["environment_context_snapshot"].(map[string]any); ok {
		meta.EnvironmentContextSnapshot = snapshot
	}
	return meta
}

func (i *AIIntent) WithValidationMetadata(meta ValidationIntentMetadata) {
	values := map[string]any{}
	if len(i.ConstraintsJSON) > 0 {
		_ = json.Unmarshal(i.ConstraintsJSON, &values)
	}
	if meta.HypothesisID != nil {
		values["hypothesis_id"] = *meta.HypothesisID
	}
	if meta.ValidationMethod != "" {
		values["validation_method"] = meta.ValidationMethod
	}
	if meta.ExpectedEvidence != "" {
		values["expected_evidence"] = meta.ExpectedEvidence
	}
	if meta.ExpectedCapability != "" {
		values["expected_capability"] = meta.ExpectedCapability
	}
	if meta.SuccessCondition != "" {
		values["success_condition"] = meta.SuccessCondition
	}
	if meta.FailureCondition != "" {
		values["failure_condition"] = meta.FailureCondition
	}
	if meta.SafetyLevel != "" {
		values["safety_level"] = meta.SafetyLevel
	}
	if len(meta.EnvironmentContextSnapshot) > 0 {
		values["environment_context_snapshot"] = meta.EnvironmentContextSnapshot
	}
	i.ConstraintsJSON = JSONValue(values)
}

func (i AIIntent) HypothesisID() *uint {
	return i.ValidationMetadata().HypothesisID
}

func (i AIIntent) ExpectedCapability() string {
	return i.ValidationMetadata().ExpectedCapability
}

func (i AIIntent) BranchValue() (*BranchValue, error) {
	if len(i.ConstraintsJSON) == 0 {
		return nil, nil
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(i.ConstraintsJSON, &values); err != nil {
		return nil, err
	}
	raw, ok := values["branch_value"]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var branch BranchValue
	if err := json.Unmarshal(raw, &branch); err != nil {
		return nil, err
	}
	return &branch, nil
}

func (i *AIIntent) WithBranchValue(v BranchValue) error {
	values := map[string]any{}
	if len(i.ConstraintsJSON) > 0 {
		if err := json.Unmarshal(i.ConstraintsJSON, &values); err != nil {
			return err
		}
	}
	values["branch_value"] = v
	i.ConstraintsJSON = JSONValue(values)
	return nil
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func uintFromAny(value any) (uint, bool) {
	switch v := value.(type) {
	case float64:
		if v > 0 {
			return uint(v), true
		}
	case int:
		if v > 0 {
			return uint(v), true
		}
	case uint:
		if v > 0 {
			return v, true
		}
	}
	return 0, false
}
