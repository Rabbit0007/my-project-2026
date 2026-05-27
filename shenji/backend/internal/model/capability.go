package model

import (
	"time"

	"gorm.io/datatypes"
)

// AICapability represents a proven ability the platform has acquired during exploration.
// Capabilities are NOT findings — they are intermediate proof that the system can do something
// (e.g., read files, execute commands, access admin panel).
// Only verified capabilities with sufficient evidence can be promoted to Findings.
type AICapability struct {
	ID                      uint           `gorm:"primaryKey" json:"id"`
	TaskID                  uint           `gorm:"index;not null" json:"taskId"`
	CapabilityType          string         `gorm:"size:80;index;not null" json:"capabilityType"`
	Target                  string         `gorm:"size:1200" json:"target"`
	Scope                   string         `gorm:"size:400" json:"scope"`
	Strength                string         `gorm:"size:40;not null" json:"strength"` // suspected / observed / verified
	ProofSummary            string         `gorm:"type:text" json:"proofSummary"`
	EvidenceRefs            datatypes.JSON `gorm:"type:jsonb" json:"evidenceRefs"`
	SourceNodeIDs           datatypes.JSON `gorm:"type:jsonb" json:"sourceNodeIds"`
	AcquiredByIntentID      *uint          `json:"acquiredByIntentId"`
	ValidatedByHypothesisID *uint          `gorm:"index" json:"validatedByHypothesisId"`
	DerivedFromEvidenceRefs datatypes.JSON `gorm:"type:jsonb" json:"derivedFromEvidenceRefs"`
	CanAdvanceGoal          bool           `json:"canAdvanceGoal"`
	NextSuggestedIntents    datatypes.JSON `gorm:"type:jsonb" json:"nextSuggestedIntents"`
	RiskLevel               string         `gorm:"size:40" json:"riskLevel"`
	CreatedAt               time.Time      `json:"createdAt"`
	UpdatedAt               time.Time      `json:"updatedAt"`
}

// Capability types
const (
	CapFileRead              = "file_read"
	CapFileWrite             = "file_write"
	CapCommandExecution      = "command_execution"
	CapDatabaseRead          = "database_read"
	CapAdminAccess           = "admin_access"
	CapAuthenticatedSession  = "authenticated_session"
	CapInternalNetworkAccess = "internal_network_access"
	CapInternalServiceAccess = "internal_service_access"
	CapSourceCodeRead        = "source_code_read"
	CapSecretDiscovered      = "secret_discovered"
	CapCredentialObtained    = "credential_obtained"
	CapLateralAccess         = "lateral_access"
	CapUploadWrite           = "upload_write"
	CapConfigRead            = "config_read"
	CapBrowserExecution      = "browser_execution"
	CapCallbackControl       = "callback_control"
	CapSSRFInternalAccess    = "ssrf_internal_access"
	CapArbitraryObjectAccess = "arbitrary_object_access"
	CapBusinessStateManip    = "business_state_manipulation"
	CapCrossUserObjectAccess = "cross_user_object_access"
	CapUnauthorizedState     = "unauthorized_state_transition"
	CapWorkflowStepBypass    = "workflow_step_bypass"
	CapBusinessValueTamper   = "business_value_tampering"
	CapReplaySuccess         = "replay_success"
	CapSQLInjection          = "sql_injection"
	CapPathTraversal         = "path_traversal"
	CapTemplateInjection     = "template_injection"
	CapDeserialization       = "deserialization"
)

// Strength levels
const (
	StrengthSuspected = "suspected"
	StrengthObserved  = "observed"
	StrengthVerified  = "verified"
)
