package model

import (
	"time"

	"gorm.io/datatypes"
)

type AIWorkspace struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Name        string `gorm:"size:180;not null" json:"name"`
	Description string `gorm:"type:text" json:"description"`
	RootPath    string `gorm:"size:800;not null" json:"rootPath"`
	StorageRef  string `gorm:"size:800" json:"storageRef"`
	CreatedBy   uint   `json:"createdBy"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type AISecurityTask struct {
	ID                  uint           `gorm:"primaryKey" json:"id"`
	WorkspaceID         uint           `gorm:"index;not null" json:"workspaceId"`
	Workspace           AIWorkspace    `json:"workspace,omitempty"`
	Name                string         `gorm:"size:220;not null" json:"name"`
	TaskType            string         `gorm:"size:40;index;not null" json:"taskType"`
	Status              string         `gorm:"size:40;index;not null" json:"status"`
	Objective           string         `gorm:"type:text" json:"objective"`
	ScopeJSON           datatypes.JSON `gorm:"type:jsonb" json:"scopeJson"`
	AuthorizationJSON   datatypes.JSON `gorm:"type:jsonb" json:"authorizationJson"`
	SafePolicyJSON      datatypes.JSON `gorm:"type:jsonb" json:"safePolicyJson"`
	ModelConfigID       *uint          `json:"modelConfigId"`
	WorkerModelConfigID *uint          `json:"workerModelConfigId"`
	IsTestTask          bool           `gorm:"index;not null;default:false" json:"isTestTask"`
	Archived            bool           `gorm:"index;not null;default:false" json:"archived"`
	ProgressStage       string         `gorm:"size:180" json:"progressStage"`
	ProgressPercent     int            `json:"progressPercent"`
	StartedAt           *time.Time     `json:"startedAt"`
	FinishedAt          *time.Time     `json:"finishedAt"`
	CreatedBy           uint           `json:"createdBy"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type AITaskTarget struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	TaskID      uint           `gorm:"index;not null" json:"taskId"`
	TargetType  string         `gorm:"size:40;index;not null" json:"targetType"`
	Value       string         `gorm:"size:1200;not null" json:"value"`
	ScopeStatus string         `gorm:"size:40;index;not null" json:"scopeStatus"`
	Metadata    datatypes.JSON `gorm:"type:jsonb" json:"metadata"`
	CreatedAt   time.Time
}

type AIAgentLoop struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	TaskID     uint       `gorm:"index;not null" json:"taskId"`
	Status     string     `gorm:"size:40;index;not null" json:"status"`
	Goal       string     `gorm:"type:text" json:"goal"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	StopReason string     `gorm:"type:text" json:"stopReason"`
	CreatedAt  time.Time
}

type AIAgentLoopIteration struct {
	ID              uint           `gorm:"primaryKey" json:"id"`
	LoopID          uint           `gorm:"index;not null" json:"loopId"`
	TaskID          uint           `gorm:"index;not null" json:"taskId"`
	IterationNo     int            `json:"iterationNo"`
	CurrentIntentID *uint          `json:"currentIntentId"`
	InputContextRef string         `gorm:"size:900" json:"inputContextRef"`
	ModelProvider   string         `gorm:"size:120" json:"modelProvider"`
	ModelName       string         `gorm:"size:180" json:"modelName"`
	ThoughtSummary  string         `gorm:"type:text" json:"thoughtSummary"`
	PlannedAction   string         `gorm:"type:text" json:"plannedAction"`
	ToolRunIDs      datatypes.JSON `gorm:"type:jsonb" json:"toolRunIds"`
	EvidenceRefs    datatypes.JSON `gorm:"type:jsonb" json:"evidenceRefs"`
	BlackboardDelta datatypes.JSON `gorm:"type:jsonb" json:"blackboardDelta"`
	Status          string         `gorm:"size:40;index;not null" json:"status"`
	ErrorMessage    string         `gorm:"type:text" json:"errorMessage"`
	StartedAt       time.Time      `json:"startedAt"`
	FinishedAt      *time.Time     `json:"finishedAt"`
}

type AIBlackboardNode struct {
	ID              uint           `gorm:"primaryKey" json:"id"`
	TaskID          uint           `gorm:"index;not null" json:"taskId"`
	NodeType        string         `gorm:"size:50;index;not null" json:"nodeType"`
	Title           string         `gorm:"size:260;not null" json:"title"`
	Summary         string         `gorm:"type:text" json:"summary"`
	ContentJSON     datatypes.JSON `gorm:"type:jsonb" json:"contentJson"`
	DedupKey        string         `gorm:"size:160;index;not null" json:"dedupKey"`
	ImportanceScore float64        `json:"importanceScore"`
	Status          string         `gorm:"size:40;index;not null" json:"status"`
	SourceType      string         `gorm:"size:50;index;not null" json:"sourceType"`
	SourceID        string         `gorm:"size:160" json:"sourceId"`
	EvidenceRefs    datatypes.JSON `gorm:"type:jsonb" json:"evidenceRefs"`
	FirstSeenAt     time.Time      `json:"firstSeenAt"`
	LastSeenAt      time.Time      `json:"lastSeenAt"`
	SeenCount       int            `json:"seenCount"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type AIBlackboardEdge struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	TaskID    uint           `gorm:"index;not null" json:"taskId"`
	FromID    uint           `gorm:"index;not null" json:"fromId"`
	ToID      uint           `gorm:"index;not null" json:"toId"`
	EdgeType  string         `gorm:"size:60;index;not null" json:"edgeType"`
	Weight    float64        `json:"weight"`
	Metadata  datatypes.JSON `gorm:"type:jsonb" json:"metadata"`
	CreatedAt time.Time
}

type AIIntent struct {
	ID               uint           `gorm:"primaryKey" json:"id"`
	TaskID           uint           `gorm:"index;not null" json:"taskId"`
	ParentNodeID     *uint          `json:"parentNodeId"`
	IntentType       string         `gorm:"size:80;index;not null" json:"intentType"`
	Title            string         `gorm:"size:260;not null" json:"title"`
	Objective        string         `gorm:"type:text" json:"objective"`
	ConstraintsJSON  datatypes.JSON `gorm:"type:jsonb" json:"constraintsJson"`
	RequiredEvidence datatypes.JSON `gorm:"type:jsonb" json:"requiredEvidence"`
	PriorityScore    float64        `gorm:"index" json:"priorityScore"`
	Status           string         `gorm:"size:40;index;not null" json:"status"`
	ClaimedBy        string         `gorm:"size:160" json:"claimedBy"`
	ClaimExpiresAt   *time.Time     `json:"claimExpiresAt"`
	CreatedBy        string         `gorm:"size:50;not null" json:"createdBy"`
	CreatedReason    string         `gorm:"type:text" json:"createdReason"`
	StartedAt        *time.Time     `json:"startedAt"`
	FinishedAt       *time.Time     `json:"finishedAt"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type AIToolRun struct {
	ID                 uint           `gorm:"primaryKey" json:"id"`
	TaskID             uint           `gorm:"index;not null" json:"taskId"`
	IterationID        *uint          `json:"iterationId"`
	IntentID           *uint          `json:"intentId"`
	RunnerType         string         `gorm:"size:80;index;not null" json:"runnerType"`
	ToolName           string         `gorm:"size:120;index;not null" json:"toolName"`
	InputJSON          datatypes.JSON `gorm:"type:jsonb" json:"inputJson"`
	CommandPreview     string         `gorm:"type:text" json:"commandPreview"`
	ContainerID        string         `gorm:"size:160" json:"containerId"`
	ImageName          string         `gorm:"size:240" json:"imageName"`
	WorkspacePath      string         `gorm:"size:800" json:"workspacePath"`
	NetworkPolicy      string         `gorm:"size:120" json:"networkPolicy"`
	ResourceLimits     datatypes.JSON `gorm:"type:jsonb" json:"resourceLimits"`
	Status             string         `gorm:"size:40;index;not null" json:"status"`
	ExitCode           *int           `json:"exitCode"`
	StdoutRef          string         `gorm:"size:900" json:"stdoutRef"`
	StderrRef          string         `gorm:"size:900" json:"stderrRef"`
	ArtifactRefs       datatypes.JSON `gorm:"type:jsonb" json:"artifactRefs"`
	SafePolicySnapshot datatypes.JSON `gorm:"type:jsonb" json:"safePolicySnapshot"`
	BlockReason        string         `gorm:"type:text" json:"blockReason"`
	StartedAt          time.Time      `json:"startedAt"`
	FinishedAt         *time.Time     `json:"finishedAt"`
	CreatedAt          time.Time
}

type AIEvidence struct {
	ID               uint           `gorm:"primaryKey" json:"id"`
	TaskID           uint           `gorm:"index;not null" json:"taskId"`
	ToolRunID        *uint          `json:"toolRunId"`
	EvidenceType     string         `gorm:"size:80;index;not null" json:"evidenceType"`
	Title            string         `gorm:"size:260;not null" json:"title"`
	Summary          string         `gorm:"type:text" json:"summary"`
	RawRef           string         `gorm:"size:900" json:"rawRef"`
	Hash             string         `gorm:"size:128;index;not null" json:"hash"`
	Target           string         `gorm:"size:1200" json:"target"`
	FilePath         string         `gorm:"size:900" json:"filePath"`
	LineStart        *int           `json:"lineStart"`
	LineEnd          *int           `json:"lineEnd"`
	RequestSnapshot  datatypes.JSON `gorm:"type:jsonb" json:"requestSnapshot"`
	ResponseSnapshot datatypes.JSON `gorm:"type:jsonb" json:"responseSnapshot"`
	ArtifactURL      string         `gorm:"size:900" json:"artifactUrl"`
	RelationType     string         `gorm:"size:80;index" json:"relationType"`
	Redacted         bool           `json:"redacted"`
	CreatedAt        time.Time
}

type AIFinding struct {
	ID                uint           `gorm:"primaryKey" json:"id"`
	TaskID            uint           `gorm:"index;not null" json:"taskId"`
	Title             string         `gorm:"size:280;not null" json:"title"`
	VulnerabilityType string         `gorm:"size:160;index;not null" json:"vulnerabilityType"`
	AffectedTarget    string         `gorm:"size:1200" json:"affectedTarget"`
	AffectedComponent string         `gorm:"size:900" json:"affectedComponent"`
	Severity          string         `gorm:"size:40;index;not null" json:"severity"`
	Status            string         `gorm:"size:60;index;not null" json:"status"`
	ValidationStatus  string         `gorm:"size:60;index;not null" json:"validationStatus"`
	ContractType      string         `gorm:"size:120" json:"contractType"`
	ContractStatus    string         `gorm:"size:60;index;not null" json:"contractStatus"`
	RichDetails       datatypes.JSON `gorm:"type:jsonb" json:"richDetails"`
	EvidenceRefs      datatypes.JSON `gorm:"type:jsonb" json:"evidenceRefs"`
	Remediation       string         `gorm:"type:text" json:"remediation"`
	RetestSteps       string         `gorm:"type:text" json:"retestSteps"`
	HumanReviewStatus string         `gorm:"size:60;index;not null" json:"humanReviewStatus"`
	HumanReviewNote   string         `gorm:"type:text" json:"humanReviewNote"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type AIContractCheckResult struct {
	ID              uint           `gorm:"primaryKey" json:"id"`
	FindingID       uint           `gorm:"index;not null" json:"findingId"`
	TaskID          uint           `gorm:"index;not null" json:"taskId"`
	ContractType    string         `gorm:"size:120;index;not null" json:"contractType"`
	Status          string         `gorm:"size:60;index;not null" json:"status"`
	MissingFields   datatypes.JSON `gorm:"type:jsonb" json:"missingFields"`
	SatisfiedFields datatypes.JSON `gorm:"type:jsonb" json:"satisfiedFields"`
	EvidenceMapping datatypes.JSON `gorm:"type:jsonb" json:"evidenceMapping"`
	DowngradeReason string         `gorm:"type:text" json:"downgradeReason"`
	NextIntentIDs   datatypes.JSON `gorm:"type:jsonb" json:"nextIntentIds"`
	CheckedAt       time.Time      `json:"checkedAt"`
}

type AIReport struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	TaskID       uint       `gorm:"index;not null" json:"taskId"`
	Title        string     `gorm:"size:260;not null" json:"title"`
	Status       string     `gorm:"size:40;index;not null" json:"status"`
	Format       string     `gorm:"size:40;not null" json:"format"`
	MarkdownRef  string     `gorm:"size:900" json:"markdownRef"`
	HTMLRef      string     `gorm:"size:900" json:"htmlRef"`
	EvidencePack string     `gorm:"size:900" json:"evidencePack"`
	Summary      string     `gorm:"type:text" json:"summary"`
	GeneratedAt  *time.Time `json:"generatedAt"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type AIHumanReview struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	TaskID    uint   `gorm:"index;not null" json:"taskId"`
	FindingID uint   `gorm:"index;not null" json:"findingId"`
	Status    string `gorm:"size:60;index;not null" json:"status"`
	Note      string `gorm:"type:text" json:"note"`
	Reviewer  string `gorm:"size:160" json:"reviewer"`
	CreatedAt time.Time
}

type AIModelConfig struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"size:160;not null" json:"name"`
	Purpose     string         `gorm:"size:40;index;not null;default:'brain'" json:"purpose"`
	Provider    string         `gorm:"size:80;not null" json:"provider"`
	BaseURL     string         `gorm:"size:900" json:"baseUrl"`
	Model       string         `gorm:"size:180;not null" json:"model"`
	APIKeyRef   string         `gorm:"size:260" json:"apiKeyRef"`
	OptionsJSON datatypes.JSON `gorm:"type:jsonb" json:"optionsJson"`
	Enabled     bool           `gorm:"index;not null;default:true" json:"enabled"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type AIAuditEvent struct {
	ID         uint           `gorm:"primaryKey" json:"id"`
	TaskID     *uint          `gorm:"index" json:"taskId"`
	EventType  string         `gorm:"size:100;index;not null" json:"eventType"`
	Actor      string         `gorm:"size:160;not null" json:"actor"`
	Summary    string         `gorm:"type:text" json:"summary"`
	Metadata   datatypes.JSON `gorm:"type:jsonb" json:"metadata"`
	OccurredAt time.Time      `gorm:"index;not null" json:"occurredAt"`
}
