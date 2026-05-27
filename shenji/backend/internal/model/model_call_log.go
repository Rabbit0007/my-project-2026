package model

import "time"

// AIModelCallLog records every model API call for observability and cost tracking.
type AIModelCallLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	TaskID       *uint     `gorm:"index" json:"taskId"`
	ModelName    string    `gorm:"size:180;index;not null" json:"modelName"`
	Provider     string    `gorm:"size:80" json:"provider"`
	Purpose      string    `gorm:"size:120;index;not null" json:"purpose"` // plan / code_audit / graph_reasoning / chat / evidence_intent / report_narrative
	Status       string    `gorm:"size:40;not null" json:"status"`         // success / failed / timeout
	LatencyMs    int64     `json:"latencyMs"`
	PromptTokens int       `json:"promptTokens"`
	CompTokens   int       `json:"compTokens"`
	ErrorMessage string    `gorm:"type:text" json:"errorMessage"`
	CalledAt     time.Time `gorm:"index;not null" json:"calledAt"`
}
