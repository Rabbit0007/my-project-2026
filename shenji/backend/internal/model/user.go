package model

import "time"

type AIUser struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Username     string `gorm:"size:80;uniqueIndex;not null" json:"username"`
	PasswordHash string `gorm:"size:260;not null" json:"-"`
	DisplayName  string `gorm:"size:120" json:"displayName"`
	Role         string `gorm:"size:40;not null;default:admin" json:"role"` // admin / viewer
	Enabled      bool   `gorm:"not null;default:true" json:"enabled"`
	LastLoginAt  *time.Time `json:"lastLoginAt"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}
