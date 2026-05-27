package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type ModelConfigService struct {
	db *gorm.DB
}

type ModelConfigUpsertInput struct {
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`
	Provider    string `json:"provider"`
	BaseURL     string `json:"baseUrl"`
	Model       string `json:"model"`
	APIKeyRef   string `json:"apiKeyRef"`
	OptionsJSON any    `json:"optionsJson"`
	Enabled     bool   `json:"enabled"`
}

func NewModelConfigService(db *gorm.DB) *ModelConfigService {
	return &ModelConfigService{db: db}
}

func (s *ModelConfigService) List(ctx context.Context) ([]model.AIModelConfig, error) {
	var configs []model.AIModelConfig
	err := s.db.WithContext(ctx).
		Order("enabled desc, purpose asc, id asc").
		Find(&configs).Error
	return configs, err
}

func (s *ModelConfigService) Get(ctx context.Context, id uint) (model.AIModelConfig, error) {
	var config model.AIModelConfig
	err := s.db.WithContext(ctx).First(&config, id).Error
	return config, err
}

func (s *ModelConfigService) Create(ctx context.Context, input ModelConfigUpsertInput) (model.AIModelConfig, error) {
	if err := validateModelConfigInput(input); err != nil {
		return model.AIModelConfig{}, err
	}
	now := time.Now().UTC()
	config := model.AIModelConfig{
		Name:        strings.TrimSpace(input.Name),
		Purpose:     normalizeModelPurpose(input.Purpose),
		Provider:    strings.TrimSpace(input.Provider),
		BaseURL:     strings.TrimSpace(input.BaseURL),
		Model:       strings.TrimSpace(input.Model),
		APIKeyRef:   strings.TrimSpace(input.APIKeyRef),
		OptionsJSON: mustJSON(input.OptionsJSON),
		Enabled:     input.Enabled,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	return config, s.db.WithContext(ctx).Create(&config).Error
}

func (s *ModelConfigService) Update(ctx context.Context, id uint, input ModelConfigUpsertInput) (model.AIModelConfig, error) {
	config, err := s.Get(ctx, id)
	if err != nil {
		return config, err
	}
	if err := validateModelConfigInput(input); err != nil {
		return config, err
	}
	config.Name = strings.TrimSpace(input.Name)
	config.Purpose = normalizeModelPurpose(input.Purpose)
	config.Provider = strings.TrimSpace(input.Provider)
	config.BaseURL = strings.TrimSpace(input.BaseURL)
	config.Model = strings.TrimSpace(input.Model)
	config.APIKeyRef = strings.TrimSpace(input.APIKeyRef)
	config.OptionsJSON = mustJSON(input.OptionsJSON)
	config.Enabled = input.Enabled
	config.UpdatedAt = time.Now().UTC()
	return config, s.db.WithContext(ctx).Save(&config).Error
}

func normalizeModelPurpose(purpose string) string {
	switch strings.ToLower(strings.TrimSpace(purpose)) {
	case "", model.ModelPurposeBrain:
		return model.ModelPurposeBrain
	case model.ModelPurposeWorker:
		return model.ModelPurposeWorker
	case model.ModelPurposeBoth:
		return model.ModelPurposeBoth
	default:
		return strings.ToLower(strings.TrimSpace(purpose))
	}
}

func validateModelConfigInput(input ModelConfigUpsertInput) error {
	if strings.TrimSpace(input.Name) == "" {
		return fmt.Errorf("模型配置名称不能为空")
	}
	purpose := normalizeModelPurpose(input.Purpose)
	if purpose != model.ModelPurposeBrain && purpose != model.ModelPurposeWorker {
		return fmt.Errorf("模型用途只能是 brain 或 worker，不能同时作为 Brain 和 Worker")
	}
	if strings.TrimSpace(input.Provider) == "" {
		return fmt.Errorf("Provider 不能为空")
	}
	if strings.TrimSpace(input.Model) == "" {
		return fmt.Errorf("模型名称不能为空")
	}
	return nil
}
