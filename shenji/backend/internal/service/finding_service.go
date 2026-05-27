package service

import (
	"context"
	"encoding/json"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type FindingService struct {
	db *gorm.DB
}

// FindingService manages delivery artifacts. A Finding is not the starting
// point of exploration: pattern hits, fingerprints, and model guesses must
// first become evidence-backed hypotheses, capabilities, negative facts, or
// unverified risks. Confirmed delivery status is reserved for validated
// evidence paths and report quality checks.
func NewFindingService(db *gorm.DB) *FindingService {
	return &FindingService{db: db}
}

func (s *FindingService) UpsertCandidate(ctx context.Context, taskID uint, title, vulnType, target, component, severity string, richDetails any, evidenceRefs []uint, validationStatus string) (model.AIFinding, error) {
	var finding model.AIFinding
	err := s.db.WithContext(ctx).
		Where("task_id = ? AND vulnerability_type = ? AND affected_target = ? AND affected_component = ?", taskID, vulnType, target, component).
		First(&finding).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return finding, err
	}
	if err == gorm.ErrRecordNotFound {
		return s.createCandidateWithValidation(ctx, taskID, title, vulnType, target, component, severity, richDetails, evidenceRefs, validationStatus)
	}

	if finding.VulnerabilityType != vulnType && vulnType != "" {
		return s.createCandidateWithValidation(ctx, taskID, title, vulnType, target, component, severity, richDetails, evidenceRefs, validationStatus)
	}

	existingRefs := []uint{}
	_ = json.Unmarshal(finding.EvidenceRefs, &existingRefs)
	existingRefs = append(existingRefs, evidenceRefs...)
	finding.Title = title
	finding.AffectedComponent = component
	finding.Severity = severity
	finding.Status = model.FindingStatusCandidate
	finding.ValidationStatus = validationStatus
	finding.RichDetails = mustJSON(richDetails)
	finding.EvidenceRefs = mustJSON(uniqueUint(existingRefs))
	finding.UpdatedAt = time.Now().UTC()
	return finding, s.db.WithContext(ctx).Save(&finding).Error
}

func (s *FindingService) createCandidateWithValidation(ctx context.Context, taskID uint, title, vulnType, target, component, severity string, richDetails any, evidenceRefs []uint, validationStatus string) (model.AIFinding, error) {
	finding, err := s.CreateCandidate(ctx, taskID, title, vulnType, target, component, severity, richDetails, evidenceRefs)
	if err != nil {
		return finding, err
	}
	if validationStatus != "" {
		finding.ValidationStatus = validationStatus
		finding.UpdatedAt = time.Now().UTC()
		err = s.db.WithContext(ctx).Save(&finding).Error
	}
	return finding, err
}

func (s *FindingService) CreateCandidate(ctx context.Context, taskID uint, title, vulnType, target, component, severity string, richDetails any, evidenceRefs []uint) (model.AIFinding, error) {
	now := time.Now().UTC()
	remediation, retestSteps := defaultDeliveryGuidance(vulnType)
	finding := model.AIFinding{
		TaskID:            taskID,
		Title:             sanitizeUTF8(title),
		VulnerabilityType: sanitizeUTF8(vulnType),
		AffectedTarget:    sanitizeUTF8(target),
		AffectedComponent: sanitizeUTF8(component),
		Severity:          severity,
		Status:            model.FindingStatusCandidate,
		ValidationStatus:  model.ValidationToolObserved,
		ContractType:      "generic_security_finding",
		ContractStatus:    model.ContractStatusNotChecked,
		RichDetails:       mustJSON(richDetails),
		EvidenceRefs:      mustJSON(evidenceRefs),
		Remediation:       remediation,
		RetestSteps:       retestSteps,
		HumanReviewStatus: model.HumanReviewPending,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	return finding, s.db.WithContext(ctx).Create(&finding).Error
}

func defaultDeliveryGuidance(vulnType string) (string, string) {
	_ = vulnType
	return "复核受影响的 Source/Sink 路径，移除不安全数据流，补充输入校验、输出编码、权限控制和最小权限约束。",
		"在相同授权范围内重新执行基线采集和验证步骤，确认原观察结果不再复现，并检查对应 Evidence 与 Contract 状态。"
}

func uniqueUint(values []uint) []uint {
	seen := map[uint]struct{}{}
	result := make([]uint, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (s *FindingService) ListByTask(ctx context.Context, taskID uint) ([]model.AIFinding, error) {
	var findings []model.AIFinding
	err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("severity asc, created_at desc").Find(&findings).Error
	return findings, err
}

func (s *FindingService) Get(ctx context.Context, id uint) (model.AIFinding, error) {
	var finding model.AIFinding
	err := s.db.WithContext(ctx).First(&finding, id).Error
	return finding, err
}

func (s *FindingService) UpdateReview(ctx context.Context, id uint, status, note string) (model.AIFinding, error) {
	finding, err := s.Get(ctx, id)
	if err != nil {
		return finding, err
	}
	finding.HumanReviewStatus = status
	finding.HumanReviewNote = note
	if status == model.HumanReviewConfirmed && finding.ContractStatus == model.ContractStatusPassed {
		finding.Status = model.FindingStatusHumanConfirmed
		finding.ValidationStatus = model.ValidationHumanConfirmed
	}
	if status == model.HumanReviewFalsePositive {
		finding.Status = model.FindingStatusFalsePositive
	}
	if status == model.HumanReviewAcceptedRisk {
		finding.Status = model.FindingStatusAcceptedRisk
	}
	finding.UpdatedAt = time.Now().UTC()
	return finding, s.db.WithContext(ctx).Save(&finding).Error
}
