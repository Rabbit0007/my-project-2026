package service

import (
	"context"
	"fmt"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type IntentService struct {
	db *gorm.DB
}

// IntentType is a classification hint, not the capability boundary. The open
// exploration goal lives in AIIntent.Objective; execution context, success /
// failure criteria, and safety constraints live in ConstraintsJSON.
func NewIntentService(db *gorm.DB) *IntentService {
	return &IntentService{db: db}
}

var runtimeIntentTypes = map[string]struct{}{
	"code_trace":                     {},
	"collect_evidence":               {},
	"fingerprint":                    {},
	"recon":                          {},
	"validate":                       {},
	model.IntentSurfaceDiscovery:     {},
	model.IntentFingerprintConfirm:   {},
	model.IntentJSAnalysis:           {},
	model.IntentBehaviorProbe:        {},
	model.IntentAuthProbe:            {},
	model.IntentIDORProbe:            {},
	model.IntentMassAssignmentProbe:  {},
	model.IntentBusinessLogicProbe:   {},
	model.IntentPathTraversalProbe:   {},
	model.IntentSQLiProbe:            {},
	model.IntentSSRFProbe:            {},
	model.IntentUploadProbe:          {},
	model.IntentXSSProbe:             {},
	model.IntentSSTIProbe:            {},
	model.IntentCommandInjProbe:      {},
	model.IntentSecretVerify:         {},
	model.IntentCodeProjectIndex:     {},
	model.IntentCodeSliceAnalysis:    {},
	model.IntentDataflowTrace:        {},
	model.IntentRouteToSinkTrace:     {},
	model.IntentEntryToAuthzTrace:    {},
	model.IntentObjectOwnerCheck:     {},
	model.IntentMassAssignTrace:      {},
	model.IntentFilePathControl:      {},
	model.IntentUploadToExec:         {},
	model.IntentSecretToAPI:          {},
	model.IntentBusinessStateTrace:   {},
	model.IntentSQLConstructTrace:    {},
	model.IntentDeserializationTrace: {},
	model.IntentTemplateRenderTrace:  {},
	model.IntentSSRFURLControl:       {},
	model.IntentCapabilityExpand:     {},
	model.IntentGoalAttempt:          {},
	model.IntentReportFinalize:       {},
}

func runtimeIntentTypeList() []string {
	values := make([]string, 0, len(runtimeIntentTypes))
	for value := range runtimeIntentTypes {
		values = append(values, value)
	}
	return values
}

func (s *IntentService) ListByTask(ctx context.Context, taskID uint) ([]model.AIIntent, error) {
	var intents []model.AIIntent
	err := s.db.WithContext(ctx).
		Where("task_id = ?", taskID).
		Order("priority_score desc, created_at asc").
		Find(&intents).Error
	return intents, err
}

func (s *IntentService) NextPending(ctx context.Context, taskID uint) (*model.AIIntent, error) {
	var intent model.AIIntent
	err := s.db.WithContext(ctx).
		Where("task_id = ? AND status = ?", taskID, model.IntentStatusPending).
		Where("intent_type IN ?", runtimeIntentTypeList()).
		Order("priority_score desc, created_at asc").
		First(&intent).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &intent, nil
}

func intentEligibleForNextPending(intent model.AIIntent) bool {
	if intent.Status != model.IntentStatusPending {
		return false
	}
	_, ok := runtimeIntentTypes[intent.IntentType]
	return ok
}

func (s *IntentService) Claim(ctx context.Context, intent *model.AIIntent, worker string, lease time.Duration) error {
	now := time.Now().UTC()
	expires := now.Add(lease)
	intent.Status = model.IntentStatusRunning
	intent.StartedAt = &now
	intent.ClaimedBy = worker
	intent.ClaimExpiresAt = &expires
	intent.UpdatedAt = now
	result := s.db.WithContext(ctx).Model(&model.AIIntent{}).
		Where("id = ? AND status = ?", intent.ID, model.IntentStatusPending).
		Updates(map[string]any{
			"status":           model.IntentStatusRunning,
			"started_at":       now,
			"claimed_by":       worker,
			"claim_expires_at": expires,
			"updated_at":       now,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("intent %d is no longer pending; another worker may have claimed this clue", intent.ID)
	}
	return nil
}

func (s *IntentService) Finish(ctx context.Context, id uint, success bool) error {
	now := time.Now().UTC()
	updates := map[string]any{
		"finished_at": now,
		"updated_at":  now,
	}
	if success {
		updates["status"] = model.IntentStatusCompleted
	} else {
		updates["status"] = model.IntentStatusFailed
	}
	return s.db.WithContext(ctx).Model(&model.AIIntent{}).Where("id = ?", id).Updates(updates).Error
}
