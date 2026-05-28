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
	model.IntentBootstrapGraph:       {},
	model.IntentDiscoverEntrypoints:  {},
	model.IntentEnumerateSurfaces:    {},
	model.IntentExploreEntrypoint:    {},
	model.IntentInspectDataflow:      {},
	model.IntentInspectGuard:         {},
	model.IntentInspectAuthBoundary:  {},
	model.IntentInspectSinkReach:     {},
	model.IntentValidateHypothesis:   {},
	model.IntentRunTool:              {},
	model.IntentResolveUnknown:       {},
	model.IntentCompareBehavior:      {},
	model.IntentExpandAttackSurface:  {},
	model.IntentRecheckInconclusive:  {},
	model.IntentVerifyCapability:     {},
	model.IntentPromoteCapability:    {},
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

var genericGraphIntentTypes = map[string]struct{}{
	model.IntentBootstrapGraph:      {},
	model.IntentDiscoverEntrypoints: {},
	model.IntentEnumerateSurfaces:   {},
	model.IntentExploreEntrypoint:   {},
	model.IntentInspectDataflow:     {},
	model.IntentInspectGuard:        {},
	model.IntentInspectAuthBoundary: {},
	model.IntentInspectSinkReach:    {},
	model.IntentValidateHypothesis:  {},
	model.IntentRunTool:             {},
	model.IntentResolveUnknown:      {},
	model.IntentCompareBehavior:     {},
	model.IntentExpandAttackSurface: {},
	model.IntentRecheckInconclusive: {},
	model.IntentVerifyCapability:    {},
	model.IntentPromoteCapability:   {},
	model.IntentSurfaceDiscovery:    {},
	model.IntentFingerprintConfirm:  {},
	model.IntentJSAnalysis:          {},
	model.IntentBehaviorProbe:       {},
	model.IntentAuthProbe:           {},
	model.IntentBusinessLogicProbe:  {},
	model.IntentCapabilityExpand:    {},
	model.IntentGoalAttempt:         {},
}

var legacyVulnIntentNormalization = map[string]struct {
	Generic            string
	ClassificationHint string
}{
	model.IntentSQLiProbe:            {Generic: model.IntentInspectDataflow, ClassificationHint: "sqli"},
	model.IntentPathTraversalProbe:   {Generic: model.IntentInspectGuard, ClassificationHint: "path_traversal"},
	model.IntentIDORProbe:            {Generic: model.IntentInspectGuard, ClassificationHint: "idor"},
	model.IntentMassAssignmentProbe:  {Generic: model.IntentInspectGuard, ClassificationHint: "mass_assignment"},
	model.IntentSSRFProbe:            {Generic: model.IntentInspectDataflow, ClassificationHint: "ssrf"},
	model.IntentUploadProbe:          {Generic: model.IntentExploreEntrypoint, ClassificationHint: "upload"},
	model.IntentXSSProbe:             {Generic: model.IntentCompareBehavior, ClassificationHint: "xss"},
	model.IntentSSTIProbe:            {Generic: model.IntentInspectDataflow, ClassificationHint: "ssti"},
	model.IntentCommandInjProbe:      {Generic: model.IntentInspectDataflow, ClassificationHint: "command_injection"},
	model.IntentFilePathControl:      {Generic: model.IntentInspectGuard, ClassificationHint: "path_traversal"},
	model.IntentSQLConstructTrace:    {Generic: model.IntentInspectDataflow, ClassificationHint: "sqli"},
	model.IntentObjectOwnerCheck:     {Generic: model.IntentInspectGuard, ClassificationHint: "idor"},
	model.IntentEntryToAuthzTrace:    {Generic: model.IntentInspectGuard, ClassificationHint: "authz"},
	model.IntentRouteToSinkTrace:     {Generic: model.IntentInspectDataflow, ClassificationHint: "route_to_sink"},
	model.IntentDataflowTrace:        {Generic: model.IntentInspectDataflow, ClassificationHint: "dataflow"},
	model.IntentSSRFURLControl:       {Generic: model.IntentInspectDataflow, ClassificationHint: "ssrf"},
	model.IntentUploadToExec:         {Generic: model.IntentInspectDataflow, ClassificationHint: "upload_to_exec"},
	model.IntentTemplateRenderTrace:  {Generic: model.IntentInspectDataflow, ClassificationHint: "template_injection"},
	model.IntentDeserializationTrace: {Generic: model.IntentInspectDataflow, ClassificationHint: "deserialization"},
}

func runtimeIntentTypeList() []string {
	values := make([]string, 0, len(runtimeIntentTypes))
	for value := range runtimeIntentTypes {
		values = append(values, value)
	}
	return values
}

func genericIntentTypeList() []string {
	values := make([]string, 0, len(genericGraphIntentTypes))
	for value := range genericGraphIntentTypes {
		values = append(values, value)
	}
	return values
}

func normalizeGraphSearchIntentType(intentType string) (string, map[string]any, bool) {
	if intentType == "" {
		return model.IntentResolveUnknown, nil, true
	}
	if normalized, ok := legacyVulnIntentNormalization[intentType]; ok {
		return normalized.Generic, map[string]any{
			"classification_hint": normalized.ClassificationHint,
			"legacy_intent":       intentType,
			"intent_role":         "classification_hint",
		}, true
	}
	if _, ok := runtimeIntentTypes[intentType]; ok {
		return intentType, nil, true
	}
	return "", nil, false
}

func mergeIntentMetadata(base map[string]any, metadata map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	for key, value := range metadata {
		base[key] = value
	}
	return base
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
		Where("intent_type IN ?", genericIntentTypeList()).
		Order("priority_score desc, created_at asc").
		First(&intent).Error
	if err == nil {
		return &intent, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}
	err = s.db.WithContext(ctx).
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
