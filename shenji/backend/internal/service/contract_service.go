package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type ContractService struct {
	db                *gorm.DB
	blackboard        *BlackboardService
	models            *ModelRuntimeService
	deliveryWriteback string // "off" (default) or "on" for legacy escape hatch
}

// ContractService is a delivery quality gate. It checks whether an
// evidence-backed Finding is complete enough for reporting, can downgrade an
// incomplete delivery artifact, and may suggest evidence gaps for later
// exploration. It is not the main planner and must not replace the
// hypothesis-driven reasoner, DynamicIntentExpander, StateExpansionPlanner, or
// ExplorationBudgetManager.
var genericContractFields = []string{
	"entrypoint",
	"controlled_input",
	"propagation_path",
	"sensitive_sink_or_behavior",
	"trigger_payload_or_action",
	"baseline_evidence",
	"validation_evidence",
	"observed_result",
	"impact_explanation",
	"scope_statement",
	"safety_statement",
	"remediation",
	"retest_steps",
	"evidence_mapping",
	"request_packet",
	"bash_poc",
	"python_poc",
	"success_criteria",
	"root_cause",
}

func NewContractService(db *gorm.DB, blackboard *BlackboardService, models *ModelRuntimeService) *ContractService {
	return &ContractService{db: db, blackboard: blackboard, models: models, deliveryWriteback: "off"}
}

// SetDeliveryWriteback sets the delivery writeback mode ("off" or "on").
func (s *ContractService) SetDeliveryWriteback(mode string) {
	if s != nil && (mode == "off" || mode == "on") {
		s.deliveryWriteback = mode
	}
}

func (s *ContractService) ListByTask(ctx context.Context, taskID uint) ([]model.AIContractCheckResult, error) {
	var checks []model.AIContractCheckResult
	err := s.db.WithContext(ctx).
		Where("task_id = ?", taskID).
		Order("checked_at desc").
		Find(&checks).Error
	return checks, err
}

func (s *ContractService) CheckFinding(ctx context.Context, finding *model.AIFinding) (model.AIContractCheckResult, error) {
	var details map[string]any
	_ = json.Unmarshal(finding.RichDetails, &details)
	missing := []string{}
	satisfied := []string{}
	for _, field := range genericContractFields {
		value, ok := details[field]
		if !ok || value == nil || strings.TrimSpace(fmt.Sprint(value)) == "" {
			missing = append(missing, field)
		} else {
			satisfied = append(satisfied, field)
		}
	}
	status := model.ContractStatusPassed
	downgrade := ""
	if len(missing) > 0 {
		status = model.ContractStatusIncomplete
		downgrade = "Finding remains incomplete because required delivery evidence is missing: " + strings.Join(missing, ", ")
		finding.Status = model.FindingStatusContractIncomplete
		finding.ValidationStatus = model.ValidationContractIncomplete
	}
	if len(missing) == 0 && finding.ValidationStatus == model.ValidationDynamicallyValidated {
		finding.Status = model.FindingStatusDynamicallyValidated
	}
	finding.ContractStatus = status
	finding.UpdatedAt = time.Now().UTC()
	if err := s.db.WithContext(ctx).Save(finding).Error; err != nil {
		return model.AIContractCheckResult{}, err
	}
	result := model.AIContractCheckResult{
		FindingID:       finding.ID,
		TaskID:          finding.TaskID,
		ContractType:    finding.ContractType,
		Status:          status,
		MissingFields:   mustJSON(missing),
		SatisfiedFields: mustJSON(satisfied),
		EvidenceMapping: finding.EvidenceRefs,
		DowngradeReason: downgrade,
		NextIntentIDs:   mustJSON([]uint{}),
		CheckedAt:       time.Now().UTC(),
	}
	if err := s.db.WithContext(ctx).Create(&result).Error; err != nil {
		return result, err
	}
	if len(missing) > 0 {
		_ = s.blackboard.AddMissingFields(ctx, finding.TaskID, finding.ID, missing)
		task, taskErr := s.loadTask(ctx, finding.TaskID)
		suggestion := deterministicEvidenceIntent(*finding, missing)
		baseIntentType := suggestion.IntentType
		if taskErr == nil && s.models != nil {
			if planned, planErr := s.models.SuggestEvidenceIntent(ctx, task, *finding, missing); planErr == nil {
				if strings.TrimSpace(planned.Title) != "" {
					suggestion.Title = planned.Title
				}
				if strings.TrimSpace(planned.Objective) != "" {
					suggestion.Objective = planned.Objective
				}
			}
		}
		intentType := baseIntentType
		title := suggestion.Title
		objective := suggestion.Objective
		constraints := map[string]any{"safe": true, "findingId": finding.ID}
		if intentType == "" {
			intentType = "collect_evidence"
		}
		if finding.VulnerabilityType == "pentest_candidate" || intentType == "validate" {
			constraints["httpValidation"] = true
		}
		var existing int64
		if err := s.db.WithContext(ctx).
			Model(&model.AIIntent{}).
			Where("task_id = ? AND intent_type = ? AND status = ? AND constraints_json @> ?", finding.TaskID, intentType, model.IntentStatusPending, mustJSON(map[string]any{"findingId": finding.ID})).
			Count(&existing).Error; err == nil && existing > 0 {
			return result, nil
		}

		// Phase 4: When deliveryWriteback is "off" (default), do NOT create
		// a core Intent from the Delivery Layer. Only emit audit diagnostic.
		if s.deliveryWriteback != "on" {
			appendAuditEvent(ctx, s.db, &finding.TaskID, "agent.contract_incomplete_diagnostic", "contract-service",
				"Contract incomplete; delivery writeback disabled, not spawning Intent.",
				map[string]any{"findingId": finding.ID, "missing": missing, "downgrade": downgrade})
			return result, nil
		}

		// Legacy escape hatch (RABBIT_DELIVERY_WRITEBACK=on): create Intent as before
		intent := model.AIIntent{
			TaskID:           finding.TaskID,
			IntentType:       intentType,
			Title:            title,
			Objective:        objective,
			ConstraintsJSON:  mustJSON(constraints),
			RequiredEvidence: mustJSON(missing),
			PriorityScore:    0.95,
			Status:           model.IntentStatusPending,
			CreatedBy:        "contract",
			CreatedReason:    downgrade,
			CreatedAt:        time.Now().UTC(),
			UpdatedAt:        time.Now().UTC(),
		}
		if err := s.db.WithContext(ctx).Create(&intent).Error; err == nil {
			result.NextIntentIDs = mustJSON([]uint{intent.ID})
			_ = s.db.WithContext(ctx).Save(&result).Error
		}
	}
	return result, nil
}

func (s *ContractService) loadTask(ctx context.Context, taskID uint) (model.AISecurityTask, error) {
	var task model.AISecurityTask
	err := s.db.WithContext(ctx).First(&task, taskID).Error
	return task, err
}
