package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type BlackboardService struct {
	db *gorm.DB
}

type BlackboardNodeDraft struct {
	TaskID          uint
	NodeType        string
	Title           string
	Summary         string
	Content         any
	DedupSeed       string
	ImportanceScore float64
	SourceType      string
	SourceID        string
	EvidenceRefs    []uint
}

func NewBlackboardService(db *gorm.DB) *BlackboardService {
	return &BlackboardService{db: db}
}

func DedupKey(taskID uint, parts ...string) string {
	normalized := []string{fmt.Sprintf("%d", taskID)}
	for _, part := range parts {
		normalized = append(normalized, strings.ToLower(strings.TrimSpace(part)))
	}
	sum := sha256.Sum256([]byte(strings.Join(normalized, "|")))
	return hex.EncodeToString(sum[:])
}

func (s *BlackboardService) UpsertNode(ctx context.Context, draft BlackboardNodeDraft) (model.AIBlackboardNode, error) {
	now := time.Now().UTC()
	// Sanitize strings to prevent PostgreSQL UTF-8 errors from model output
	draft.Title = sanitizeUTF8(draft.Title)
	draft.Summary = sanitizeUTF8(draft.Summary)
	draft.DedupSeed = sanitizeUTF8(draft.DedupSeed)
	draft.SourceID = sanitizeUTF8(draft.SourceID)

	evidenceRefs := make([]string, 0, len(draft.EvidenceRefs))
	for _, ref := range draft.EvidenceRefs {
		evidenceRefs = append(evidenceRefs, fmt.Sprintf("%d", ref))
	}
	dedupSeed := draft.DedupSeed
	if dedupSeed == "" {
		dedupSeed = draft.NodeType + "|" + draft.Title
	}
	dedup := DedupKey(draft.TaskID, dedupSeed)
	var existing model.AIBlackboardNode
	err := s.db.WithContext(ctx).Where("task_id = ? AND dedup_key = ?", draft.TaskID, dedup).First(&existing).Error
	if err == nil {
		existing.LastSeenAt = now
		existing.SeenCount++
		if draft.Summary != "" {
			existing.Summary = draft.Summary
		}
		if draft.ImportanceScore > existing.ImportanceScore {
			existing.ImportanceScore = draft.ImportanceScore
		}
		existing.EvidenceRefs = stringListJSON(evidenceRefs)
		return existing, s.db.WithContext(ctx).Save(&existing).Error
	}
	if err != gorm.ErrRecordNotFound {
		return model.AIBlackboardNode{}, err
	}
	node := model.AIBlackboardNode{
		TaskID:          draft.TaskID,
		NodeType:        draft.NodeType,
		Title:           draft.Title,
		Summary:         draft.Summary,
		ContentJSON:     mustJSON(draft.Content),
		DedupKey:        dedup,
		ImportanceScore: draft.ImportanceScore,
		Status:          model.BlackboardNodeStatusActive,
		SourceType:      draft.SourceType,
		SourceID:        draft.SourceID,
		EvidenceRefs:    stringListJSON(evidenceRefs),
		FirstSeenAt:     now,
		LastSeenAt:      now,
		SeenCount:       1,
	}
	return node, s.db.WithContext(ctx).Create(&node).Error
}

func (s *BlackboardService) AddEdge(ctx context.Context, taskID, fromID, toID uint, edgeType string, weight float64, metadata any) error {
	edge := model.AIBlackboardEdge{
		TaskID:    taskID,
		FromID:    fromID,
		ToID:      toID,
		EdgeType:  edgeType,
		Weight:    weight,
		Metadata:  mustJSON(metadata),
		CreatedAt: time.Now().UTC(),
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&edge).Error
}

func (s *BlackboardService) RecentNodes(ctx context.Context, taskID uint, limit int) ([]model.AIBlackboardNode, error) {
	if limit <= 0 || limit > 200 {
		limit = 80
	}
	var nodes []model.AIBlackboardNode
	err := s.db.WithContext(ctx).
		Where("task_id = ? AND status = ?", taskID, model.BlackboardNodeStatusActive).
		Order("importance_score desc, last_seen_at desc").
		Limit(limit).
		Find(&nodes).Error
	return nodes, err
}

func (s *BlackboardService) AddMissingFields(ctx context.Context, taskID uint, findingID uint, fields []string) error {
	_, err := s.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        "hint",
		Title:           "Finding contract requires more evidence",
		Summary:         "Missing evidence fields: " + strings.Join(fields, ", "),
		Content:         map[string]any{"findingId": findingID, "missingFields": fields},
		DedupSeed:       fmt.Sprintf("missing-fields-%d-%s", findingID, strings.Join(fields, ",")),
		ImportanceScore: 0.92,
		SourceType:      "contract",
		SourceID:        fmt.Sprintf("%d", findingID),
	})
	return err
}

func jsonOrEmpty(value any) datatypes.JSON {
	if value == nil {
		return datatypes.JSON([]byte("{}"))
	}
	return mustJSON(value)
}
