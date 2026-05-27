package service

import (
	"context"
	"fmt"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type BlackboardCompactor struct {
	db         *gorm.DB
	blackboard *BlackboardService
}

func NewBlackboardCompactor(db *gorm.DB, blackboard *BlackboardService) *BlackboardCompactor {
	return &BlackboardCompactor{db: db, blackboard: blackboard}
}

func (c *BlackboardCompactor) Compact(ctx context.Context, taskID uint) error {
	var failedIntents int64
	if err := c.db.WithContext(ctx).Model(&model.AIIntent{}).Where("task_id = ? AND status = ?", taskID, model.IntentStatusFailed).Count(&failedIntents).Error; err != nil {
		return err
	}
	if failedIntents > 0 {
		_, err := c.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
			TaskID:          taskID,
			NodeType:        "negative_fact",
			Title:           "Failed exploration attempts summarized",
			Summary:         fmt.Sprintf("%d exploration intents failed or produced no useful evidence.", failedIntents),
			Content:         map[string]any{"failedIntents": failedIntents, "compactedAt": time.Now().UTC()},
			DedupSeed:       "failed-intent-summary",
			ImportanceScore: 0.32,
			SourceType:      "system",
			SourceID:        "blackboard_compactor",
		})
		if err != nil {
			return err
		}
	}
	return nil
}
