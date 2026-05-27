package service

import (
	"context"
	"fmt"
	"time"

	"shenji/backend/internal/model"
	"shenji/backend/internal/storage"
	"shenji/backend/internal/tools"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type EvidenceService struct {
	db    *gorm.DB
	store storage.ArtifactStore
}

func NewEvidenceService(db *gorm.DB, store storage.ArtifactStore) *EvidenceService {
	return &EvidenceService{db: db, store: store}
}

func (s *EvidenceService) CreateFromDraft(ctx context.Context, taskID uint, toolRunID *uint, draft tools.EvidenceDraft) (model.AIEvidence, error) {
	key := fmt.Sprintf("task-%d/evidence/%d-%s.txt", taskID, time.Now().UnixNano(), draft.Type)
	ref, hash, err := s.store.PutText(ctx, key, draft.Raw)
	if err != nil {
		return model.AIEvidence{}, err
	}
	evidence := model.AIEvidence{
		TaskID:           taskID,
		ToolRunID:        toolRunID,
		EvidenceType:     draft.Type,
		Title:            draft.Title,
		Summary:          draft.Summary,
		RawRef:           ref,
		Hash:             hash,
		Target:           draft.Target,
		FilePath:         draft.FilePath,
		LineStart:        draft.LineStart,
		LineEnd:          draft.LineEnd,
		RequestSnapshot:  rawJSON(draft.RequestSnapshot),
		ResponseSnapshot: rawJSON(draft.ResponseSnapshot),
		ArtifactURL:      s.store.PublicURL(ref),
		RelationType:     draft.RelationType,
		Redacted:         draft.Redacted,
		CreatedAt:        time.Now().UTC(),
	}
	return evidence, s.db.WithContext(ctx).Create(&evidence).Error
}

func rawJSON(raw []byte) datatypes.JSON {
	if len(raw) == 0 {
		return datatypes.JSON([]byte("{}"))
	}
	return datatypes.JSON(raw)
}

func (s *EvidenceService) ListByTask(ctx context.Context, taskID uint) ([]model.AIEvidence, error) {
	var evidence []model.AIEvidence
	err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at desc").Find(&evidence).Error
	return evidence, err
}

func (s *EvidenceService) Get(ctx context.Context, id uint) (model.AIEvidence, error) {
	var evidence model.AIEvidence
	err := s.db.WithContext(ctx).First(&evidence, id).Error
	return evidence, err
}
