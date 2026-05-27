package service

import (
	"context"
	"testing"

	"shenji/backend/internal/model"
)

func TestWriteCapabilityDeduplicatesNilHypothesisCapabilities(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, NewFindingService(db), nil, nil, nil, nil)
	draft := CapabilityDraft{
		CapabilityType: model.CapCrossUserObjectAccess,
		Target:         "/objects/1",
		Strength:       model.StrengthObserved,
		ProofSummary:   "Observed a cross-user object access signal.",
		EvidenceIDs:    []uint{1},
	}

	first, err := loop.WriteCapability(ctx, 101, draft, nil)
	if err != nil {
		t.Fatalf("write first capability: %v", err)
	}
	second, err := loop.WriteCapability(ctx, 101, draft, nil)
	if err != nil {
		t.Fatalf("write duplicate capability: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected duplicate write to return existing capability id=%d, got id=%d", first.ID, second.ID)
	}
	var count int64
	if err := db.Model(&model.AICapability{}).Where("task_id = ?", 101).Count(&count).Error; err != nil {
		t.Fatalf("count capabilities: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one deduplicated capability, got %d", count)
	}
}
