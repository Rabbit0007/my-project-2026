package service

import (
	"testing"

	"shenji/backend/internal/model"
)

func TestHypothesisDraftsFromEvidenceMapsSecurityPatterns(t *testing.T) {
	item := model.AIEvidence{
		ID:           12,
		EvidenceType: "code_snippet",
		Title:        "SQL template sink",
		Summary:      "matched dynamic_sql and database_query_sink",
		FilePath:     "app/user.go",
		RelationType: "code_sink",
	}

	drafts := hypothesisDraftsFromEvidence(99, item)
	if len(drafts) == 0 {
		t.Fatal("expected at least one hypothesis draft")
	}
	if drafts[0].HypothesisType != model.HypothesisTypeInjectionCandidate {
		t.Fatalf("expected injection hypothesis, got %s", drafts[0].HypothesisType)
	}
	if drafts[0].ExpectedCapability != model.CapSQLInjection {
		t.Fatalf("expected sql injection capability, got %s", drafts[0].ExpectedCapability)
	}
}

func TestHypothesisDraftsFromEvidenceMapsUploadPattern(t *testing.T) {
	item := model.AIEvidence{
		ID:       13,
		Summary:  "matched file_upload_source and file_upload_sink",
		FilePath: "upload.php",
	}

	drafts := hypothesisDraftsFromEvidence(99, item)
	found := false
	for _, draft := range drafts {
		if draft.HypothesisType == model.HypothesisTypeUploadBypassCandidate && draft.ExpectedCapability == model.CapUploadWrite {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected upload bypass hypothesis, got %+v", drafts)
	}
}
