package model

import (
	"strings"
	"testing"
)

func TestValidationIntentMetadataRoundTripPreservesExistingConstraints(t *testing.T) {
	hypothesisID := uint(42)
	intent := AIIntent{
		ConstraintsJSON: JSONValue(map[string]any{
			"policy": "authorized_only",
		}),
	}

	intent.WithValidationMetadata(ValidationIntentMetadata{
		HypothesisID:       &hypothesisID,
		ValidationMethod:   "marker_probe",
		ExpectedEvidence:   "response diff",
		ExpectedCapability: CapAuthenticatedSession,
		SuccessCondition:   "marker changes authorized response",
		FailureCondition:   "no behavioral difference",
		SafetyLevel:        "authorized_non_destructive",
		EnvironmentContextSnapshot: map[string]any{
			"runtime_environment": "linux",
		},
	})

	meta := intent.ValidationMetadata()
	if meta.HypothesisID == nil || *meta.HypothesisID != hypothesisID {
		t.Fatalf("expected hypothesis id %d, got %+v", hypothesisID, meta.HypothesisID)
	}
	if meta.ExpectedCapability != CapAuthenticatedSession {
		t.Fatalf("expected capability %s, got %s", CapAuthenticatedSession, meta.ExpectedCapability)
	}
	if meta.ValidationMethod != "marker_probe" {
		t.Fatalf("expected validation method marker_probe, got %s", meta.ValidationMethod)
	}
	if got := string(intent.ConstraintsJSON); got == "" || !strings.Contains(got, "authorized_only") {
		t.Fatalf("expected existing policy constraint to be preserved, got %s", got)
	}
}

func TestValidationMetadataReadsLegacyCriteriaNames(t *testing.T) {
	intent := AIIntent{
		ConstraintsJSON: JSONValue(map[string]any{
			"success_criteria": "legacy success",
			"failure_criteria": "legacy failure",
		}),
	}

	meta := intent.ValidationMetadata()
	if meta.SuccessCondition != "legacy success" {
		t.Fatalf("expected legacy success criteria, got %q", meta.SuccessCondition)
	}
	if meta.FailureCondition != "legacy failure" {
		t.Fatalf("expected legacy failure criteria, got %q", meta.FailureCondition)
	}
}

func TestBranchValueRoundTripPreservesValidationMetadata(t *testing.T) {
	hypothesisID := uint(88)
	intent := AIIntent{}
	intent.WithValidationMetadata(ValidationIntentMetadata{
		HypothesisID:       &hypothesisID,
		ValidationMethod:   "http_validation",
		ExpectedCapability: CapFileRead,
	})

	branch := BranchValue{
		CapabilityUnlockScore:  0.8,
		GraphExpansionScore:    0.7,
		NoveltyScore:           0.6,
		RiskValue:              0.9,
		CoverageGain:           0.2,
		FinalScore:             0.74,
		Reason:                 "high capability gain",
		NegativeFactRefs:       []uint{7},
		MatchedEnvironmentRefs: []string{"runtime_environment.php=strong"},
	}
	if err := intent.WithBranchValue(branch); err != nil {
		t.Fatalf("unexpected branch value write error: %v", err)
	}

	got, err := intent.BranchValue()
	if err != nil {
		t.Fatalf("unexpected branch value read error: %v", err)
	}
	if got == nil || got.FinalScore != branch.FinalScore {
		t.Fatalf("expected branch final score %f, got %+v", branch.FinalScore, got)
	}
	meta := intent.ValidationMetadata()
	if meta.HypothesisID == nil || *meta.HypothesisID != hypothesisID {
		t.Fatalf("expected validation metadata to survive branch write, got %+v", meta)
	}
	if meta.ExpectedCapability != CapFileRead {
		t.Fatalf("expected expected capability to survive, got %s", meta.ExpectedCapability)
	}
}

func TestBranchValueMissingReturnsNil(t *testing.T) {
	intent := AIIntent{ConstraintsJSON: JSONValue(map[string]any{"policy": "authorized"})}
	got, err := intent.BranchValue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected missing branch value to return nil, got %+v", got)
	}
}

func TestValidationMetadataWritePreservesBranchValueAndOtherConstraints(t *testing.T) {
	intent := AIIntent{ConstraintsJSON: JSONValue(map[string]any{"policy": "authorized_only"})}
	branch := BranchValue{
		CapabilityUnlockScore: 0.9,
		FinalScore:            0.81,
		Reason:                "high capability gain",
	}
	if err := intent.WithBranchValue(branch); err != nil {
		t.Fatalf("unexpected branch value write error: %v", err)
	}
	hypothesisID := uint(91)
	intent.WithValidationMetadata(ValidationIntentMetadata{
		HypothesisID:       &hypothesisID,
		ExpectedCapability: CapCommandExecution,
	})

	got, err := intent.BranchValue()
	if err != nil {
		t.Fatalf("unexpected branch value read error: %v", err)
	}
	if got == nil || got.FinalScore != branch.FinalScore {
		t.Fatalf("expected branch value to survive validation metadata write, got %+v", got)
	}
	if meta := intent.ValidationMetadata(); meta.HypothesisID == nil || *meta.HypothesisID != hypothesisID {
		t.Fatalf("expected validation metadata to be written, got %+v", meta)
	}
	if raw := string(intent.ConstraintsJSON); !strings.Contains(raw, "authorized_only") {
		t.Fatalf("expected existing constraint to survive, got %s", raw)
	}
}
