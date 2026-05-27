package service

import (
	"testing"

	"shenji/backend/internal/model"
)

func TestInferGoalTypeAndModeDefaultsByTaskType(t *testing.T) {
	cases := []struct {
		name     string
		task     model.AISecurityTask
		wantType string
		wantMode string
	}{
		{
			name:     "code audit coverage",
			task:     model.AISecurityTask{TaskType: model.TaskTypeCodeAudit, Objective: "audit this source"},
			wantType: model.GoalTypeCoverage,
			wantMode: model.GoalModeCodeAudit,
		},
		{
			name:     "web pentest coverage",
			task:     model.AISecurityTask{TaskType: model.TaskTypePentest, Objective: "test authorized web app"},
			wantType: model.GoalTypeCoverage,
			wantMode: model.GoalModeWebPentest,
		},
		{
			name:     "internal pentest expansion",
			task:     model.AISecurityTask{TaskType: model.TaskTypeInternalPentest, Objective: "expand inside authorized network"},
			wantType: model.GoalTypeExpansion,
			wantMode: model.GoalModeInternal,
		},
		{
			name:     "terminal proof explicit",
			task:     model.AISecurityTask{TaskType: model.TaskTypeHybrid, Objective: "prove admin access is reachable"},
			wantType: model.GoalTypeTerminal,
			wantMode: model.GoalModeTerminalProof,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotMode := inferGoalTypeAndMode(tc.task)
			if gotType != tc.wantType || gotMode != tc.wantMode {
				t.Fatalf("expected %s/%s, got %s/%s", tc.wantType, tc.wantMode, gotType, gotMode)
			}
		})
	}
}

func TestHypothesisPatternKeyNormalizesParts(t *testing.T) {
	got := hypothesisPatternKey(" FILE_READ_CANDIDATE ", " /etc/passwd ", " Test Path ")
	want := "file_read_candidate|/etc/passwd|test path"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
