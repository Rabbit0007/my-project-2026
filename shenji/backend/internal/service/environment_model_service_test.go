package service

import (
	"testing"

	"shenji/backend/internal/model"
	"shenji/backend/internal/tools"
)

func TestInferEnvironmentSignalsFromCodeEvidence(t *testing.T) {
	outcome := ToolRunOutcome{
		ToolRun: model.AIToolRun{
			ID:         7,
			RunnerType: "code_audit",
			ToolName:   "code_search",
		},
		Evidence: []model.AIEvidence{
			{FilePath: "app/pom.xml", Summary: "Spring controller source"},
			{FilePath: "deploy/Dockerfile", Summary: "container build"},
			{FilePath: "k8s/deployment.yaml", Summary: "namespace config"},
		},
	}

	signals := inferEnvironmentSignals(outcome)
	if !hasEnvSignal(signals, "runtime_environment", "java") {
		t.Fatalf("expected java runtime signal, got %+v", signals)
	}
	if !hasEnvSignal(signals, "container_runtime", "docker") {
		t.Fatalf("expected docker container signal, got %+v", signals)
	}
	if !hasEnvSignal(signals, "orchestration_layer", "kubernetes") {
		t.Fatalf("expected kubernetes orchestration signal, got %+v", signals)
	}
}

func TestInferEnvironmentSignalsFromFingerprintMetadata(t *testing.T) {
	outcome := ToolRunOutcome{
		ToolRun: model.AIToolRun{
			ID:         8,
			RunnerType: "pentest",
			ToolName:   "fingerprint",
		},
		Result: &tools.ToolResult{
			Summary: "Fingerprint scan identified Apache and PHP",
			Stdout:  `{"components":[{"name":"Apache","category":"server"},{"name":"PHP","category":"language"}]}`,
		},
	}

	signals := inferEnvironmentSignals(outcome)
	if !hasEnvSignal(signals, "deployment_model", "apache") {
		t.Fatalf("expected apache deployment signal, got %+v", signals)
	}
	if !hasEnvSignal(signals, "runtime_environment", "php") {
		t.Fatalf("expected php runtime signal, got %+v", signals)
	}
}

func TestMergeEnvSignalKeepsStrongerConfidence(t *testing.T) {
	doc := map[string]any{}
	if !mergeEnvSignal(doc, envSignal{Field: "runtime_environment", Value: "php", Confidence: model.ConfidenceStrong}) {
		t.Fatal("expected first merge to change doc")
	}
	if mergeEnvSignal(doc, envSignal{Field: "runtime_environment", Value: "php", Confidence: model.ConfidenceSuspected}) {
		t.Fatal("weaker signal should not replace stronger confidence")
	}
	bucket := doc["runtime_environment"].(map[string]any)
	if bucket["php"] != model.ConfidenceStrong {
		t.Fatalf("expected strong confidence, got %v", bucket["php"])
	}
}

func hasEnvSignal(signals []envSignal, field, value string) bool {
	for _, signal := range signals {
		if signal.Field == field && signal.Value == value {
			return true
		}
	}
	return false
}
