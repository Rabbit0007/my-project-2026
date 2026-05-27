package service

import (
	"strings"
	"testing"
)

func TestValidateModelConfigInputRejectsBothPurpose(t *testing.T) {
	err := validateModelConfigInput(ModelConfigUpsertInput{
		Name:     "dual-role",
		Purpose:  "both",
		Provider: "openai-compatible",
		Model:    "gpt-test",
	})
	if err == nil {
		t.Fatal("expected both purpose to be rejected")
	}
	if !strings.Contains(err.Error(), "不能同时") {
		t.Fatalf("expected clear single-role error, got %v", err)
	}
}

func TestValidateModelConfigInputAcceptsSingleRolePurpose(t *testing.T) {
	for _, purpose := range []string{"brain", "worker"} {
		if err := validateModelConfigInput(ModelConfigUpsertInput{
			Name:     purpose + "-model",
			Purpose:  purpose,
			Provider: "openai-compatible",
			Model:    "gpt-test",
		}); err != nil {
			t.Fatalf("expected purpose %s to be accepted, got %v", purpose, err)
		}
	}
}

func TestNormalizeModelProviderTreatsGatewayProvidersAsOpenAICompatible(t *testing.T) {
	for _, provider := range []string{"zhipu", "bailian", "newapi", "oneapi", "openrouter"} {
		if got := normalizeModelProvider(provider); got != "openai-compatible" {
			t.Fatalf("expected %s to normalize to openai-compatible, got %q", provider, got)
		}
	}
	if got := normalizeModelProvider("OpenAI"); got != "openai" {
		t.Fatalf("expected OpenAI to normalize to openai, got %q", got)
	}
}
