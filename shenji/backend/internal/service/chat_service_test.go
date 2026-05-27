package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"shenji/backend/internal/model"
)

func TestChatUsesEnvAPIKeyAndCustomHeaders(t *testing.T) {
	db := newRegressionTestDB(t)
	t.Setenv("RABBIT_TEST_MODEL_KEY", "secret-from-env")
	var gotAuth, gotCustom string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Rabbit-Gateway")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message": map[string]string{"content": "pong"},
			}},
		})
	}))
	defer server.Close()
	config := model.AIModelConfig{
		Name:      "brain",
		Purpose:   model.ModelPurposeBrain,
		Provider:  "openai-compatible",
		BaseURL:   server.URL,
		Model:     "test-model",
		APIKeyRef: "env://RABBIT_TEST_MODEL_KEY",
		Enabled:   true,
		OptionsJSON: mustJSON(map[string]any{
			"customHeaders": map[string]any{"X-Rabbit-Gateway": "enabled"},
		}),
	}
	if err := db.Create(&config).Error; err != nil {
		t.Fatalf("create model config: %v", err)
	}

	reply, err := NewChatService(db).Chat(context.Background(), ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "ping"}}})
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if reply.Reply != "pong" {
		t.Fatalf("unexpected reply %q", reply.Reply)
	}
	if gotAuth != "Bearer secret-from-env" {
		t.Fatalf("expected env api key authorization header, got %q", gotAuth)
	}
	if gotCustom != "enabled" {
		t.Fatalf("expected custom header, got %q", gotCustom)
	}
}

func TestConnectionUsesEnvAPIKeyAndCustomHeaders(t *testing.T) {
	db := newRegressionTestDB(t)
	t.Setenv("RABBIT_TEST_MODEL_KEY", "secret-from-env")
	var gotAuth, gotCustom string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Rabbit-Gateway")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"pong"}}]}`))
	}))
	defer server.Close()
	config := model.AIModelConfig{
		Name:      "brain",
		Purpose:   model.ModelPurposeBrain,
		Provider:  "openai-compatible",
		BaseURL:   server.URL,
		Model:     "test-model",
		APIKeyRef: "env://RABBIT_TEST_MODEL_KEY",
		Enabled:   true,
		OptionsJSON: mustJSON(map[string]any{
			"customHeaders": map[string]any{"X-Rabbit-Gateway": "enabled"},
		}),
	}

	result := NewChatService(db).TestConnection(context.Background(), config)
	if !result.Success {
		t.Fatalf("expected successful test connection, got %+v", result)
	}
	if gotAuth != "Bearer secret-from-env" {
		t.Fatalf("expected env api key authorization header, got %q", gotAuth)
	}
	if gotCustom != "enabled" {
		t.Fatalf("expected custom header, got %q", gotCustom)
	}
}
