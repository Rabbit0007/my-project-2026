package tools

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"shenji/backend/internal/safety"
)

type ToolSchema struct {
	Description string            `json:"description"`
	Properties  map[string]string `json:"properties"`
	Required    []string          `json:"required"`
}

type ToolResult struct {
	StartedAt   time.Time         `json:"startedAt"`
	FinishedAt  time.Time         `json:"finishedAt"`
	Status      string            `json:"status"`
	Summary     string            `json:"summary"`
	Stdout      string            `json:"stdout"`
	Stderr      string            `json:"stderr"`
	Artifacts   map[string]string `json:"artifacts"`
	Metadata    map[string]any    `json:"metadata"`
	CommandHint string            `json:"commandHint"`
}

type EvidenceDraft struct {
	Type             string          `json:"type"`
	Title            string          `json:"title"`
	Summary          string          `json:"summary"`
	Raw              string          `json:"raw"`
	Target           string          `json:"target"`
	FilePath         string          `json:"filePath"`
	LineStart        *int            `json:"lineStart"`
	LineEnd          *int            `json:"lineEnd"`
	RequestSnapshot  json.RawMessage `json:"requestSnapshot"`
	ResponseSnapshot json.RawMessage `json:"responseSnapshot"`
	RelationType     string          `json:"relationType"`
	Redacted         bool            `json:"redacted"`
}

type SecurityTool interface {
	Name() string
	Kind() string
	Schema() ToolSchema
	Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error
	Run(ctx context.Context, input json.RawMessage) (*ToolResult, error)
	ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error)
}

type ToolDescriptor struct {
	Name   string     `json:"name"`
	Kind   string     `json:"kind"`
	Schema ToolSchema `json:"schema"`
}

type ToolRegistry struct {
	mu    sync.RWMutex
	tools map[string]SecurityTool
}

func NewRegistry() *ToolRegistry {
	return &ToolRegistry{tools: map[string]SecurityTool{}}
}

func (r *ToolRegistry) Register(tool SecurityTool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.Name()] = tool
}

func (r *ToolRegistry) Get(name string) (SecurityTool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, ok := r.tools[name]
	return tool, ok
}

func (r *ToolRegistry) MustGet(name string) (SecurityTool, error) {
	tool, ok := r.Get(name)
	if !ok {
		return nil, errors.New("tool not registered: " + name)
	}
	return tool, nil
}

func (r *ToolRegistry) List() []ToolDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	descriptors := make([]ToolDescriptor, 0, len(r.tools))
	for _, tool := range r.tools {
		descriptors = append(descriptors, ToolDescriptor{
			Name:   tool.Name(),
			Kind:   tool.Kind(),
			Schema: tool.Schema(),
		})
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Name < descriptors[j].Name
	})
	return descriptors
}
