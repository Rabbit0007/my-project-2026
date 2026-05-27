package service

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"gorm.io/gorm"
)

type envSignal struct {
	Field      string
	Value      string
	Confidence string
	SourceRef  string
}

var envConfidenceRank = map[string]int{
	model.ConfidenceSuspected: 1,
	model.ConfidencePlausible: 2,
	model.ConfidenceStrong:    3,
	model.ConfidenceValidated: 4,
}

func (s *HypothesisLifecycleService) UpdateEnvironmentFromOutcome(ctx context.Context, taskID uint, outcome ToolRunOutcome) error {
	signals := inferEnvironmentSignals(outcome)
	if len(signals) == 0 {
		return nil
	}
	return s.MergeEnvironmentSignals(ctx, taskID, fmt.Sprintf("toolrun-%d", outcome.ToolRun.ID), signals)
}

func (s *HypothesisLifecycleService) MergeEnvironmentSignals(ctx context.Context, taskID uint, updatedFrom string, signals []envSignal) error {
	if len(signals) == 0 {
		return nil
	}
	doc := map[string]any{}
	var existing model.AIEnvironmentModel
	err := s.db.WithContext(ctx).Where("task_id = ?", taskID).First(&existing).Error
	if err == nil && len(existing.ModelJSON) > 0 {
		_ = json.Unmarshal(existing.ModelJSON, &doc)
	} else if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	changed := false
	for _, signal := range signals {
		if mergeEnvSignal(doc, signal) {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	doc["updated_at"] = time.Now().UTC().Format(time.RFC3339)
	doc["updated_from"] = updatedFrom
	raw := mustJSON(doc)
	now := time.Now().UTC()
	if existing.ID == 0 {
		existing = model.AIEnvironmentModel{
			TaskID:      taskID,
			ModelJSON:   raw,
			UpdatedFrom: updatedFrom,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.db.WithContext(ctx).Create(&existing).Error; err != nil {
			return err
		}
	} else {
		if err := s.db.WithContext(ctx).Model(&model.AIEnvironmentModel{}).Where("id = ?", existing.ID).Updates(map[string]any{
			"model_json":   raw,
			"updated_from": updatedFrom,
			"updated_at":   now,
		}).Error; err != nil {
			return err
		}
		existing.ModelJSON = raw
		existing.UpdatedFrom = updatedFrom
		existing.UpdatedAt = now
	}
	_, _ = s.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
		TaskID:          taskID,
		NodeType:        model.NodeEnvironmentModel,
		Title:           "Environment model",
		Summary:         summarizeEnvironmentModel(doc),
		Content:         existing,
		DedupSeed:       "environment-model",
		ImportanceScore: 0.88,
		SourceType:      "hypothesis-lifecycle",
		SourceID:        updatedFrom,
	})
	appendAuditEvent(ctx, s.db, &taskID, "environment_model.updated", "hypothesis-lifecycle", summarizeEnvironmentModel(doc), map[string]any{"updatedFrom": updatedFrom, "signals": signals})
	return nil
}

func inferEnvironmentSignals(outcome ToolRunOutcome) []envSignal {
	source := fmt.Sprintf("toolrun:%d", outcome.ToolRun.ID)
	chunks := []string{
		outcome.ToolRun.ToolName,
		outcome.ToolRun.RunnerType,
		outcome.ToolRun.CommandPreview,
		outcome.ToolRun.ImageName,
		outcome.ToolRun.WorkspacePath,
	}
	if outcome.Result != nil {
		chunks = append(chunks, outcome.Result.Summary, truncateForInference(outcome.Result.Stdout), truncateForInference(outcome.Result.Stderr))
		rawMeta, _ := json.Marshal(outcome.Result.Metadata)
		chunks = append(chunks, string(rawMeta))
	}
	for _, item := range outcome.Evidence {
		chunks = append(chunks, item.Title, item.Summary, item.Target, item.FilePath, item.RelationType)
	}
	text := strings.ToLower(strings.Join(chunks, "\n"))
	signals := []envSignal{}
	add := func(field, value, confidence string) {
		signals = append(signals, envSignal{Field: field, Value: value, Confidence: confidence, SourceRef: source})
	}

	switch outcome.ToolRun.RunnerType {
	case "code_audit":
		add("runtime_environment", "source_code", model.ConfidenceStrong)
	case "pentest", "http":
		add("network_zone", "external_web", model.ConfidencePlausible)
	}
	switch outcome.ToolRun.ToolName {
	case "fingerprint":
		add("deployment_model", "fingerprinted_service", model.ConfidenceStrong)
	case "http_request", "http_surface", "pentest_probe":
		add("deployment_model", "web_application", model.ConfidencePlausible)
	}

	inferTextSignals(text, add)
	for _, item := range outcome.Evidence {
		inferPathSignals(item.FilePath, add)
	}
	return dedupeEnvSignals(signals)
}

func inferTextSignals(text string, add func(field, value, confidence string)) {
	hints := []struct {
		Needles    []string
		Field      string
		Value      string
		Confidence string
	}{
		{[]string{"spring boot", "spring_boot", "springframework", "pom.xml"}, "framework_stack", "spring_boot", model.ConfidenceStrong},
		{[]string{"laravel", "artisan"}, "framework_stack", "laravel", model.ConfidenceStrong},
		{[]string{"thinkphp"}, "framework_stack", "thinkphp", model.ConfidenceStrong},
		{[]string{"express", "koa", "nestjs"}, "framework_stack", "node_web", model.ConfidencePlausible},
		{[]string{"vue", "react", "angular"}, "framework_stack", "spa_frontend", model.ConfidencePlausible},
		{[]string{"php", "$_get", "$_post", "$_request"}, "runtime_environment", "php", model.ConfidenceStrong},
		{[]string{"node.js", "nodejs", "package.json", "npm"}, "runtime_environment", "nodejs", model.ConfidenceStrong},
		{[]string{"java", "maven", "gradle"}, "runtime_environment", "java", model.ConfidencePlausible},
		{[]string{"go.mod", "golang"}, "runtime_environment", "go", model.ConfidenceStrong},
		{[]string{"python", "requirements.txt", "django", "flask"}, "runtime_environment", "python", model.ConfidencePlausible},
		{[]string{"nginx", "nginx.conf"}, "deployment_model", "nginx", model.ConfidenceStrong},
		{[]string{"apache", "httpd"}, "deployment_model", "apache", model.ConfidenceStrong},
		{[]string{"dockerfile", "docker-compose", "containerid"}, "container_runtime", "docker", model.ConfidenceStrong},
		{[]string{"kubernetes", "serviceaccount", "k8s", "namespace", "apiserver"}, "orchestration_layer", "kubernetes", model.ConfidenceStrong},
		{[]string{"aws_access_key", "amazonaws", "s3.amazonaws"}, "cloud_provider", "aws", model.ConfidencePlausible},
		{[]string{"azure", "blob.core.windows.net"}, "cloud_provider", "azure", model.ConfidencePlausible},
		{[]string{"googleapis", "gcp", "metadata.google.internal"}, "cloud_provider", "gcp", model.ConfidencePlausible},
		{[]string{"jwt", "bearer ", "authorization:"}, "authentication_mechanism", "token_auth", model.ConfidencePlausible},
		{[]string{"set-cookie", "sessionid", "jsessionid", "phpsessid"}, "session_model", "cookie_session", model.ConfidencePlausible},
		{[]string{"active directory", "ldap", "kerberos", "windows domain"}, "identity_model", "windows_ad", model.ConfidencePlausible},
	}
	for _, hint := range hints {
		for _, needle := range hint.Needles {
			if strings.Contains(text, needle) {
				add(hint.Field, hint.Value, hint.Confidence)
				break
			}
		}
	}
}

func inferPathSignals(path string, add func(field, value, confidence string)) {
	if strings.TrimSpace(path) == "" {
		return
	}
	lower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	ext := strings.ToLower(filepath.Ext(lower))
	switch ext {
	case ".php":
		add("runtime_environment", "php", model.ConfidenceStrong)
	case ".js", ".ts", ".mjs", ".cjs":
		add("runtime_environment", "nodejs", model.ConfidencePlausible)
	case ".java", ".jsp":
		add("runtime_environment", "java", model.ConfidenceStrong)
	case ".go":
		add("runtime_environment", "go", model.ConfidenceStrong)
	case ".py":
		add("runtime_environment", "python", model.ConfidenceStrong)
	}
	switch {
	case strings.HasSuffix(lower, "package.json"):
		add("runtime_environment", "nodejs", model.ConfidenceStrong)
	case strings.HasSuffix(lower, "pom.xml") || strings.HasSuffix(lower, "build.gradle"):
		add("runtime_environment", "java", model.ConfidenceStrong)
		add("framework_stack", "spring_boot", model.ConfidencePlausible)
	case strings.Contains(lower, "dockerfile") || strings.Contains(lower, "docker-compose"):
		add("container_runtime", "docker", model.ConfidenceStrong)
	case strings.Contains(lower, "nginx.conf"):
		add("deployment_model", "nginx", model.ConfidenceStrong)
	case strings.Contains(lower, "k8s") || strings.Contains(lower, "kubernetes") || strings.Contains(lower, "deployment.yaml"):
		add("orchestration_layer", "kubernetes", model.ConfidencePlausible)
	}
}

func mergeEnvSignal(doc map[string]any, signal envSignal) bool {
	field := strings.TrimSpace(signal.Field)
	value := strings.TrimSpace(signal.Value)
	confidence := strings.TrimSpace(signal.Confidence)
	if field == "" || value == "" {
		return false
	}
	if confidence == "" {
		confidence = model.ConfidenceSuspected
	}
	bucket := map[string]any{}
	if existing, ok := doc[field].(map[string]any); ok {
		bucket = existing
	}
	current, _ := bucket[value].(string)
	if envConfidenceRank[confidence] <= envConfidenceRank[current] {
		return false
	}
	bucket[value] = confidence
	doc[field] = bucket
	return true
}

func summarizeEnvironmentModel(doc map[string]any) string {
	parts := []string{}
	for _, field := range []string{"runtime_environment", "deployment_model", "framework_stack", "cloud_provider", "identity_model", "network_zone", "execution_context", "container_runtime", "orchestration_layer", "authentication_mechanism", "session_model"} {
		bucket, ok := doc[field].(map[string]any)
		if !ok || len(bucket) == 0 {
			continue
		}
		values := []string{}
		for value, confidence := range bucket {
			values = append(values, fmt.Sprintf("%s=%v", value, confidence))
		}
		parts = append(parts, field+": "+strings.Join(values, ", "))
	}
	if len(parts) == 0 {
		return "Environment model updated with low-confidence observations."
	}
	if len(parts) > 4 {
		parts = parts[:4]
	}
	return strings.Join(parts, " | ")
}

func truncateForInference(text string) string {
	if len(text) <= 16000 {
		return text
	}
	return text[:16000]
}

func dedupeEnvSignals(signals []envSignal) []envSignal {
	best := map[string]envSignal{}
	for _, signal := range signals {
		key := signal.Field + "|" + signal.Value
		if existing, ok := best[key]; ok && envConfidenceRank[existing.Confidence] >= envConfidenceRank[signal.Confidence] {
			continue
		}
		best[key] = signal
	}
	out := make([]envSignal, 0, len(best))
	for _, signal := range best {
		out = append(out, signal)
	}
	return out
}
