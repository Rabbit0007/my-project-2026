package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"shenji/backend/internal/runner"
	"shenji/backend/internal/safety"
)

// CodeProjectIndexTool performs initial project knowledge graph construction.
// Instead of just grepping for dangerous functions, it identifies:
// - Language, framework, entry files, routes
// - API endpoints, controllers, handlers
// - Auth middleware, permission checks
// - Data models, sensitive fields
// - File operations, command execution, template rendering, deserialization
// - Upload/download/export/import/search/login/register/admin interfaces
// Results are written as structured Code Facts to the blackboard.
type CodeProjectIndexTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type codeProjectIndexInput struct {
	TaskID uint   `json:"taskId"`
	Root   string `json:"root"`
}

type ProjectIndex struct {
	Language       string          `json:"language"`
	Framework      string          `json:"framework"`
	EntryFiles     []string        `json:"entry_files"`
	Routes         []RouteInfo     `json:"routes"`
	Controllers    []string        `json:"controllers"`
	AuthMiddleware []string        `json:"auth_middleware"`
	DataModels     []DataModelInfo `json:"data_models"`
	SensitiveOps   []SensitiveOp  `json:"sensitive_ops"`
	Endpoints      []EndpointInfo  `json:"endpoints"`
	FileStructure  []string        `json:"file_structure"`
}

type RouteInfo struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Handler string `json:"handler"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	HasAuth bool   `json:"has_auth"`
}

type DataModelInfo struct {
	Name            string   `json:"name"`
	File            string   `json:"file"`
	SensitiveFields []string `json:"sensitive_fields"`
}

type SensitiveOp struct {
	Type    string `json:"type"` // file_op / command_exec / template_render / deserialize / db_query / http_client / upload / download
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

type EndpointInfo struct {
	Type string `json:"type"` // upload / download / export / import / search / login / register / admin / api
	Path string `json:"path"`
	File string `json:"file"`
}

func NewCodeProjectIndexTool(manager *runner.RunnerManager, timeout time.Duration) *CodeProjectIndexTool {
	return &CodeProjectIndexTool{manager: manager, timeout: timeout}
}

func (t *CodeProjectIndexTool) Name() string { return "code_project_index" }
func (t *CodeProjectIndexTool) Kind() string { return "code_audit" }
func (t *CodeProjectIndexTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Build a project knowledge graph: identify language, framework, routes, auth, data models, sensitive operations, and endpoints. This is the first step of Cairn-style code audit.",
		Properties:  map[string]string{"root": "extracted source root"},
		Required:    []string{"root"},
	}
}

func (t *CodeProjectIndexTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	var parsed codeProjectIndexInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.Root) == "" {
		return fmt.Errorf("root is required")
	}
	return nil
}

func (t *CodeProjectIndexTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed codeProjectIndexInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}

	started := time.Now().UTC()

	// Phase 1: File structure and language detection
	structureResult := t.manager.Run(ctx, runner.RunRequest{
		TaskID:        parsed.TaskID,
		RunnerType:    "code_audit",
		ToolName:      t.Name(),
		ImageName:     "runner-code-audit",
		WorkspacePath: parsed.Root,
		Command: []string{"sh", "-lc", `set -eu
echo '## file_tree'
find . -type f \( -name "*.php" -o -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" -o -name "*.java" -o -name "*.rb" -o -name "*.jsp" -o -name "*.vue" \) | grep -v node_modules | grep -v vendor | grep -v dist | grep -v build | head -200

echo '## routes'
rg -n --no-heading -e "Route\.|router\.|@(Get|Post|Put|Delete|Patch|RequestMapping|app\.(get|post|put|delete))" -e "r\.GET|r\.POST|r\.PUT|r\.DELETE|r\.Group" -e "path\s*=|url\s*=" . 2>/dev/null | grep -v node_modules | grep -v vendor | head -80 || true

echo '## auth_middleware'
rg -n --no-heading -e "(auth|permission|role|token|session|jwt|login|logout|middleware)" -l . 2>/dev/null | grep -v node_modules | grep -v vendor | head -30 || true

echo '## data_models'
rg -n --no-heading -e "(is_admin|role|status|owner_id|user_id|org_id|price|balance|amount|password|secret|token|permission|approved)" . 2>/dev/null | grep -v node_modules | grep -v vendor | grep -v "\.min\." | head -60 || true

echo '## sensitive_ops'
rg -n --no-heading -e "(exec|system|popen|eval|unserialize|readObject|file_get_contents|fopen|include|require|curl_exec|render|template)" . 2>/dev/null | grep -v node_modules | grep -v vendor | grep -v "\.min\." | head -60 || true

echo '## upload_download'
rg -n --no-heading -e "(upload|download|export|import|file_put_contents|move_uploaded_file|multer|formidable|multipart)" . 2>/dev/null | grep -v node_modules | grep -v vendor | head -40 || true

echo '## config_secrets'
rg -n --no-heading -e "(API_KEY|SECRET|PASSWORD|DATABASE_URL|REDIS|MONGO|AWS_|PRIVATE_KEY)" . 2>/dev/null | grep -v node_modules | grep -v vendor | grep -v "\.min\." | head -30 || true
`},
		Timeout:       t.timeout,
		NetworkPolicy: "none",
	})

	// Parse results into structured index
	index := parseProjectIndex(structureResult.Stdout)
	raw, _ := json.MarshalIndent(index, "", "  ")

	summary := fmt.Sprintf("Project index: %s/%s, %d routes, %d controllers, %d sensitive ops, %d endpoints",
		index.Language, index.Framework, len(index.Routes), len(index.Controllers), len(index.SensitiveOps), len(index.Endpoints))

	return &ToolResult{
		StartedAt:   started,
		FinishedAt:  structureResult.FinishedAt,
		Status:      structureResult.Status,
		Summary:     summary,
		Stdout:      string(raw),
		Stderr:      structureResult.Stderr,
		Metadata: map[string]any{
			"index":         index,
			"root":          parsed.Root,
			"image":         structureResult.ImageName,
			"containerId":   structureResult.ContainerID,
			"routeCount":    len(index.Routes),
			"modelCount":    len(index.DataModels),
			"sensitiveOps":  len(index.SensitiveOps),
			"endpointCount": len(index.Endpoints),
		},
		CommandHint: structureResult.CommandPreview,
	}, nil
}

func (t *CodeProjectIndexTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	evidence := []EvidenceDraft{{
		Type:         "tool_output",
		Title:        "Project Knowledge Graph Index",
		Summary:      result.Summary,
		Raw:          result.Stdout,
		RelationType: "baseline",
		Redacted:     false,
	}}
	return evidence, nil
}

func parseProjectIndex(stdout string) ProjectIndex {
	index := ProjectIndex{}
	lines := strings.Split(stdout, "\n")
	section := ""

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimPrefix(line, "## ")
			continue
		}
		if line == "" {
			continue
		}

		switch section {
		case "file_tree":
			index.FileStructure = append(index.FileStructure, line)
			// Detect language/framework from files
			if strings.HasSuffix(line, ".php") {
				index.Language = "PHP"
			} else if strings.HasSuffix(line, ".py") {
				index.Language = "Python"
			} else if strings.HasSuffix(line, ".go") {
				index.Language = "Go"
			} else if strings.HasSuffix(line, ".java") || strings.HasSuffix(line, ".jsp") {
				index.Language = "Java"
			} else if strings.HasSuffix(line, ".js") || strings.HasSuffix(line, ".ts") {
				if index.Language == "" {
					index.Language = "JavaScript"
				}
			}
			// Detect framework
			lower := strings.ToLower(line)
			if strings.Contains(lower, "laravel") || strings.Contains(lower, "artisan") {
				index.Framework = "Laravel"
			} else if strings.Contains(lower, "django") || strings.Contains(lower, "wsgi") {
				index.Framework = "Django"
			} else if strings.Contains(lower, "flask") || strings.Contains(lower, "app.py") {
				index.Framework = "Flask"
			} else if strings.Contains(lower, "express") || strings.Contains(lower, "koa") {
				index.Framework = "Express"
			} else if strings.Contains(lower, "spring") {
				index.Framework = "Spring"
			} else if strings.Contains(lower, "gin") || strings.Contains(lower, "echo") {
				index.Framework = "Go-Web"
			}
			// Entry files
			base := strings.ToLower(line)
			if strings.Contains(base, "index.") || strings.Contains(base, "main.") || strings.Contains(base, "app.") || strings.Contains(base, "server.") {
				index.EntryFiles = append(index.EntryFiles, line)
			}

		case "routes":
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 2 {
				file := strings.TrimPrefix(parts[0], "./")
				index.Controllers = appendUniqueStr(index.Controllers, file)
				lineNo := 0
				fmt.Sscanf(parts[1], "%d", &lineNo)
				index.Routes = append(index.Routes, RouteInfo{File: file, Line: lineNo, Handler: strings.TrimSpace(safeIndex(parts, 2))})
			}

		case "auth_middleware":
			index.AuthMiddleware = append(index.AuthMiddleware, strings.TrimPrefix(line, "./"))

		case "data_models":
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 3 {
				file := strings.TrimPrefix(parts[0], "./")
				snippet := strings.TrimSpace(parts[2])
				// Extract sensitive field names
				for _, field := range []string{"is_admin", "role", "status", "owner_id", "user_id", "org_id", "price", "balance", "amount", "password", "secret", "token", "permission", "approved"} {
					if strings.Contains(strings.ToLower(snippet), field) {
						found := false
						for i := range index.DataModels {
							if index.DataModels[i].File == file {
								index.DataModels[i].SensitiveFields = appendUniqueStr(index.DataModels[i].SensitiveFields, field)
								found = true
								break
							}
						}
						if !found {
							index.DataModels = append(index.DataModels, DataModelInfo{File: file, SensitiveFields: []string{field}})
						}
					}
				}
			}

		case "sensitive_ops":
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 3 {
				file := strings.TrimPrefix(parts[0], "./")
				lineNo := 0
				fmt.Sscanf(parts[1], "%d", &lineNo)
				snippet := strings.TrimSpace(parts[2])
				opType := classifySensitiveOp(snippet)
				index.SensitiveOps = append(index.SensitiveOps, SensitiveOp{Type: opType, File: file, Line: lineNo, Snippet: truncateStr(snippet, 120)})
			}

		case "upload_download":
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 2 {
				file := strings.TrimPrefix(parts[0], "./")
				snippet := strings.ToLower(safeIndex(parts, 2))
				epType := "api"
				if strings.Contains(snippet, "upload") || strings.Contains(snippet, "multipart") {
					epType = "upload"
				} else if strings.Contains(snippet, "download") || strings.Contains(snippet, "export") {
					epType = "download"
				} else if strings.Contains(snippet, "import") {
					epType = "import"
				}
				index.Endpoints = append(index.Endpoints, EndpointInfo{Type: epType, File: file})
			}
		}
	}

	// Truncate large lists
	if len(index.FileStructure) > 50 {
		index.FileStructure = index.FileStructure[:50]
	}
	if len(index.Routes) > 30 {
		index.Routes = index.Routes[:30]
	}
	if len(index.SensitiveOps) > 30 {
		index.SensitiveOps = index.SensitiveOps[:30]
	}

	return index
}

func classifySensitiveOp(snippet string) string {
	lower := strings.ToLower(snippet)
	switch {
	case strings.Contains(lower, "exec") || strings.Contains(lower, "system") || strings.Contains(lower, "popen"):
		return "command_exec"
	case strings.Contains(lower, "unserialize") || strings.Contains(lower, "readobject") || strings.Contains(lower, "pickle"):
		return "deserialize"
	case strings.Contains(lower, "file_get_contents") || strings.Contains(lower, "fopen") || strings.Contains(lower, "include") || strings.Contains(lower, "require"):
		return "file_op"
	case strings.Contains(lower, "render") || strings.Contains(lower, "template"):
		return "template_render"
	case strings.Contains(lower, "curl") || strings.Contains(lower, "http") || strings.Contains(lower, "fetch"):
		return "http_client"
	case strings.Contains(lower, "eval"):
		return "code_eval"
	default:
		return "other"
	}
}

func appendUniqueStr(slice []string, value string) []string {
	for _, s := range slice {
		if s == value {
			return slice
		}
	}
	return append(slice, value)
}

func safeIndex(parts []string, idx int) string {
	if idx < len(parts) {
		return parts[idx]
	}
	return ""
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
