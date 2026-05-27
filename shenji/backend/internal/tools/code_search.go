package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"shenji/backend/internal/runner"
	"shenji/backend/internal/safety"
)

type CodeSearchTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type codeSearchInput struct {
	TaskID   uint     `json:"taskId"`
	Root     string   `json:"root"`
	Patterns []string `json:"patterns"`
	MaxHits  int      `json:"maxHits"`
}

type codeSearchHit struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Pattern string `json:"pattern"`
	Snippet string `json:"snippet"`
}

func NewCodeSearchTool(manager *runner.RunnerManager, timeout time.Duration) *CodeSearchTool {
	return &CodeSearchTool{manager: manager, timeout: timeout}
}

func (t CodeSearchTool) Name() string { return "code_search" }
func (t CodeSearchTool) Kind() string { return "code_audit" }
func (t CodeSearchTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Search source code for source/sink/security-relevant patterns inside an extracted workspace.",
		Properties:  map[string]string{"root": "extracted source root", "patterns": "regex patterns", "maxHits": "maximum findings"},
		Required:    []string{"root"},
	}
}

func (t CodeSearchTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	_ = ctx
	_ = policy
	var parsed codeSearchInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.Root) == "" {
		return fmt.Errorf("root is required")
	}
	return nil
}

func (t CodeSearchTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed codeSearchInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}
	patterns := parsed.Patterns
	if len(patterns) == 0 {
		patterns = []string{
			`(?i)\b(exec\.Command|exec\.CommandContext|Runtime\.getRuntime\s*\(\)\.exec|ProcessBuilder|shell_exec|passthru|proc_open|pcntl_exec|popen|system|eval|assert|preg_replace)\s*\(`,
			`(?i)\b(move_uploaded_file|is_uploaded_file)\s*\(`,
			`(?i)\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[`,
			`(?i)\$_(?:POST|GET|REQUEST|COOKIE|FILES|SERVER)\s*\[\s*['"][A-Za-z0-9_.-]{1,80}['"]\s*\]`,
			`(?i)\b(ctx\.request|req\.query|req\.body|req\.params|request\.query|request\.body|request\.params|params?\s*\[|body\s*\[|query\s*\[|getParameter|param\s*\(|input\s*\(|request\s*\()`,
			`(?i)\b(pathinfo|strrchr|substr|explode|end|getimagesize|exif_imagetype|mime_content_type|finfo_file|in_array|strtolower|str_ireplace|preg_match)\s*\(`,
			`(?i)\b(rename|copy|file_put_contents)\s*\(.*(\$_FILES|\$_POST|UPLOAD_PATH|upload|tmp_name|save_name)`,
			`(?i)\b(unserialize|readObject|ObjectInputStream|pickle\.loads|yaml\.load)\s*\(`,
			`(?i)\b(SELECT|UPDATE|DELETE|INSERT|REPLACE)\b.*(\.|\+|sprintf|fmt\.Sprintf|\$\{|%s|request|param|getParameter|_GET|_POST|_REQUEST|ctx\.|req\.|body|query)`,
			`(?i)\b(mysql_query|mysqli_query|queryLong|queryOne|queryAll|query|prepareStatement|createQuery|rawQuery|execute|exec)\s*\(.*(\.|\+|\$\{|%s|request|param|getParameter|_GET|_POST|_REQUEST|ctx\.|req\.|body|query)`,
			`(?i)\b(getSQLWhere|check[A-Za-z0-9_]*Unique|[A-Za-z0-9_]*Unique|where\s*\+=|sql\s*\+=|sql\s*=|sqlstr|querysql)\b`,
			`(?i)\b(file_get_contents|fopen|readFile|Files\.read|Path\.of|open)\s*\(.*(_GET|_POST|request|param|getParameter)`,
			`(?i)\b(include|include_once|require|require_once)\s*\(.*(\$_GET|\$_POST|\$_REQUEST|request|param|getParameter|file|path)`,
			`(?i)\b(curl_exec|curl_setopt|http_get|requests\.(get|post)|axios\.|fetch\s*\(|HttpClient|URL\s*\(|openConnection)\b`,
			`(?i)\b(header\s*\(\s*['"]Location:|sendRedirect|redirect\s*\(|Response\.Redirect|res\.redirect)\b`,
			`(?i)\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|simplexml_load|simplexml_load_string|DOMDocument)\b`,
			`(?i)\b(md5|sha1)\s*\(.*(password|passwd|pwd|token|secret|key)`,
		}
	}
	maxHits := parsed.MaxHits
	if maxHits <= 0 {
		maxHits = 120
	}
	if maxHits > 5000 {
		maxHits = 5000
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, re)
	}

	args := []string{"-n", "-H", "--no-heading"}
	for _, pattern := range patterns {
		args = append(args, "-e", pattern)
	}
	for _, glob := range codeSearchExcludeGlobs() {
		args = append(args, "-g", "!"+glob)
	}
	args = append(args, ".")
	started := time.Now().UTC()
	runResult := t.manager.Run(ctx, runner.RunRequest{
		TaskID:        parsed.TaskID,
		RunnerType:    "code_audit",
		ToolName:      t.Name(),
		ImageName:     "runner-code-audit",
		WorkspacePath: parsed.Root,
		Command:       append([]string{"rg"}, args...),
		Timeout:       t.timeout,
		NetworkPolicy: "none",
	})
	hits := []codeSearchHit{}
	seen := map[string]struct{}{}
	categoryCounts := map[string]int{}
	fileCounts := map[string]int{}
	perCategoryLimit := maxInt(80, maxHits/4)
	perFileLimit := maxInt(16, maxHits/60)
	for _, line := range strings.Split(runResult.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		fileName := strings.TrimPrefix(parts[0], "./")
		if !isAuditableSourcePath(fileName) {
			continue
		}
		lineNo := 0
		_, _ = fmt.Sscanf(parts[1], "%d", &lineNo)
		snippet := strings.TrimSpace(parts[2])
		pattern := "security-pattern"
		for _, re := range compiled {
			if re.MatchString(snippet) {
				pattern = codeSearchPatternLabel(re.String())
				break
			}
		}
		if categoryCounts[pattern] >= perCategoryLimit {
			continue
		}
		if isLowValueLibraryPath(fileName) && codeSearchPatternPriority(pattern) < 70 {
			continue
		}
		if fileCounts[fileName] >= perFileLimit && codeSearchPathScore(fileName) < 80 {
			continue
		}
		key := fmt.Sprintf("%s:%d:%s", fileName, lineNo, pattern)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		categoryCounts[pattern]++
		fileCounts[fileName]++
		if len(hits) < maxHits {
			hits = append(hits, codeSearchHit{
				File:    fileName,
				Line:    lineNo,
				Pattern: pattern,
				Snippet: snippet,
			})
			continue
		}
		if shouldPreferCodeSearchHit(hits, pattern) {
			hits = replaceLowestPriorityHit(hits, codeSearchHit{
				File:    fileName,
				Line:    lineNo,
				Pattern: pattern,
				Snippet: snippet,
			})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		left := codeSearchHitPriority(hits[i])
		right := codeSearchHitPriority(hits[j])
		if left == right {
			if hits[i].File == hits[j].File {
				return hits[i].Line < hits[j].Line
			}
			return hits[i].File < hits[j].File
		}
		return left > right
	})
	raw, _ := json.MarshalIndent(hits, "", "  ")
	return &ToolResult{
		StartedAt:   started,
		FinishedAt:  runResult.FinishedAt,
		Status:      runResult.Status,
		Summary:     fmt.Sprintf("Code search found %d security-relevant source/sink candidates", len(hits)),
		Stdout:      string(raw),
		Stderr:      runResult.Stderr,
		Metadata:    map[string]any{"hits": hits, "root": parsed.Root, "image": runResult.ImageName, "containerId": runResult.ContainerID, "workspacePath": parsed.Root},
		CommandHint: runResult.CommandPreview,
	}, nil
}

func shouldPreferCodeSearchHit(existing []codeSearchHit, pattern string) bool {
	incoming := codeSearchPatternPriority(pattern)
	for _, item := range existing {
		if codeSearchPatternPriority(item.Pattern) < incoming {
			return true
		}
	}
	return false
}

func codeSearchHitPriority(hit codeSearchHit) int {
	return codeSearchPatternPriority(hit.Pattern) + codeSearchPathScore(hit.File)
}

func replaceLowestPriorityHit(existing []codeSearchHit, incoming codeSearchHit) []codeSearchHit {
	if len(existing) == 0 {
		return existing
	}
	replaceAt := 0
	lowest := codeSearchPatternPriority(existing[0].Pattern)
	for i := 1; i < len(existing); i++ {
		priority := codeSearchPatternPriority(existing[i].Pattern)
		if priority < lowest {
			lowest = priority
			replaceAt = i
		}
	}
	if codeSearchPatternPriority(incoming.Pattern) > lowest {
		existing[replaceAt] = incoming
	}
	return existing
}

func codeSearchPatternPriority(pattern string) int {
	lower := strings.ToLower(pattern)
	switch {
	case strings.Contains(lower, "dynamic_code_execution"):
		return 100
	case strings.Contains(lower, "sql_template") || strings.Contains(lower, "dynamic_sql") || strings.Contains(lower, "unique_check"):
		return 94
	case strings.Contains(lower, "file_upload_sink"):
		return 90
	case strings.Contains(lower, "file_upload_user_controlled_name"):
		return 86
	case strings.Contains(lower, "file_upload_source"):
		return 84
	case strings.Contains(lower, "file_write_sink"):
		return 82
	case strings.Contains(lower, "file_upload_validation_check"):
		return 78
	case strings.Contains(lower, "deserialization"):
		return 76
	case strings.Contains(lower, "database_query"):
		return 88
	case strings.Contains(lower, "file_read"):
		return 72
	case strings.Contains(lower, "file_include"):
		return 70
	case strings.Contains(lower, "ssrf") || strings.Contains(lower, "outbound_request"):
		return 68
	case strings.Contains(lower, "open_redirect"):
		return 62
	case strings.Contains(lower, "xxe"):
		return 60
	case strings.Contains(lower, "weak_crypto"):
		return 40
	case strings.Contains(lower, "input_source"):
		return 58
	default:
		return 10
	}
}

func codeSearchPatternLabel(pattern string) string {
	lower := strings.ToLower(pattern)
	switch {
	case strings.Contains(lower, "getsqlwhere"):
		return "dynamic_sql_builder(getSQLWhere/where concat)"
	case strings.Contains(lower, "check[a-za-z0-9_]*unique") || strings.Contains(lower, "unique"):
		return "unique_check_endpoint(candidate)"
	case strings.Contains(lower, "move_uploaded_file") || strings.Contains(lower, "is_uploaded_file"):
		return "file_upload_sink(move_uploaded_file/is_uploaded_file)"
	case strings.Contains(lower, "$_files"):
		return "file_upload_source($_FILES)"
	case strings.Contains(lower, "$_(") || strings.Contains(lower, "$_(?:get") || strings.Contains(lower, "$_get") || strings.Contains(lower, "$_request") || strings.Contains(lower, "$_cookie"):
		return "input_source(superglobal/request)"
	case strings.Contains(lower, "save_name") || strings.Contains(lower, "$_post"):
		return "file_upload_user_controlled_name($_POST)"
	case strings.Contains(lower, "getimagesize") || strings.Contains(lower, "mime_content_type") || strings.Contains(lower, "pathinfo") || strings.Contains(lower, "in_array"):
		return "file_upload_validation_check(extension/mime)"
	case strings.Contains(lower, "rename") || strings.Contains(lower, "copy") || strings.Contains(lower, "file_put_contents"):
		return "file_write_sink(rename/copy/file_put_contents)"
	case strings.Contains(lower, "eval") || strings.Contains(lower, "system") || strings.Contains(lower, "shell_exec"):
		return "dynamic_code_execution_sink(eval/system/exec)"
	case strings.Contains(lower, "unserialize") || strings.Contains(lower, "readobject"):
		return "deserialization_sink"
	case strings.Contains(lower, "${") && (strings.Contains(lower, "select") || strings.Contains(lower, "update") || strings.Contains(lower, "delete") || strings.Contains(lower, "insert")):
		return "sql_template_interpolation_sink"
	case strings.Contains(lower, "select") || strings.Contains(lower, "query"):
		return "database_query_sink"
	case strings.Contains(lower, "file_get_contents") || strings.Contains(lower, "fopen"):
		return "file_read_sink"
	case strings.Contains(lower, "include") || strings.Contains(lower, "require"):
		return "file_include_sink"
	case strings.Contains(lower, "curl_exec") || strings.Contains(lower, "curl_setopt") || strings.Contains(lower, "requests") || strings.Contains(lower, "fetch") || strings.Contains(lower, "openconnection"):
		return "outbound_request_sink(ssrf)"
	case strings.Contains(lower, "location:") || strings.Contains(lower, "redirect"):
		return "open_redirect_sink"
	case strings.Contains(lower, "documentbuilderfactory") || strings.Contains(lower, "simplexml") || strings.Contains(lower, "domdocument") || strings.Contains(lower, "xmlinputfactory"):
		return "xxe_parser_sink"
	case strings.Contains(lower, "md5") || strings.Contains(lower, "sha1"):
		return "weak_crypto"
	default:
		return "security-pattern"
	}
}

func (t CodeSearchTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	_ = ctx
	var hits []struct {
		File    string `json:"file"`
		Line    int    `json:"line"`
		Pattern string `json:"pattern"`
		Snippet string `json:"snippet"`
	}
	_ = json.Unmarshal([]byte(result.Stdout), &hits)
	evidence := make([]EvidenceDraft, 0, len(hits))
	for _, h := range hits {
		line := h.Line
		evidence = append(evidence, EvidenceDraft{
			Type:         "code_snippet",
			Title:        "Security-relevant code candidate",
			Summary:      fmt.Sprintf("%s:%d matched %s", h.File, h.Line, h.Pattern),
			Raw:          safety.RedactSensitive(h.Snippet),
			FilePath:     h.File,
			LineStart:    &line,
			LineEnd:      &line,
			RelationType: "code_sink",
			Redacted:     true,
		})
	}
	if len(evidence) == 0 {
		evidence = append(evidence, EvidenceDraft{
			Type:         "tool_output",
			Title:        "Code search completed",
			Summary:      result.Summary,
			Raw:          result.Stdout,
			RelationType: "baseline",
			Redacted:     true,
		})
	}
	return evidence, nil
}

func codeSearchExcludeGlobs() []string {
	return []string{
		"**/.git/**",
		"**/node_modules/**",
		"**/vendor/**",
		"**/dist/**",
		"**/build/**",
		"**/coverage/**",
		"**/public/h5dw/report/**",
		"**/public/designer/static/**",
		"**/myapp/libs/**",
		"**/libs/**",
		"**/upload-labs-env*/**",
		"**/Apache/**",
		"**/PHP/**",
		"**/php.ini*",
		"**/*.min.js",
		"**/*.map",
		"**/*.jpg",
		"**/*.jpeg",
		"**/*.png",
		"**/*.gif",
		"**/*.exe",
		"**/*.dll",
		"**/*.rar",
		"**/*.zip",
		"**/*.log",
	}
}

func isAuditableSourcePath(path string) bool {
	normalized := strings.ReplaceAll(path, "\\", "/")
	lower := strings.ToLower(normalized)
	if strings.Contains(lower, "/upload-labs-env") ||
		strings.Contains(lower, "/apache/") ||
		strings.Contains(lower, "/php/") ||
		strings.Contains(lower, "/node_modules/") ||
		strings.Contains(lower, "/vendor/") ||
		strings.Contains(lower, "/public/h5dw/report/") ||
		strings.Contains(lower, "/public/designer/static/") ||
		strings.Contains(lower, "/myapp/libs/") ||
		strings.Contains(lower, "/libs/") ||
		strings.Contains(lower, "/dist/") ||
		strings.Contains(lower, "/build/") {
		return false
	}
	base := strings.ToLower(filepath.Base(lower))
	if strings.HasSuffix(base, ".min.js") || strings.HasPrefix(base, "jquery") || strings.HasPrefix(base, "prism") || strings.HasPrefix(base, "php.ini") ||
		strings.Contains(base, ".bundle.") || strings.Contains(base, "bundle.js") || strings.Contains(base, "echarts") || strings.Contains(base, "jspdf") || strings.Contains(base, "mui") || strings.Contains(base, "pinyin") {
		return false
	}
	switch filepath.Ext(lower) {
	case ".go", ".java", ".kt", ".js", ".ts", ".jsx", ".tsx", ".php", ".py", ".rb", ".cs", ".xml", ".jsp", ".vue":
		return true
	default:
		return false
	}
}

func codeSearchPathScore(path string) int {
	lower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	score := 0
	if strings.Contains(lower, "/server/plugins/") || strings.Contains(lower, "/satweb/") || strings.Contains(lower, "/erp/") || strings.Contains(lower, "/api/") || strings.Contains(lower, "/controller") || strings.Contains(lower, "/routes/") {
		score += 90
	}
	if strings.HasSuffix(lower, "/user.js") || strings.HasSuffix(lower, "/app.js") || strings.HasSuffix(lower, "/erp.js") || strings.HasSuffix(lower, "/all_api.js") || strings.Contains(lower, "controller") || strings.Contains(lower, "service") {
		score += 40
	}
	if isLowValueLibraryPath(path) {
		score -= 120
	}
	return score
}

func isLowValueLibraryPath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	base := strings.ToLower(filepath.Base(lower))
	return strings.Contains(lower, "/public/") ||
		strings.Contains(lower, "/static/") ||
		strings.Contains(lower, "/assets/") ||
		strings.Contains(lower, "/jsutil/") ||
		strings.Contains(base, "bundle") ||
		strings.Contains(base, "echarts") ||
		strings.Contains(base, "jspdf") ||
		strings.Contains(base, "jquery") ||
		strings.Contains(base, "mui")
}
