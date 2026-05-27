package service

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"sort"
	"strings"
	"time"

	"shenji/backend/internal/model"
	"shenji/backend/internal/storage"

	"gorm.io/gorm"
)

type ReportService struct {
	db    *gorm.DB
	store storage.ArtifactStore
}

type reportSnapshot struct {
	Task           model.AISecurityTask
	Findings       []model.AIFinding
	Evidence       []model.AIEvidence
	ToolRuns       []model.AIToolRun
	ContractChecks []model.AIContractCheckResult
}

type reportView struct {
	Task              model.AISecurityTask
	Narrative         ReportNarrative
	ExecutiveFacts    []string
	Findings          []reportFindingView
	EvidenceGroups    []reportEvidenceGroup
	ToolRunSections   []reportToolRunSection
	ContractSummary   []string
	ScopeJSON         string
	AuthorizationJSON string
}

type reportFindingView struct {
	ID                uint
	Title             string
	VulnerabilityType string
	Severity          string
	AffectedTarget    string
	AffectedComponent string
	Status            string
	ValidationStatus  string
	ContractStatus    string
	Narrative         string
	Remediation       string
	RetestSteps       string
	Details           map[string]any
	EvidenceItems     []model.AIEvidence
	CodeEvidence      []reportCodeEvidence
	HTTPPackets       []reportHTTPPacket
	ToolRuns          []model.AIToolRun
}

type reportCodeEvidence struct {
	Path      string
	LineStart int
	LineEnd   int
	Summary   string
	Snippet   string
}

type reportHTTPPacket struct {
	Title    string
	Request  string
	Response string
	Summary  string
}

type reportEvidenceGroup struct {
	Heading string
	Items   []model.AIEvidence
}

type reportToolRunSection struct {
	Heading string
	Items   []model.AIToolRun
}

func NewReportService(db *gorm.DB, store storage.ArtifactStore) *ReportService {
	return &ReportService{db: db, store: store}
}

func (s *ReportService) Generate(ctx context.Context, taskID uint) (model.AIReport, error) {
	snapshot, err := s.loadSnapshot(ctx, taskID)
	if err != nil {
		return model.AIReport{}, err
	}
	normalizeReportTaskStatus(&snapshot.Task)

	narrative := deterministicReportNarrative(snapshot.Task, snapshot.Findings, snapshot.Evidence, snapshot.ToolRuns)
	models := NewModelRuntimeService(s.db, 90*time.Second)
	if enriched, err := models.GenerateReportNarrative(ctx, snapshot.Task, snapshot.Findings, snapshot.Evidence, snapshot.ToolRuns); err == nil {
		narrative = enriched
	}

	view := buildReportView(ctx, snapshot, narrative, s.store)
	markdown := renderMarkdownReport(view)
	htmlDoc := renderHTMLReport(view)

	now := time.Now().UTC()
	mdRef, _, err := s.store.PutText(ctx, fmt.Sprintf("task-%d/reports/report-%d.md", taskID, now.Unix()), markdown)
	if err != nil {
		return model.AIReport{}, err
	}
	htmlRef, _, err := s.store.PutText(ctx, fmt.Sprintf("task-%d/reports/report-%d.html", taskID, now.Unix()), htmlDoc)
	if err != nil {
		return model.AIReport{}, err
	}
	report := model.AIReport{
		TaskID:      taskID,
		Title:       snapshot.Task.Name + " 安全验证报告",
		Status:      model.ReportStatusReady,
		Format:      "markdown_html",
		MarkdownRef: mdRef,
		HTMLRef:     htmlRef,
		Summary:     fmt.Sprintf("Generated report with %d delivery-ready findings, %d evidence items, and %d tool runs.", len(view.Findings), len(snapshot.Evidence), len(snapshot.ToolRuns)),
		GeneratedAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	return report, s.db.WithContext(ctx).Create(&report).Error
}

func normalizeReportTaskStatus(task *model.AISecurityTask) {
	if task == nil {
		return
	}
	if task.Status == model.TaskStatusRunning && task.ProgressStage == "正在生成交付报告" {
		task.Status = model.TaskStatusCompleted
		task.ProgressStage = "报告已生成"
		task.ProgressPercent = 100
	}
}

func (s *ReportService) ListByTask(ctx context.Context, taskID uint) ([]model.AIReport, error) {
	var reports []model.AIReport
	err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at desc").Find(&reports).Error
	return reports, err
}

func (s *ReportService) LatestByTask(ctx context.Context, taskID uint) (*model.AIReport, error) {
	var report model.AIReport
	err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at desc").First(&report).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &report, nil
}

func (s *ReportService) loadSnapshot(ctx context.Context, taskID uint) (reportSnapshot, error) {
	var snapshot reportSnapshot
	if err := s.db.WithContext(ctx).First(&snapshot.Task, taskID).Error; err != nil {
		return snapshot, err
	}
	if err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at asc").Find(&snapshot.Findings).Error; err != nil {
		return snapshot, err
	}
	if err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at asc").Find(&snapshot.Evidence).Error; err != nil {
		return snapshot, err
	}
	if err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("created_at asc").Find(&snapshot.ToolRuns).Error; err != nil {
		return snapshot, err
	}
	if err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Order("checked_at desc").Find(&snapshot.ContractChecks).Error; err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func buildReportView(ctx context.Context, snapshot reportSnapshot, narrative ReportNarrative, store storage.ArtifactStore) reportView {
	findingViews := buildFindingViews(ctx, snapshot, narrative, store)
	view := reportView{
		Task:              snapshot.Task,
		Narrative:         narrative,
		ExecutiveFacts:    buildExecutiveFacts(snapshot),
		Findings:          findingViews,
		EvidenceGroups:    buildEvidenceGroups(evidenceIndexFromFindings(findingViews, 12)),
		ToolRunSections:   buildToolRunSections(snapshot.ToolRuns),
		ContractSummary:   latestContractSummaryForFindings(snapshot.ContractChecks, findingViews),
		ScopeJSON:         string(snapshot.Task.ScopeJSON),
		AuthorizationJSON: string(snapshot.Task.AuthorizationJSON),
	}
	return view
}

func buildExecutiveFacts(snapshot reportSnapshot) []string {
	facts := []string{
		fmt.Sprintf("任务类型：%s", snapshot.Task.TaskType),
		fmt.Sprintf("当前状态：%s", snapshot.Task.Status),
		fmt.Sprintf("证据数量：%d", len(snapshot.Evidence)),
		fmt.Sprintf("工具执行数量：%d", len(snapshot.ToolRuns)),
	}
	if snapshot.Task.StartedAt != nil && snapshot.Task.FinishedAt != nil {
		facts = append(facts, fmt.Sprintf("执行时长：%s", snapshot.Task.FinishedAt.Sub(*snapshot.Task.StartedAt).Round(time.Second)))
	}
	if snapshot.Task.ModelConfigID != nil {
		facts = append(facts, fmt.Sprintf("模型配置 ID：%d", *snapshot.Task.ModelConfigID))
	}
	return facts
}

func buildFindingViews(ctx context.Context, snapshot reportSnapshot, narrative ReportNarrative, store storage.ArtifactStore) []reportFindingView {
	toolRunByID := map[uint]model.AIToolRun{}
	for _, run := range snapshot.ToolRuns {
		toolRunByID[run.ID] = run
	}
	views := make([]reportFindingView, 0, len(snapshot.Findings))
	for _, finding := range snapshot.Findings {
		if !isReportDeliverableFinding(finding) {
			continue
		}
		evidenceItems := evidenceForFinding(snapshot.Evidence, finding)
		linkedRuns := linkedToolRuns(toolRunByID, evidenceItems)
		text := narrative.FindingNarratives[finding.ID]
		if strings.TrimSpace(text) == "" {
			text = defaultFindingNarrative(finding)
		}
		details := map[string]any{}
		_ = unmarshalJSON(finding.RichDetails, &details)
		remediation := deliveryRemediation(finding, details)
		retestSteps := deliveryRetestSteps(finding, details)
		codeEvidence := buildCodeEvidence(ctx, snapshot, finding, evidenceItems, store)
		views = append(views, reportFindingView{
			ID:                finding.ID,
			Title:             finding.Title,
			VulnerabilityType: finding.VulnerabilityType,
			Severity:          finding.Severity,
			AffectedTarget:    finding.AffectedTarget,
			AffectedComponent: finding.AffectedComponent,
			Status:            finding.Status,
			ValidationStatus:  finding.ValidationStatus,
			ContractStatus:    finding.ContractStatus,
			Narrative:         text,
			Remediation:       remediation,
			RetestSteps:       retestSteps,
			Details:           details,
			EvidenceItems:     evidenceItems,
			CodeEvidence:      codeEvidence,
			HTTPPackets:       buildHTTPPackets(details, evidenceItems),
			ToolRuns:          linkedRuns,
		})
	}
	return views
}

func isReportDeliverableFinding(finding model.AIFinding) bool {
	if finding.ContractStatus != model.ContractStatusPassed {
		return false
	}
	switch finding.Status {
	case model.FindingStatusDynamicallyValidated, model.FindingStatusHumanConfirmed:
		return true
	default:
		return finding.ValidationStatus == model.ValidationDynamicallyValidated || finding.ValidationStatus == model.ValidationHumanConfirmed
	}
}

func buildCodeEvidence(ctx context.Context, snapshot reportSnapshot, finding model.AIFinding, items []model.AIEvidence, store storage.ArtifactStore) []reportCodeEvidence {
	selected := make([]model.AIEvidence, 0, len(items))
	for _, item := range items {
		if item.EvidenceType != "code_snippet" {
			continue
		}
		selected = append(selected, item)
	}
	if len(selected) < 5 {
		paths := findingDetailStrings(finding.RichDetails, "affected_component", "entrypoint")
		for _, item := range snapshot.Evidence {
			if item.EvidenceType != "code_snippet" || item.FilePath == "" {
				continue
			}
			for _, path := range paths {
				if path != "" && strings.Contains(strings.ToLower(item.FilePath), strings.ToLower(path)) {
					selected = append(selected, item)
					break
				}
			}
		}
	}
	sort.SliceStable(selected, func(i, j int) bool {
		left := codeEvidenceReportScore(selected[i])
		right := codeEvidenceReportScore(selected[j])
		if left == right {
			return selected[i].ID < selected[j].ID
		}
		return left > right
	})
	result := make([]reportCodeEvidence, 0, len(selected))
	seen := map[string]struct{}{}
	for _, item := range selected {
		key := evidenceLocationKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		snippet := ""
		if store != nil && strings.TrimSpace(item.RawRef) != "" {
			if text, err := store.ReadText(ctx, item.RawRef); err == nil {
				snippet = trimReportSnippet(text, 36)
			}
		}
		result = append(result, reportCodeEvidence{
			Path:      item.FilePath,
			LineStart: lineValue(item.LineStart),
			LineEnd:   lineValue(item.LineEnd),
			Summary:   deliveryCodeSummary(item),
			Snippet:   snippet,
		})
		if len(result) >= 8 {
			break
		}
	}
	return result
}

func buildHTTPPackets(details map[string]any, evidenceItems []model.AIEvidence) []reportHTTPPacket {
	packets := []reportHTTPPacket{}
	if request := optionalDetail(details, "request_packet"); request != "" {
		packets = append(packets, reportHTTPPacket{
			Title:    firstReportValue(optionalDetail(details, "proof_endpoint"), "验证请求"),
			Request:  request,
			Response: optionalDetail(details, "response_packet"),
			Summary:  optionalDetail(details, "observed_result"),
		})
	}
	seen := map[string]struct{}{}
	for _, item := range evidenceItems {
		request := requestSnapshotPacket(item.RequestSnapshot)
		response := responseSnapshotPacket(item.ResponseSnapshot)
		if request == "" && response == "" {
			continue
		}
		key := request + "\n---\n" + response
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		packets = append(packets, reportHTTPPacket{
			Title:    firstReportValue(item.Title, "HTTP 证据数据包"),
			Request:  request,
			Response: response,
			Summary:  item.Summary,
		})
	}
	return packets
}

func requestSnapshotPacket(raw []byte) string {
	values := map[string]any{}
	if len(raw) == 0 || json.Unmarshal(raw, &values) != nil || len(values) == 0 {
		return ""
	}
	method := strings.ToUpper(firstReportValue(reportAnyString(values["method"]), "GET"))
	rawURL := firstReportValue(reportAnyString(values["url"]), reportAnyString(values["target"]))
	path := rawURL
	host := reportAnyString(values["host"])
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Scheme != "" {
		path = parsed.RequestURI()
		if path == "" {
			path = "/"
		}
		host = parsed.Host
	}
	if strings.TrimSpace(path) == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\n")
	if strings.TrimSpace(host) != "" {
		b.WriteString("Host: " + host + "\n")
	}
	if headers, ok := values["headers"].(map[string]any); ok {
		keys := make([]string, 0, len(headers))
		for key := range headers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := reportAnyString(headers[key])
			if strings.TrimSpace(value) != "" {
				b.WriteString(key + ": " + value + "\n")
			}
		}
	}
	if body := reportAnyString(values["body"]); strings.TrimSpace(body) != "" {
		b.WriteString("\n" + body)
	}
	return strings.TrimSpace(b.String())
}

func responseSnapshotPacket(raw []byte) string {
	values := map[string]any{}
	if len(raw) == 0 || json.Unmarshal(raw, &values) != nil || len(values) == 0 {
		return ""
	}
	status := firstReportValue(reportAnyString(values["status"]), reportAnyString(values["statusCode"]))
	if strings.TrimSpace(status) == "" || status == "未形成可交付证据" {
		return ""
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\n")
	if headers, ok := values["headers"].(map[string]any); ok {
		keys := make([]string, 0, len(headers))
		for key := range headers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := reportAnyString(headers[key])
			if strings.TrimSpace(value) != "" {
				b.WriteString(key + ": " + value + "\n")
			}
		}
	}
	if body := firstReportValue(reportAnyString(values["body"]), reportAnyString(values["summary"])); body != "未形成可交付证据" {
		b.WriteString("\n" + body)
	}
	return strings.TrimSpace(b.String())
}

func reportAnyString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case []string:
		return strings.Join(typed, ", ")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := reportAnyString(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func codeEvidenceReportScore(item model.AIEvidence) int {
	score := 0
	text := strings.ToLower(item.Title + "\n" + item.Summary + "\n" + item.FilePath)
	if isFocusedCodeSlice(item) {
		score += 120
	}
	if strings.Contains(text, "sql") || strings.Contains(text, "query") || strings.Contains(text, "upload") || strings.Contains(text, "exec") || strings.Contains(text, "system") || strings.Contains(text, "sink") || strings.Contains(text, "source") {
		score += 80
	}
	if strings.Contains(text, "/satweb/erp/") || strings.Contains(text, "/server/plugins/erp/") || strings.Contains(text, "/api/") || strings.Contains(text, "/controller") {
		score += 70
	}
	if strings.Contains(text, "bundle") || strings.Contains(text, "jspdf") || strings.Contains(text, "echarts") || strings.Contains(text, "/public/") {
		score -= 140
	}
	return score
}

func findingDetailStrings(raw []byte, keys ...string) []string {
	details := map[string]any{}
	_ = unmarshalJSON(raw, &details)
	values := []string{}
	for _, key := range keys {
		text := strings.TrimSpace(fmt.Sprint(details[key]))
		if text == "" || text == "<nil>" {
			continue
		}
		values = append(values, strings.ReplaceAll(text, "\\", "/"))
	}
	return values
}

func trimReportSnippet(text string, maxLines int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if maxLines <= 0 || len(lines) <= maxLines {
		return strings.TrimSpace(text)
	}
	return strings.Join(lines[:maxLines], "\n") + "\n..."
}

func buildEvidenceGroups(items []model.AIEvidence) []reportEvidenceGroup {
	groupMap := map[string][]model.AIEvidence{}
	order := []string{}
	for _, item := range items {
		key := strings.TrimSpace(item.EvidenceType)
		if key == "" {
			key = "unknown"
		}
		if _, ok := groupMap[key]; !ok {
			order = append(order, key)
		}
		groupMap[key] = append(groupMap[key], item)
	}
	groups := make([]reportEvidenceGroup, 0, len(order))
	for _, key := range order {
		groups = append(groups, reportEvidenceGroup{
			Heading: key,
			Items:   groupMap[key],
		})
	}
	return groups
}

func deliveryEvidence(items []model.AIEvidence) []model.AIEvidence {
	result := make([]model.AIEvidence, 0, len(items))
	for _, item := range items {
		if isDeliveryEvidence(item) {
			result = append(result, item)
		}
	}
	return preferFocusedEvidence(result)
}

func isDeliveryEvidence(item model.AIEvidence) bool {
	path := strings.ToLower(strings.ReplaceAll(item.FilePath, "\\", "/"))
	summary := strings.ToLower(item.Summary)
	if item.EvidenceType == "command_output" {
		return item.RelationType == "poc_result" || strings.Contains(summary, "命令执行漏洞验证") || strings.Contains(summary, "poc")
	}
	if item.EvidenceType == "runtime_log" || item.EvidenceType == "tool_output" {
		return false
	}
	if strings.Contains(path, "/upload-labs-env") ||
		strings.Contains(path, "/apache/") ||
		strings.Contains(path, "/php/") ||
		strings.HasSuffix(path, ".min.js") ||
		strings.Contains(summary, "php.ini") ||
		strings.Contains(summary, "jquery.min.js") ||
		strings.Contains(summary, "httpd.conf") {
		return false
	}
	return item.EvidenceType == "code_snippet" ||
		item.EvidenceType == "http_exchange" ||
		item.EvidenceType == "response_diff" ||
		item.EvidenceType == "marker_poc" ||
		item.EvidenceType == "command_output"
}

func buildToolRunSections(items []model.AIToolRun) []reportToolRunSection {
	groupMap := map[string][]model.AIToolRun{}
	order := []string{}
	for _, item := range items {
		key := strings.TrimSpace(item.RunnerType)
		if key == "" {
			key = "runner"
		}
		if _, ok := groupMap[key]; !ok {
			order = append(order, key)
		}
		groupMap[key] = append(groupMap[key], item)
	}
	sections := make([]reportToolRunSection, 0, len(order))
	for _, key := range order {
		sections = append(sections, reportToolRunSection{
			Heading: key,
			Items:   groupMap[key],
		})
	}
	return sections
}

func buildContractSummary(checks []model.AIContractCheckResult) []string {
	if len(checks) == 0 {
		return []string{"未找到 Contract 检查结果。"}
	}
	lines := make([]string, 0, len(checks))
	for _, check := range checks {
		line := fmt.Sprintf("%s · %s", check.ContractType, check.Status)
		if strings.TrimSpace(check.DowngradeReason) != "" {
			line += " · " + check.DowngradeReason
		}
		lines = append(lines, line)
	}
	return lines
}

func latestContractSummary(checks []model.AIContractCheckResult) []string {
	if len(checks) == 0 {
		return []string{"未找到 Contract 检查结果。"}
	}
	latestByFinding := map[uint]model.AIContractCheckResult{}
	for _, check := range checks {
		current, ok := latestByFinding[check.FindingID]
		if !ok || check.CheckedAt.After(current.CheckedAt) {
			latestByFinding[check.FindingID] = check
		}
	}
	ordered := make([]model.AIContractCheckResult, 0, len(latestByFinding))
	for _, check := range latestByFinding {
		ordered = append(ordered, check)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].FindingID < ordered[j].FindingID
	})
	lines := make([]string, 0, len(ordered))
	for _, check := range ordered {
		line := fmt.Sprintf("%s · %s", check.ContractType, check.Status)
		if strings.TrimSpace(check.DowngradeReason) != "" && check.Status != model.ContractStatusPassed {
			line += " · " + check.DowngradeReason
		}
		lines = append(lines, line)
	}
	return lines
}

func latestContractSummaryForFindings(checks []model.AIContractCheckResult, findings []reportFindingView) []string {
	if len(findings) == 0 {
		return []string{"本报告无需要交付展示的 Contract 检查项；未闭环探索结果保留在后台。"}
	}
	allowed := map[uint]struct{}{}
	for _, finding := range findings {
		allowed[finding.ID] = struct{}{}
	}
	filtered := make([]model.AIContractCheckResult, 0, len(checks))
	for _, check := range checks {
		if _, ok := allowed[check.FindingID]; ok {
			filtered = append(filtered, check)
		}
	}
	return latestContractSummary(filtered)
}

func evidenceForFinding(all []model.AIEvidence, finding model.AIFinding) []model.AIEvidence {
	ids := []uint{}
	_ = jsonUnmarshalIDs(finding.EvidenceRefs, &ids)
	if len(ids) == 0 {
		return nil
	}
	index := map[uint]model.AIEvidence{}
	for _, item := range all {
		index[item.ID] = item
	}
	result := make([]model.AIEvidence, 0, len(ids))
	seenProof := map[string]struct{}{}
	for _, id := range ids {
		if item, ok := index[id]; ok {
			if !isDeliveryEvidence(item) {
				continue
			}
			proofKey := fmt.Sprintf("%s:%d:%s", item.FilePath, lineValue(item.LineStart), item.RelationType)
			if _, exists := seenProof[proofKey]; exists {
				continue
			}
			seenProof[proofKey] = struct{}{}
			result = append(result, item)
		}
	}
	return preferFocusedEvidence(result)
}

func evidenceIndexFromFindings(findings []reportFindingView, limit int) []model.AIEvidence {
	if limit <= 0 {
		limit = 12
	}
	result := make([]model.AIEvidence, 0, limit)
	seen := map[string]struct{}{}
	for _, finding := range findings {
		for _, item := range finding.EvidenceItems {
			key := evidenceLocationKey(item)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, item)
			if len(result) >= limit {
				return result
			}
		}
	}
	return result
}

func preferFocusedEvidence(items []model.AIEvidence) []model.AIEvidence {
	if len(items) <= 1 {
		return items
	}
	focusedByLocation := map[string]struct{}{}
	for _, item := range items {
		if isFocusedCodeSlice(item) {
			focusedByLocation[evidenceLocationKey(item)] = struct{}{}
		}
	}
	result := make([]model.AIEvidence, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		key := evidenceLocationKey(item)
		if _, hasFocused := focusedByLocation[key]; hasFocused && !isFocusedCodeSlice(item) {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
	}
	return result
}

func isFocusedCodeSlice(item model.AIEvidence) bool {
	return item.Title == "Focused code slice" || strings.Contains(strings.ToLower(item.Summary), "extracted code slice")
}

func evidenceLocationKey(item model.AIEvidence) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(strings.ReplaceAll(item.FilePath, "\\", "/")), lineValue(item.LineStart))
}

func linkedToolRuns(index map[uint]model.AIToolRun, evidence []model.AIEvidence) []model.AIToolRun {
	seen := map[uint]struct{}{}
	result := []model.AIToolRun{}
	for _, item := range evidence {
		if item.ToolRunID == nil {
			continue
		}
		if _, ok := seen[*item.ToolRunID]; ok {
			continue
		}
		run, ok := index[*item.ToolRunID]
		if !ok {
			continue
		}
		seen[*item.ToolRunID] = struct{}{}
		result = append(result, run)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

func defaultFindingNarrative(finding model.AIFinding) string {
	if finding.Status == model.FindingStatusDynamicallyValidated || finding.Status == model.FindingStatusHumanConfirmed {
		return "该结果已通过动态验证，证据链和执行记录可用于正式交付。"
	}
	return "该结果当前仍属于候选风险，证据或 Contract 尚未完整，报告不使用强确认措辞。"
}

func deliveryRemediation(finding model.AIFinding, details map[string]any) string {
	if text := detailValue(details, "remediation"); text != "未形成可交付证据" {
		return text
	}
	if strings.TrimSpace(finding.Remediation) != "" {
		return finding.Remediation
	}
	return "移除不安全的数据流，补充输入校验、权限控制和危险行为隔离，并重新执行同一授权范围内的安全验证。"
}

func deliveryRetestSteps(finding model.AIFinding, details map[string]any) string {
	if text := detailValue(details, "retest_steps"); text != "未形成可交付证据" {
		return text
	}
	if strings.TrimSpace(finding.RetestSteps) != "" {
		return finding.RetestSteps
	}
	return "按本次相同 Scope 重新执行验证，确认原触发路径不再复现，相关 Evidence 与 Contract 状态均已更新。"
}

func reportValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "未明确"
	}
	return value
}

func severityLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "信息"
	default:
		return reportValue(value)
	}
}

func validationLabel(validationStatus, contractStatus string) string {
	if validationStatus == model.ValidationDynamicallyValidated {
		return "已通过动态验证"
	}
	if contractStatus == model.ContractStatusPassed {
		return "证据合同已闭环"
	}
	if validationStatus == model.ValidationToolObserved {
		return "工具已观察到候选证据"
	}
	if validationStatus == model.ValidationContractIncomplete || contractStatus == model.ContractStatusIncomplete {
		return "证据合同未闭环"
	}
	return reportValue(validationStatus)
}

func contractLabel(status string) string {
	switch status {
	case model.ContractStatusPassed:
		return "已闭环"
	case model.ContractStatusIncomplete:
		return "未闭环"
	case model.ContractStatusFailed:
		return "检查失败"
	case model.ContractStatusNotChecked:
		return "未检查"
	default:
		return reportValue(status)
	}
}

func detailValue(details map[string]any, key string) string {
	value, ok := details[key]
	if !ok || value == nil {
		return "未形成可交付证据"
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "[]" || text == "<nil>" || strings.Contains(text, "readonly validation proof") {
		return "未形成可交付证据"
	}
	return text
}

func optionalDetail(details map[string]any, key string) string {
	text := detailValue(details, key)
	if text == "未形成可交付证据" {
		return ""
	}
	return text
}

func proofValue(finding reportFindingView, key string) string {
	text := detailValue(finding.Details, key)
	if strings.Contains(text, "evidence items collected") || strings.HasPrefix(text, "[") {
		return "见上方关键代码证据。"
	}
	return text
}

func shortEvidenceID(item model.AIEvidence) string {
	if item.ID == 0 {
		return ""
	}
	return fmt.Sprintf("Evidence #%d", item.ID)
}

func rootCauseText(finding reportFindingView) string {
	if text := detailValue(finding.Details, "root_cause"); text != "未形成可交付证据" {
		return text
	}
	if strings.TrimSpace(finding.AffectedComponent) != "" && finding.AffectedComponent != "补齐 Finding Contract 缺失证据" {
		return "风险集中在 " + finding.AffectedComponent + " 对可控输入、权限边界或危险行为的约束不足。"
	}
	return "风险来自可控输入与敏感行为之间缺少足够的校验、权限约束或安全边界。"
}

func evidenceTypeLabel(value string) string {
	switch value {
	case "code_snippet":
		return "代码片段证据"
	case "command_output":
		return "命令回显证明"
	case "http_exchange":
		return "HTTP 交互证据"
	case "response_diff":
		return "响应差异证据"
	case "marker_poc":
		return "Marker 验证证据"
	default:
		return strings.ToUpper(value)
	}
}

func evidenceSummaryForReport(item model.AIEvidence) string {
	location := strings.TrimSpace(item.FilePath)
	if location != "" && item.LineStart != nil {
		location = fmt.Sprintf("%s:%d", location, *item.LineStart)
	}
	if location == "" {
		location = fmt.Sprintf("Evidence #%d", item.ID)
	}
	if item.EvidenceType == "command_output" && item.RelationType == "poc_result" {
		return fmt.Sprintf("%s：%s%s", location, item.Summary, evidenceSuffix(item))
	}
	if item.Title == "Focused code slice" {
		return fmt.Sprintf("%s：关键代码片段显示可控输入与危险 Sink 位于同一执行链路。", location)
	}
	return fmt.Sprintf("%s：%s", location, item.Summary)
}

func deliveryCodeSummary(item model.AIEvidence) string {
	summary := evidenceSummaryForReport(item)
	if idx := strings.Index(summary, "（Evidence #"); idx >= 0 {
		if end := strings.Index(summary[idx:], "）"); end >= 0 {
			return summary[:idx] + summary[idx+end+len("）"):]
		}
	}
	return summary
}

func evidenceSuffix(item model.AIEvidence) string {
	id := shortEvidenceID(item)
	if id == "" {
		return ""
	}
	return "（" + id + "）"
}

func lineValue(line *int) int {
	if line == nil {
		return 0
	}
	return *line
}

func compactJSONForReport(raw string) string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "{}"
	}
	return text
}

func renderMarkdownReport(view reportView) string {
	var b strings.Builder
	b.WriteString("# " + view.Task.Name + " 安全验证报告\n\n")
	b.WriteString("## 执行摘要\n\n")
	for _, fact := range view.ExecutiveFacts {
		b.WriteString("- " + fact + "\n")
	}
	b.WriteString("\n")
	if strings.TrimSpace(view.Narrative.ExecutiveSummary) != "" {
		b.WriteString(view.Narrative.ExecutiveSummary + "\n\n")
	}
	b.WriteString("## 测试范围与授权边界\n\n")
	b.WriteString("- 授权范围：`" + compactJSONForReport(view.ScopeJSON) + "`\n")
	b.WriteString("- 授权策略：`" + compactJSONForReport(view.AuthorizationJSON) + "`\n\n")
	b.WriteString("## 漏洞发现\n\n")
	if len(view.Findings) == 0 {
		b.WriteString("本阶段未形成满足交付门槛的漏洞发现。后台保留执行记录与原始材料供后续分析，不作为报告主体证据展示。\n\n")
	} else {
		for _, finding := range view.Findings {
			writeMarkdownFinding(&b, finding)
		}
	}
	b.WriteString("## 说明\n\n")
	b.WriteString("本报告仅展示满足交付门槛的漏洞。未闭环的假设、探索线索、Capability、NegativeFact 与原始 ToolRun 审计材料保留在平台后台，不作为漏洞结论呈现。\n")
	return b.String()
}

func writeMarkdownFinding(b *strings.Builder, finding reportFindingView) {
	b.WriteString("### " + finding.Title + "\n\n")
	b.WriteString("**漏洞名称**: " + finding.Title + "\n")
	b.WriteString("**漏洞等级**: " + severityLabel(finding.Severity) + "\n")
	b.WriteString("**漏洞类型**: " + reportValue(finding.VulnerabilityType) + "\n")
	if strings.TrimSpace(finding.AffectedTarget) != "" {
		b.WriteString("**影响目标**: " + finding.AffectedTarget + "\n")
	}
	if strings.TrimSpace(finding.AffectedComponent) != "" {
		b.WriteString("**影响组件**: " + finding.AffectedComponent + "\n")
	}
	writeMarkdownDetailLine(b, finding, "CVSS 3.1表达式", "cvss_vector")
	writeMarkdownDetailLine(b, finding, "CVSS 3.1分数", "cvss_score")
	b.WriteString("\n")

	b.WriteString("#### 漏洞定性与风险评估\n\n")
	b.WriteString("**漏洞类型**: " + reportValue(finding.VulnerabilityType) + "\n")
	b.WriteString("**风险等级**: " + severityLabel(finding.Severity) + "\n")
	b.WriteString("**验证状态**: " + validationLabel(finding.ValidationStatus, finding.ContractStatus) + "\n")
	writeMarkdownListSection(b, "理由", detailStringList(finding.Details, "risk_reasons"))

	b.WriteString("#### 漏洞描述\n\n")
	description := firstReportValue(detailValue(finding.Details, "vulnerability_description"), finding.Narrative)
	b.WriteString(description + "\n\n")
	writeMarkdownListSection(b, "关键证据", detailStringList(finding.Details, "key_evidence"))

	b.WriteString("#### 漏洞证明\n\n")
	writeMarkdownProofSummary(b, finding)
	writeMarkdownPackets(b, finding)
	writeMarkdownReproduction(b, finding)

	b.WriteString("#### 攻击向量\n\n")
	if scenario := optionalDetail(finding.Details, "attack_scenario"); scenario != "" {
		b.WriteString("##### 攻击场景\n\n")
		b.WriteString(scenario + "\n\n")
	}
	writeMarkdownListSection(b, "攻击步骤", detailStringList(finding.Details, "attack_steps"))

	b.WriteString("#### 数据流分析与代码证据\n\n")
	b.WriteString("##### 1. 入口点与 Source\n\n")
	writeMarkdownOptionalBullet(b, "入口点", optionalDetail(finding.Details, "entrypoint"))
	writeMarkdownOptionalBullet(b, "访问路径", optionalDetail(finding.Details, "access_path"))
	writeMarkdownOptionalBullet(b, "Source(s)", optionalDetail(finding.Details, "controlled_input"))
	writeMarkdownOptionalBullet(b, "可控性分析", optionalDetail(finding.Details, "source_analysis"))
	b.WriteString("\n")
	b.WriteString("##### 2. 数据流传播 (Propagation)\n\n")
	writeMarkdownPropagationHops(b, finding)
	b.WriteString("##### 3. Sink & Impact (危害)\n\n")
	writeMarkdownOptionalBullet(b, "Sink", optionalDetail(finding.Details, "sensitive_sink_or_behavior"))
	writeMarkdownOptionalBullet(b, "Post-Sink Mitigation", optionalDetail(finding.Details, "post_sink_mitigation"))
	writeMarkdownOptionalBullet(b, "Impact", optionalDetail(finding.Details, "impact_explanation"))
	b.WriteString("\n")

	b.WriteString("#### 实际可利用性分析\n\n")
	writeMarkdownOptionalBullet(b, "运行时可达性", optionalDetail(finding.Details, "runtime_reachability"))
	writeMarkdownOptionalBullet(b, "业务逻辑限制", optionalDetail(finding.Details, "business_constraints"))
	writeMarkdownOptionalBullet(b, "运行环境限制", optionalDetail(finding.Details, "environment_constraints"))
	writeMarkdownOptionalBullet(b, "实际可行性评估", optionalDetail(finding.Details, "exploitability_assessment"))
	b.WriteString("\n")

	if hasAnyDetail(finding.Details, "framework_analysis", "route_mapping", "auth_logic") {
		b.WriteString("#### 技术框架分析\n\n")
		writeMarkdownOptionalBullet(b, "路由框架", optionalDetail(finding.Details, "framework_analysis"))
		writeMarkdownOptionalBullet(b, "路由映射方式", optionalDetail(finding.Details, "route_mapping"))
		writeMarkdownOptionalBullet(b, "鉴权逻辑", optionalDetail(finding.Details, "auth_logic"))
		b.WriteString("\n")
	}

	if len(finding.CodeEvidence) > 0 || len(detailStringList(finding.Details, "call_stack")) > 0 || optionalDetail(finding.Details, "mermaid_graph") != "" {
		b.WriteString("#### 调用栈信息与流程图\n\n")
		writeMarkdownListSection(b, "调用栈", detailStringList(finding.Details, "call_stack"))
		if mermaid := optionalDetail(finding.Details, "mermaid_graph"); mermaid != "" {
			b.WriteString("##### 调用栈可视化 (Mermaid)\n\n")
			b.WriteString(markdownCodeFence("mermaid", mermaid))
		}
		if len(finding.CodeEvidence) > 0 {
			b.WriteString("##### 代码证据\n\n")
			writeMarkdownCodeEvidence(b, finding)
		}
	}

	b.WriteString("#### 根源分析\n\n")
	writeMarkdownOptionalBullet(b, "直接原因", optionalDetail(finding.Details, "direct_cause"))
	b.WriteString("- **根本原因**: " + rootCauseText(finding) + "\n")
	writeMarkdownOptionalBullet(b, "因果链", optionalDetail(finding.Details, "causal_chain"))
	b.WriteString("\n")

	b.WriteString("#### 修复建议\n\n")
	b.WriteString("- **临时修复**: " + firstReportValue(detailValue(finding.Details, "temporary_fix"), finding.Remediation) + "\n")
	b.WriteString("- **长期修复**: " + firstReportValue(detailValue(finding.Details, "strategic_fix"), finding.Remediation) + "\n")
	writeMarkdownListSection(b, "纵深防御", detailStringList(finding.Details, "defense_in_depth"))
	b.WriteString("##### 复测方法\n\n")
	for _, line := range splitDeliveryLines(finding.RetestSteps) {
		b.WriteString("- " + line + "\n")
	}
	b.WriteString("\n")
}

func writeMarkdownProofSummary(b *strings.Builder, finding reportFindingView) {
	writeMarkdownOptionalBullet(b, "验证端点", optionalDetail(finding.Details, "proof_endpoint"))
	writeMarkdownOptionalBullet(b, "验证载荷", optionalDetail(finding.Details, "proof_payload"))
	writeMarkdownOptionalBullet(b, "观察结果", optionalDetail(finding.Details, "observed_result"))
	writeMarkdownOptionalBullet(b, "成功判定", optionalDetail(finding.Details, "success_criteria"))
	if len(finding.EvidenceItems) > 0 {
		b.WriteString("\n**证据索引**:\n")
		for _, item := range finding.EvidenceItems {
			b.WriteString("- " + evidenceSummaryForReport(item) + "\n")
		}
	}
	b.WriteString("\n")
}

func writeMarkdownPackets(b *strings.Builder, finding reportFindingView) {
	if len(finding.HTTPPackets) == 0 {
		return
	}
	b.WriteString("##### 详细数据包\n\n")
	for i, packet := range finding.HTTPPackets {
		title := packet.Title
		if strings.TrimSpace(title) == "" {
			title = fmt.Sprintf("HTTP 数据包 %d", i+1)
		}
		b.WriteString("**" + title + "**\n\n")
		if strings.TrimSpace(packet.Summary) != "" {
			b.WriteString("- 观察结果：" + packet.Summary + "\n\n")
		}
		if strings.TrimSpace(packet.Request) != "" {
			b.WriteString("请求包：\n\n")
			b.WriteString(markdownCodeFence("http", packet.Request))
		}
		if strings.TrimSpace(packet.Response) != "" {
			b.WriteString("响应包：\n\n")
			b.WriteString(markdownCodeFence("http", packet.Response))
		}
	}
}

func writeMarkdownOptionalBullet(b *strings.Builder, label string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	b.WriteString("- **" + label + "**: " + value + "\n")
}

func hasAnyDetail(details map[string]any, keys ...string) bool {
	for _, key := range keys {
		if optionalDetail(details, key) != "" {
			return true
		}
	}
	return false
}

func renderHTMLReport(view reportView) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>")
	b.WriteString(html.EscapeString(view.Task.Name))
	b.WriteString(" 安全验证报告</title><style>")
	b.WriteString(reportCSS())
	b.WriteString("</style></head><body>")
	b.WriteString("<main class=\"report-shell\">")
	b.WriteString("<section class=\"hero\">")
	b.WriteString("<div class=\"hero__eyebrow\">Rabbit AI Security Validation Platform</div>")
	b.WriteString("<h1>" + html.EscapeString(view.Task.Name) + " 安全验证报告</h1>")
	b.WriteString("<p class=\"hero__summary\">" + html.EscapeString(view.Narrative.ExecutiveSummary) + "</p>")
	b.WriteString("<div class=\"hero__facts\">")
	for _, fact := range view.ExecutiveFacts {
		b.WriteString("<span>" + html.EscapeString(fact) + "</span>")
	}
	b.WriteString("</div></section>")

	b.WriteString("<section class=\"panel\"><h2>测试范围与授权边界</h2><div class=\"two-column\">")
	b.WriteString("<div><h3>授权范围</h3><pre>" + html.EscapeString(compactJSONForReport(view.ScopeJSON)) + "</pre></div>")
	b.WriteString("<div><h3>授权策略</h3><pre>" + html.EscapeString(compactJSONForReport(view.AuthorizationJSON)) + "</pre></div>")
	b.WriteString("</div></section>")

	b.WriteString("<section class=\"panel\"><h2>漏洞发现</h2>")
	if len(view.Findings) == 0 {
		b.WriteString("<div class=\"empty\">本阶段未形成满足交付门槛的漏洞发现。后台保留执行记录与原始材料供后续分析，不作为报告主体证据展示。</div>")
	} else {
		for _, finding := range view.Findings {
			b.WriteString("<article class=\"finding-card\">")
			b.WriteString("<div class=\"finding-card__header\">")
			b.WriteString("<h3>" + html.EscapeString(finding.Title) + "</h3>")
			b.WriteString("<div class=\"pill-row\">")
			b.WriteString("<span class=\"pill\">" + html.EscapeString(validationLabel(finding.ValidationStatus, finding.ContractStatus)) + "</span>")
			b.WriteString("<span class=\"pill\">" + html.EscapeString(contractLabel(finding.ContractStatus)) + "</span>")
			b.WriteString("</div></div>")
			b.WriteString("<div class=\"meta-grid\">")
			b.WriteString("<span>漏洞名称：" + html.EscapeString(finding.Title) + "</span>")
			b.WriteString("<span>漏洞等级：" + html.EscapeString(severityLabel(finding.Severity)) + "</span>")
			b.WriteString("<span>漏洞类型：" + html.EscapeString(finding.VulnerabilityType) + "</span>")
			b.WriteString("<span>影响目标：" + html.EscapeString(finding.AffectedTarget) + "</span>")
			if strings.TrimSpace(finding.AffectedComponent) != "" {
				b.WriteString("<span>影响组件：" + html.EscapeString(finding.AffectedComponent) + "</span>")
			}
			b.WriteString("</div>")
			b.WriteString("<div class=\"subsection\"><strong>漏洞描述</strong><p>" + html.EscapeString(firstReportValue(detailValue(finding.Details, "vulnerability_description"), finding.Narrative)) + "</p></div>")
			if reasons := detailStringList(finding.Details, "risk_reasons"); len(reasons) > 0 {
				b.WriteString("<div class=\"subsection\"><strong>风险评估理由</strong>" + htmlList(reasons) + "</div>")
			}
			b.WriteString("<div class=\"subsection\"><strong>攻击向量</strong><ul>")
			b.WriteString("<li>入口点：" + html.EscapeString(detailValue(finding.Details, "entrypoint")) + "</li>")
			b.WriteString("<li>可控输入：" + html.EscapeString(detailValue(finding.Details, "controlled_input")) + "</li>")
			b.WriteString("<li>触发动作：" + html.EscapeString(detailValue(finding.Details, "trigger_payload_or_action")) + "</li>")
			b.WriteString("</ul></div>")
			if steps := detailStringList(finding.Details, "attack_steps"); len(steps) > 0 {
				b.WriteString("<div class=\"subsection\"><strong>攻击步骤</strong>" + htmlList(steps) + "</div>")
			}
			b.WriteString("<div class=\"subsection\"><strong>数据流分析与代码证据</strong><ul>")
			b.WriteString("<li>传播路径：" + html.EscapeString(detailValue(finding.Details, "propagation_path")) + "</li>")
			b.WriteString("<li>敏感行为或 Sink：" + html.EscapeString(detailValue(finding.Details, "sensitive_sink_or_behavior")) + "</li>")
			b.WriteString("</ul></div>")
			if len(finding.CodeEvidence) > 0 {
				b.WriteString("<div class=\"subsection\"><strong>关键代码证据</strong><ul>")
				for _, item := range finding.CodeEvidence {
					b.WriteString("<li>" + html.EscapeString(item.Summary) + "</li>")
				}
				b.WriteString("</ul>")
				for _, item := range finding.CodeEvidence {
					if strings.TrimSpace(item.Snippet) != "" {
						b.WriteString("<pre>" + html.EscapeString(item.Snippet) + "</pre>")
					}
				}
				b.WriteString("</div>")
			} else {
				b.WriteString("<div class=\"subsection\"><strong>关键代码证据</strong><p>本次未形成可进入报告主体的漏洞证明证据，原始过程材料保留在后台。</p></div>")
			}
			b.WriteString("<div class=\"subsection\"><strong>漏洞利用证明</strong><ul>")
			b.WriteString("<li>基线证据：" + html.EscapeString(proofValue(finding, "baseline_evidence")) + "</li>")
			b.WriteString("<li>验证证据：" + html.EscapeString(proofValue(finding, "validation_evidence")) + "</li>")
			b.WriteString("<li>观察结果：" + html.EscapeString(detailValue(finding.Details, "observed_result")) + "</li>")
			b.WriteString("</ul></div>")
			writeHTMLPackets(&b, finding)
			writeHTMLReproduction(&b, finding)
			if mermaid := detailValue(finding.Details, "mermaid_graph"); mermaid != "未形成可交付证据" {
				b.WriteString("<div class=\"subsection\"><strong>调用栈可视化</strong><pre>" + html.EscapeString(mermaid) + "</pre></div>")
			}
			b.WriteString("<div class=\"subsection\"><strong>影响说明</strong><p>" + html.EscapeString(detailValue(finding.Details, "impact_explanation")) + "</p></div>")
			b.WriteString("<div class=\"subsection\"><strong>根源分析</strong><p>" + html.EscapeString(rootCauseText(finding)) + "</p></div>")
			b.WriteString("<div class=\"subsection\"><strong>修复建议</strong>" + htmlList(splitDeliveryLines(finding.Remediation)) + "</div>")
			b.WriteString("<div class=\"subsection\"><strong>复测方法</strong>" + htmlList(splitDeliveryLines(finding.RetestSteps)) + "</div>")
			b.WriteString("</article>")
		}
	}
	b.WriteString("</section>")

	b.WriteString("<section class=\"panel panel--muted\"><h2>说明</h2><p>本报告仅展示满足交付门槛的漏洞。未闭环的假设、探索线索、Capability、NegativeFact 与原始 ToolRun 审计材料保留在平台后台，不作为漏洞结论呈现。</p></section>")
	b.WriteString("</main></body></html>")
	return b.String()
}

func writeMarkdownReproduction(b *strings.Builder, finding reportFindingView) {
	requestPacket := detailValue(finding.Details, "request_packet")
	curlPOC := firstReportValue(detailValue(finding.Details, "bash_poc"), detailValue(finding.Details, "curl_poc"))
	pythonPOC := detailValue(finding.Details, "python_poc")
	successCriteria := detailValue(finding.Details, "success_criteria")
	if requestPacket == "未形成可交付证据" && curlPOC == "未形成可交付证据" && pythonPOC == "未形成可交付证据" {
		return
	}
	b.WriteString("#### 复现验证材料\n\n")
	if endpoint := detailValue(finding.Details, "proof_endpoint"); endpoint != "未形成可交付证据" {
		b.WriteString("- 验证端点：" + endpoint + "\n")
	}
	if accessPath := detailValue(finding.Details, "uploaded_access_path"); accessPath != "未形成可交付证据" {
		b.WriteString("- 上传后访问路径：" + accessPath + "\n")
	}
	if payload := detailValue(finding.Details, "proof_payload"); payload != "未形成可交付证据" {
		b.WriteString("- 验证载荷：" + payload + "\n")
	}
	if successCriteria != "未形成可交付证据" {
		b.WriteString("- 成功判定：" + successCriteria + "\n")
	}
	if steps := detailStringList(finding.Details, "verification_steps"); len(steps) > 0 {
		b.WriteString("\n验证步骤：\n")
		for i, step := range steps {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
	}
	if notes := detailValue(finding.Details, "proof_notes"); notes != "未形成可交付证据" {
		b.WriteString("- 注意事项：" + notes + "\n")
	}
	b.WriteString("\n")
	if requestPacket != "未形成可交付证据" {
		b.WriteString("原始 HTTP 请求包：\n\n")
		b.WriteString(markdownCodeFence("http", requestPacket))
	}
	if curlPOC != "未形成可交付证据" {
		label := "curl PoC"
		if !strings.Contains(strings.ToLower(curlPOC), "curl ") {
			label = "执行 PoC 命令"
		}
		b.WriteString(label + "：\n\n")
		b.WriteString(markdownCodeFence("bash", curlPOC))
	}
	if pythonPOC != "未形成可交付证据" {
		b.WriteString("Python 利用脚本：\n\n")
		b.WriteString(markdownCodeFence("python", pythonPOC))
	}
}

func writeMarkdownDetailLine(b *strings.Builder, finding reportFindingView, label string, key string) {
	if value := detailValue(finding.Details, key); value != "未形成可交付证据" {
		b.WriteString("**" + label + "**: " + value + "\n")
	}
}

func writeMarkdownListSection(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	b.WriteString("**" + title + "**:\n")
	for i, item := range items {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, item))
	}
	b.WriteString("\n")
}

func writeMarkdownCodeEvidence(b *strings.Builder, finding reportFindingView) {
	if len(finding.CodeEvidence) == 0 {
		b.WriteString("关键代码证据：本次未形成可进入报告主体的漏洞证明证据，原始过程材料保留在后台。\n\n")
		return
	}
	for i, item := range finding.CodeEvidence {
		location := item.Path
		if item.LineStart > 0 {
			location = fmt.Sprintf("%s:%d", item.Path, item.LineStart)
		}
		b.WriteString(fmt.Sprintf("**代码证据 %d** (%s): %s\n\n", i+1, location, item.Summary))
		if strings.TrimSpace(item.Snippet) != "" {
			b.WriteString(markdownCodeFence(languageFromPath(item.Path), item.Snippet))
		}
	}
}

func writeMarkdownPropagationHops(b *strings.Builder, finding reportFindingView) {
	hops := detailPropagationHops(finding.Details, "propagation_hops")
	if len(hops) == 0 {
		writeMarkdownOptionalBullet(b, "传播路径", optionalDetail(finding.Details, "propagation_path"))
		b.WriteString("\n")
		return
	}
	b.WriteString("**详细传播链**:\n\n")
	for i, hop := range hops {
		b.WriteString(fmt.Sprintf("- **跳%d** %s\n", i+1, reportMapValue(hop, "step")))
		if line := reportMapValue(hop, "line"); line != "" {
			b.WriteString("  - 位置: " + line + "\n")
		}
		if transform := reportMapValue(hop, "transform"); transform != "" {
			b.WriteString("  - 数据变换: " + transform + "\n")
		}
		if code := reportMapValue(hop, "code"); code != "" {
			b.WriteString("  - 代码证据:\n\n")
			b.WriteString(markdownCodeFence("", code))
		}
	}
	b.WriteString("\n")
}

func detailPropagationHops(details map[string]any, key string) []map[string]any {
	value, ok := details[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []map[string]any:
		return typed
	case []any:
		result := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if mapped, ok := item.(map[string]any); ok {
				result = append(result, mapped)
			}
		}
		return result
	default:
		return nil
	}
}

func reportMapValue(values map[string]any, key string) string {
	text := strings.TrimSpace(fmt.Sprint(values[key]))
	if text == "" || text == "<nil>" {
		return ""
	}
	return text
}

func firstReportValue(values ...string) string {
	for _, value := range values {
		text := strings.TrimSpace(value)
		if text != "" && text != "未形成可交付证据" {
			return text
		}
	}
	return "未形成可交付证据"
}

func markdownCodeFence(language, content string) string {
	content = strings.ReplaceAll(strings.TrimSpace(content), "```", "`\u200b``")
	return "```" + language + "\n" + content + "\n```\n\n"
}

func languageFromPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".php"):
		return "php"
	case strings.HasSuffix(lower, ".java"):
		return "java"
	case strings.HasSuffix(lower, ".go"):
		return "go"
	case strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".ts"), strings.HasSuffix(lower, ".vue"):
		return "javascript"
	case strings.HasSuffix(lower, ".py"):
		return "python"
	case strings.HasSuffix(lower, ".xml"):
		return "xml"
	default:
		return "text"
	}
}

func detailStringList(details map[string]any, key string) []string {
	value, ok := details[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return compactStringList(typed)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || text == "[]" {
			return nil
		}
		return compactStringList(strings.Split(text, "\n"))
	}
}

func compactStringList(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		text := strings.TrimSpace(strings.TrimPrefix(value, "-"))
		if text != "" {
			result = append(result, text)
		}
	}
	return result
}

func splitDeliveryLines(text string) []string {
	normalized := strings.ReplaceAll(text, "；", ";\n")
	normalized = strings.ReplaceAll(normalized, "。", "。\n")
	parts := compactStringList(strings.Split(normalized, "\n"))
	if len(parts) == 0 && strings.TrimSpace(text) != "" {
		return []string{strings.TrimSpace(text)}
	}
	return parts
}

func htmlList(items []string) string {
	if len(items) == 0 {
		return "<p>未形成可交付建议。</p>"
	}
	var b strings.Builder
	b.WriteString("<ul>")
	for _, item := range items {
		b.WriteString("<li>" + html.EscapeString(item) + "</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func writeHTMLPackets(b *strings.Builder, finding reportFindingView) {
	if len(finding.HTTPPackets) == 0 {
		return
	}
	b.WriteString("<div class=\"subsection\"><strong>详细数据包</strong>")
	for i, packet := range finding.HTTPPackets {
		title := packet.Title
		if strings.TrimSpace(title) == "" {
			title = fmt.Sprintf("HTTP 数据包 %d", i+1)
		}
		b.WriteString("<h4>" + html.EscapeString(title) + "</h4>")
		if strings.TrimSpace(packet.Summary) != "" {
			b.WriteString("<p>观察结果：" + html.EscapeString(packet.Summary) + "</p>")
		}
		if strings.TrimSpace(packet.Request) != "" {
			b.WriteString("<h5>请求包</h5><pre>" + html.EscapeString(packet.Request) + "</pre>")
		}
		if strings.TrimSpace(packet.Response) != "" {
			b.WriteString("<h5>响应包</h5><pre>" + html.EscapeString(packet.Response) + "</pre>")
		}
	}
	b.WriteString("</div>")
}

func writeHTMLReproduction(b *strings.Builder, finding reportFindingView) {
	requestPacket := detailValue(finding.Details, "request_packet")
	curlPOC := firstReportValue(detailValue(finding.Details, "bash_poc"), detailValue(finding.Details, "curl_poc"))
	pythonPOC := detailValue(finding.Details, "python_poc")
	successCriteria := detailValue(finding.Details, "success_criteria")
	if requestPacket == "未形成可交付证据" && curlPOC == "未形成可交付证据" && pythonPOC == "未形成可交付证据" {
		return
	}
	b.WriteString("<div class=\"subsection\"><strong>复现验证材料</strong><ul>")
	if endpoint := detailValue(finding.Details, "proof_endpoint"); endpoint != "未形成可交付证据" {
		b.WriteString("<li>验证端点：" + html.EscapeString(endpoint) + "</li>")
	}
	if accessPath := detailValue(finding.Details, "uploaded_access_path"); accessPath != "未形成可交付证据" {
		b.WriteString("<li>上传后访问路径：" + html.EscapeString(accessPath) + "</li>")
	}
	if payload := detailValue(finding.Details, "proof_payload"); payload != "未形成可交付证据" {
		b.WriteString("<li>验证载荷：" + html.EscapeString(payload) + "</li>")
	}
	if successCriteria != "未形成可交付证据" {
		b.WriteString("<li>成功判定：" + html.EscapeString(successCriteria) + "</li>")
	}
	if steps := detailStringList(finding.Details, "verification_steps"); len(steps) > 0 {
		b.WriteString("<li>验证步骤：" + html.EscapeString(strings.Join(steps, "；")) + "</li>")
	}
	if notes := detailValue(finding.Details, "proof_notes"); notes != "未形成可交付证据" {
		b.WriteString("<li>注意事项：" + html.EscapeString(notes) + "</li>")
	}
	b.WriteString("</ul>")
	if requestPacket != "未形成可交付证据" {
		b.WriteString("<h4>原始 HTTP 请求包</h4><pre>" + html.EscapeString(requestPacket) + "</pre>")
	}
	if curlPOC != "未形成可交付证据" {
		label := "curl PoC"
		if !strings.Contains(strings.ToLower(curlPOC), "curl ") {
			label = "执行 PoC 命令"
		}
		b.WriteString("<h4>" + html.EscapeString(label) + "</h4><pre>" + html.EscapeString(curlPOC) + "</pre>")
	}
	if pythonPOC != "未形成可交付证据" {
		b.WriteString("<h4>Python 利用脚本</h4><pre>" + html.EscapeString(pythonPOC) + "</pre>")
	}
	b.WriteString("</div>")
}

func reportCSS() string {
	return `
	body {
	  margin: 0;
	  background: #eef3fb;
	  color: #1f2a44;
	  font-family: "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
	}
	.report-shell {
	  max-width: 1120px;
	  margin: 0 auto;
	  padding: 40px 24px 72px;
	}
	.hero, .panel {
	  background: #ffffff;
	  border: 1px solid #dbe5f2;
	  border-radius: 24px;
	  box-shadow: 0 20px 48px rgba(36, 65, 130, 0.08);
	}
	.hero {
	  padding: 36px 40px;
	  margin-bottom: 20px;
	  background: linear-gradient(135deg, #ffffff 0%, #f6f9ff 100%);
	}
	.hero__eyebrow {
	  color: #2f6fe4;
	  font-size: 13px;
	  font-weight: 800;
	  letter-spacing: 0.08em;
	  text-transform: uppercase;
	  margin-bottom: 12px;
	}
	.hero h1 {
	  margin: 0 0 14px;
	  font-size: 40px;
	  line-height: 1.1;
	}
	.hero__summary {
	  margin: 0 0 18px;
	  color: #4a5e82;
	  font-size: 16px;
	  line-height: 1.75;
	}
	.hero__facts {
	  display: flex;
	  flex-wrap: wrap;
	  gap: 10px;
	}
	.hero__facts span, .pill {
	  display: inline-flex;
	  align-items: center;
	  padding: 8px 12px;
	  border-radius: 999px;
	  background: #edf4ff;
	  color: #2f6fe4;
	  font-size: 13px;
	  font-weight: 700;
	}
	.panel {
	  padding: 26px 28px;
	  margin-bottom: 18px;
	}
	.panel--muted {
	  background: #f8fbff;
	}
	h2 {
	  margin: 0 0 18px;
	  font-size: 24px;
	}
	h3 {
	  margin: 0 0 12px;
	  font-size: 18px;
	}
	.two-column {
	  display: grid;
	  grid-template-columns: repeat(2, minmax(0, 1fr));
	  gap: 18px;
	}
	pre, .mono {
	  font-family: "SFMono-Regular", "Menlo", monospace;
	  font-size: 12px;
	  white-space: pre-wrap;
	  word-break: break-all;
	}
	pre {
	  margin: 0;
	  padding: 16px;
	  border-radius: 16px;
	  background: #0f172a;
	  color: #e6eefc;
	}
	.finding-card {
	  padding: 20px 22px;
	  border: 1px solid #e1e8f5;
	  border-radius: 18px;
	  background: #fbfdff;
	  margin-bottom: 14px;
	}
	.finding-card__header {
	  display: flex;
	  justify-content: space-between;
	  gap: 16px;
	  align-items: flex-start;
	}
	.pill-row {
	  display: flex;
	  flex-wrap: wrap;
	  gap: 8px;
	}
	.meta-grid {
	  display: grid;
	  grid-template-columns: repeat(2, minmax(0, 1fr));
	  gap: 10px 18px;
	  color: #586b8c;
	  font-size: 13px;
	  margin-bottom: 14px;
	}
	.narrative {
	  margin: 0 0 14px;
	  color: #24334f;
	  line-height: 1.8;
	}
	.subsection {
	  margin-top: 12px;
	}
	.subsection p {
	  margin: 8px 0 0;
	  line-height: 1.75;
	  color: #30415f;
	}
	ul {
	  margin: 10px 0 0 20px;
	  padding: 0;
	}
	li {
	  margin: 8px 0;
	  line-height: 1.7;
	}
	.evidence-group, .toolrun-group {
	  margin-bottom: 16px;
	}
	.empty {
	  color: #5f6f8d;
	  line-height: 1.8;
	}
	@media (max-width: 960px) {
	  .two-column, .meta-grid {
	    grid-template-columns: 1fr;
	  }
	  .hero {
	    padding: 28px 24px;
	  }
	  .hero h1 {
	    font-size: 30px;
	  }
	}
	`
}

func jsonUnmarshalIDs(raw any, out *[]uint) error {
	switch typed := raw.(type) {
	case []byte:
		return json.Unmarshal(typed, out)
	case string:
		return json.Unmarshal([]byte(typed), out)
	default:
		bytes, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		return json.Unmarshal(bytes, out)
	}
}
