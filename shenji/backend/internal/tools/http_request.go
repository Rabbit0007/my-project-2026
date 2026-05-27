package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"shenji/backend/internal/runner"
	"shenji/backend/internal/safety"
)

type HTTPRequestTool struct {
	manager *runner.RunnerManager
	timeout time.Duration
}

type httpRequestInput struct {
	TaskID  uint              `json:"taskId"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func NewHTTPRequestTool(timeout time.Duration, manager *runner.RunnerManager) *HTTPRequestTool {
	return &HTTPRequestTool{timeout: timeout, manager: manager}
}

func (t *HTTPRequestTool) Name() string { return "http_request" }
func (t *HTTPRequestTool) Kind() string { return "http" }
func (t *HTTPRequestTool) Schema() ToolSchema {
	return ToolSchema{
		Description: "Perform an authorized HTTP baseline or diff request and collect request/response evidence.",
		Properties:  map[string]string{"method": "HTTP method", "url": "authorized target URL", "headers": "optional headers", "body": "optional body"},
		Required:    []string{"url"},
	}
}

func (t *HTTPRequestTool) Validate(ctx context.Context, input json.RawMessage, policy safety.SafePolicy) error {
	var parsed httpRequestInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return err
	}
	if err := policy.ValidateTarget(ctx, parsed.URL); err != nil {
		return err
	}
	if err := policy.ValidatePayload(ctx, parsed.Body); err != nil {
		return err
	}
	return nil
}

func (t *HTTPRequestTool) Run(ctx context.Context, input json.RawMessage) (*ToolResult, error) {
	var parsed httpRequestInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(parsed.Method))
	if method == "" {
		method = http.MethodGet
	}
	started := time.Now().UTC()
	command := []string{"curl", "-sS", "-i", "-X", method}
	for key, value := range parsed.Headers {
		command = append(command, "-H", key+": "+value)
	}
	if parsed.Body != "" {
		command = append(command, "--data-raw", parsed.Body)
	}
	command = append(command, "-w", "\n__RABBIT_STATUS__:%{http_code}", parsed.URL)
	runResult := t.manager.Run(ctx, runner.RunRequest{
		TaskID:        parsed.TaskID,
		RunnerType:    "pentest",
		ToolName:      t.Name(),
		ImageName:     "runner-pentest",
		Command:       command,
		Timeout:       t.timeout,
		NetworkPolicy: "bridge",
	})
	statusCode, headerMap, body := parseHTTPResponse(runResult.Stdout)
	resultStatus := runResult.Status
	if statusCode == 0 {
		resultStatus = "failed"
	}
	summary := fmt.Sprintf("%s %s returned HTTP %d with %d bytes", method, parsed.URL, statusCode, len(body))
	if resultStatus == "failed" && strings.TrimSpace(runResult.Stderr) == "" && statusCode == 0 {
		runResult.Stderr = "HTTP request did not produce a valid response"
	}
	return &ToolResult{
		StartedAt:  started,
		FinishedAt: runResult.FinishedAt,
		Status:     resultStatus,
		Summary:    summary,
		Stdout:     safety.RedactSensitive(body),
		Stderr:     runResult.Stderr,
		Metadata: map[string]any{
			"statusCode":     statusCode,
			"headers":        headerMap,
			"url":            parsed.URL,
			"method":         method,
			"requestHeaders": parsed.Headers,
			"requestBody":    safety.RedactSensitive(parsed.Body),
			"image":          runResult.ImageName,
			"containerId":    runResult.ContainerID,
		},
		CommandHint: runResult.CommandPreview,
	}, nil
}

func (t *HTTPRequestTool) ExtractEvidence(ctx context.Context, result *ToolResult) ([]EvidenceDraft, error) {
	_ = ctx
	response, _ := json.Marshal(map[string]any{
		"summary": result.Summary,
		"headers": result.Metadata["headers"],
		"status":  result.Metadata["statusCode"],
	})
	target, _ := result.Metadata["url"].(string)
	request, _ := json.Marshal(map[string]any{
		"method":  result.Metadata["method"],
		"url":     result.Metadata["url"],
		"headers": result.Metadata["requestHeaders"],
		"body":    result.Metadata["requestBody"],
	})
	return []EvidenceDraft{{
		Type:             "http_exchange",
		Title:            "HTTP exchange evidence",
		Summary:          result.Summary,
		Raw:              result.Stdout,
		Target:           target,
		RequestSnapshot:  request,
		ResponseSnapshot: response,
		RelationType:     "baseline",
		Redacted:         true,
	}}, nil
}

func parseHTTPResponse(raw string) (int, map[string][]string, string) {
	statusCode := 0
	headers := map[string][]string{}
	statusMarker := "\n__RABBIT_STATUS__:"
	bodyAndMarker := raw
	if idx := strings.LastIndex(raw, statusMarker); idx >= 0 {
		bodyAndMarker = raw[:idx]
		fmt.Sscanf(raw[idx+len(statusMarker):], "%d", &statusCode)
	}
	if resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(bodyAndMarker)), nil); err == nil {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		if statusCode == 0 {
			statusCode = resp.StatusCode
		}
		for key, values := range resp.Header {
			headers[key] = append([]string{}, values...)
		}
		return statusCode, headers, string(bodyBytes)
	}
	separator := "\r\n\r\n"
	idx := strings.Index(bodyAndMarker, separator)
	if idx < 0 {
		separator = "\n\n"
		idx = strings.Index(bodyAndMarker, separator)
	}
	if idx >= 0 {
		head := bodyAndMarker[:idx]
		body := bodyAndMarker[idx+len(separator):]
		for _, line := range strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "HTTP/") || !strings.Contains(line, ":") {
				continue
			}
			key, value, _ := strings.Cut(line, ":")
			headers[key] = append(headers[key], strings.TrimSpace(value))
		}
		return statusCode, headers, body
	}
	return statusCode, headers, bodyAndMarker
}
