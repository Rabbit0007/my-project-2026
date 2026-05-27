#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:18190}"
TMP_DIR="$(mktemp -d /tmp/rabbit-smoke.XXXXXX)"
CODE_ZIP="$TMP_DIR/code-audit-smoke.zip"
CODE_TASK_ID=""
PENTEST_TASK_ID=""
ARCHIVE_ON_EXIT="${ARCHIVE_ON_EXIT:-true}"

cleanup() {
  rm -rf "$TMP_DIR"
  if [[ "$ARCHIVE_ON_EXIT" == "true" ]]; then
    if [[ -n "$CODE_TASK_ID" ]]; then
      curl -sS -X POST "$BASE_URL/api/v1/tasks/$CODE_TASK_ID/archive" \
        -H 'Content-Type: application/json' \
        -d '{"archived":true}' >/dev/null || true
    fi
    if [[ -n "$PENTEST_TASK_ID" ]]; then
      curl -sS -X POST "$BASE_URL/api/v1/tasks/$PENTEST_TASK_ID/archive" \
        -H 'Content-Type: application/json' \
        -d '{"archived":true}' >/dev/null || true
    fi
  fi
}
trap cleanup EXIT

log() {
  printf '[smoke] %s\n' "$1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

poll_task_completed() {
  local task_id="$1"
  local attempts="${2:-90}"
  local response=""
  local status=""

  for _ in $(seq 1 "$attempts"); do
    response="$(curl -sS "$BASE_URL/api/v1/tasks/$task_id")"
    status="$(printf '%s' "$response" | jq -r '.task.status')"
    case "$status" in
      completed)
        printf '%s' "$response"
        return 0
        ;;
      failed|cancelled)
        echo "task $task_id ended with status=$status" >&2
        printf '%s\n' "$response" >&2
        return 1
        ;;
    esac
    sleep 1
  done

  echo "task $task_id did not complete within timeout" >&2
  printf '%s\n' "$response" >&2
  return 1
}

assert_jq() {
  local json="$1"
  local expr="$2"
  local message="$3"
  if ! printf '%s' "$json" | jq -e "$expr" >/dev/null; then
    echo "assertion failed: $message" >&2
    printf '%s\n' "$json" | jq '.' >&2
    exit 1
  fi
}

require_cmd curl
require_cmd jq
require_cmd zip

log "Checking backend health"
curl -fsS "$BASE_URL/healthz" >/dev/null

log "Preparing code audit smoke ZIP"
cat >"$TMP_DIR/main.go" <<'EOF'
package main

import "os/exec"

func main() {
	_, _ = exec.Command("sh", "-c", "echo hi").CombinedOutput()
}
EOF
(cd "$TMP_DIR" && zip -q "$CODE_ZIP" main.go)

log "Creating code audit smoke task"
CODE_CREATE_RESPONSE="$(
  curl -sS -X POST "$BASE_URL/api/v1/tasks" \
    -H 'Content-Type: application/json' \
    -d '{
      "name":"Smoke Code Audit First Stage",
      "taskType":"code_audit",
      "objective":"Validate the first-stage code audit closed loop end to end.",
      "targets":[],
      "includePaths":[],
      "excludePaths":[],
      "authorizationLevel":1,
      "allowChainExploration":false,
      "allowReadOnlyCommands":true,
      "isTestTask":true
    }'
)"
CODE_TASK_ID="$(printf '%s' "$CODE_CREATE_RESPONSE" | jq -r '.id')"

log "Uploading code audit ZIP to task $CODE_TASK_ID"
curl -sS -X POST "$BASE_URL/api/v1/tasks/$CODE_TASK_ID/upload" -F "file=@$CODE_ZIP" >/dev/null

log "Starting code audit task $CODE_TASK_ID"
curl -sS -X POST "$BASE_URL/api/v1/tasks/$CODE_TASK_ID/start" >/dev/null

log "Waiting for code audit task completion"
CODE_DETAIL="$(poll_task_completed "$CODE_TASK_ID")"

assert_jq "$CODE_DETAIL" '.toolRuns | length >= 4' 'code audit should create multiple tool runs'
assert_jq "$CODE_DETAIL" '.evidence | length >= 4' 'code audit should create evidence'
assert_jq "$CODE_DETAIL" '.contractChecks | any(.status == "passed")' 'code audit contract should pass'
assert_jq "$CODE_DETAIL" '.findings | any(.status == "dynamically_validated")' 'code audit should dynamically validate a finding'
assert_jq "$CODE_DETAIL" '.toolRuns | any(.toolName == "code_search" and (.containerId | length > 0))' 'code_search should have a real container id'
assert_jq "$CODE_DETAIL" '.toolRuns | any(.toolName == "sandbox_exec" and (.containerId | length > 0))' 'sandbox_exec should have a real container id'
assert_jq "$CODE_DETAIL" '.evidence | all(.rawRef | startswith("minio://"))' 'code audit evidence should be stored in MinIO'
assert_jq "$CODE_DETAIL" '.reports | all(.markdownRef | startswith("minio://"))' 'code audit reports should be stored in MinIO'

log "Creating pentest smoke task"
PENTEST_CREATE_RESPONSE="$(
  curl -sS -X POST "$BASE_URL/api/v1/tasks" \
    -H 'Content-Type: application/json' \
    -d '{
      "name":"Smoke Pentest First Stage",
      "taskType":"pentest",
      "objective":"Validate the first-stage pentest closed loop end to end.",
      "targets":["http://host.docker.internal:18190/healthz"],
      "includePaths":[],
      "excludePaths":[],
      "authorizationLevel":1,
      "allowChainExploration":false,
      "allowReadOnlyCommands":true,
      "isTestTask":true
    }'
)"
PENTEST_TASK_ID="$(printf '%s' "$PENTEST_CREATE_RESPONSE" | jq -r '.id')"

log "Starting pentest task $PENTEST_TASK_ID"
curl -sS -X POST "$BASE_URL/api/v1/tasks/$PENTEST_TASK_ID/start" >/dev/null

log "Waiting for pentest task completion"
PENTEST_DETAIL="$(poll_task_completed "$PENTEST_TASK_ID")"

assert_jq "$PENTEST_DETAIL" '.toolRuns | any(.toolName == "http_request")' 'pentest should perform HTTP requests'
assert_jq "$PENTEST_DETAIL" '.toolRuns | any(.toolName == "http_request" and .status == "success")' 'pentest HTTP request should succeed'
assert_jq "$PENTEST_DETAIL" '.toolRuns | any(.toolName == "http_request" and (.containerId | length > 0))' 'pentest HTTP request should have a real container id'
assert_jq "$PENTEST_DETAIL" '.toolRuns | any(.toolName == "response_diff")' 'pentest should perform response diff'
assert_jq "$PENTEST_DETAIL" '.evidence | any(.evidenceType == "http_exchange")' 'pentest should record HTTP exchange evidence'
assert_jq "$PENTEST_DETAIL" '.evidence | any(.evidenceType == "response_diff")' 'pentest should record response diff evidence'
assert_jq "$PENTEST_DETAIL" '.contractChecks | any(.status == "passed")' 'pentest contract should pass'
assert_jq "$PENTEST_DETAIL" '.findings | any(.status == "dynamically_validated")' 'pentest should dynamically validate a finding'
assert_jq "$PENTEST_DETAIL" '.evidence | all(.rawRef | startswith("minio://"))' 'pentest evidence should be stored in MinIO'
assert_jq "$PENTEST_DETAIL" '.reports | all(.htmlRef | startswith("minio://"))' 'pentest reports should be stored in MinIO'

log "All first-stage smoke checks passed"
printf 'CODE_TASK_ID=%s\n' "$CODE_TASK_ID"
printf 'PENTEST_TASK_ID=%s\n' "$PENTEST_TASK_ID"
