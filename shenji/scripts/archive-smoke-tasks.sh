#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:18190}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

echo "[archive-smoke] fetching tasks"
TASKS_JSON="$(curl -sS "$BASE_URL/api/v1/tasks?include_archived=true&include_tests=true")"

MATCHED_IDS="$(printf '%s' "$TASKS_JSON" | jq -r '.[] | select((.archived == false) and ((.isTestTask == true) or (.name | test("Smoke")))) | .id')"

if [[ -z "$MATCHED_IDS" ]]; then
  echo "[archive-smoke] no active smoke tasks found"
  exit 0
fi

while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  echo "[archive-smoke] archiving task $id"
  curl -sS -X POST "$BASE_URL/api/v1/tasks/$id/archive" \
    -H 'Content-Type: application/json' \
    -d '{"archived":true}' >/dev/null
done <<< "$MATCHED_IDS"

echo "[archive-smoke] done"
