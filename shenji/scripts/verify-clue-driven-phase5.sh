#!/bin/bash
# verify-clue-driven-phase5.sh
#
# Phase 5: Real LLM Worker ClueDelta Validation
# Requires: running docker compose with RABBIT_CLUE_DRIVEN_PHASE=3
#
# This script:
# 1. Checks model connectivity
# 2. Creates code_audit tasks from fixtures/vuln-labs
# 3. Polls until completion
# 4. Queries DB for clue-driven statistics
# 5. Saves artifacts to artifacts/phase5/

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:18190}"
DB_DSN="${DATABASE_DSN:-host=localhost user=shenji password=shenji dbname=shenji port=25440 sslmode=disable}"
ARTIFACTS_DIR="artifacts/phase5"
FIXTURE_DIR="fixtures/vuln-labs"
MAX_POLL_SECONDS=300
POLL_INTERVAL=10

echo "=== Phase 5: Real LLM Worker ClueDelta Validation ==="
echo "Backend: $BACKEND_URL"
echo "Artifacts: $ARTIFACTS_DIR"
echo ""

# --- Step 0: Login ---
echo "[0] Logging in..."
TOKEN=$(curl -sf "$BACKEND_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))")
if [ -z "$TOKEN" ]; then
  echo "FATAL: Login failed"
  exit 1
fi
echo "    Token obtained."

# --- Step 1: Check model connectivity ---
echo "[1] Checking model connectivity..."
MODELS=$(curl -sf "$BACKEND_URL/api/v1/model-configs" -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "[]")
BRAIN_CONFIG=$(echo "$MODELS" | python3 -c "
import sys,json
configs = json.load(sys.stdin)
brain = [c for c in configs if c.get('enabled') and c.get('purpose') == 'brain']
if brain:
    c = brain[0]
    print(f'ID={c[\"id\"]} model={c[\"model\"]} baseUrl={c[\"baseUrl\"]}')
else:
    print('NONE')
")
echo "    Brain config: $BRAIN_CONFIG"
if [ "$BRAIN_CONFIG" = "NONE" ]; then
  echo "FATAL: No enabled brain model config found. Phase 5 cannot proceed without real LLM."
  exit 1
fi

# Quick connectivity test via backend healthz (model will be tested during task execution)
echo "    Backend healthy: $(curl -sf $BACKEND_URL/healthz | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status","?"))')"

# --- Step 2: Prepare fixtures ---
echo "[2] Preparing fixtures..."
mkdir -p "$ARTIFACTS_DIR"
TASK_IDS=()

for fixture in "$FIXTURE_DIR"/*/; do
  fixture_name=$(basename "$fixture")
  echo "    Fixture: $fixture_name"
  
  # Create ZIP
  zip_path="$ARTIFACTS_DIR/${fixture_name}.zip"
  (cd "$fixture" && zip -qr - . -x "ground_truth.json" -x "README.md") > "$zip_path"
  echo "      ZIP: $zip_path"
  
  # Create task
  TASK_RESPONSE=$(curl -sf "$BACKEND_URL/api/v1/tasks" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"Phase5-ClueDriven-${fixture_name}\",
      \"taskType\": \"code_audit\",
      \"objective\": \"Clue-driven security exploration of ${fixture_name} fixture\",
      \"targets\": [],
      \"includePaths\": [],
      \"excludePaths\": [],
      \"authorizationLevel\": 1,
      \"allowChainExploration\": true,
      \"allowReadOnlyCommands\": true,
      \"isTestTask\": true
    }")
  TASK_ID=$(echo "$TASK_RESPONSE" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',0))")
  echo "      Task ID: $TASK_ID"
  
  if [ "$TASK_ID" = "0" ] || [ -z "$TASK_ID" ]; then
    echo "      ERROR: Failed to create task"
    continue
  fi
  
  # Upload ZIP
  UPLOAD_RESPONSE=$(curl -sf "$BACKEND_URL/api/v1/tasks/$TASK_ID/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@$zip_path")
  echo "      Upload: $(echo "$UPLOAD_RESPONSE" | python3 -c "import sys,json;d=json.load(sys.stdin);print(f'{len(d.get(\"files\",[]))} files')" 2>/dev/null || echo "ok")"
  
  # Start task
  curl -sf "$BACKEND_URL/api/v1/tasks/$TASK_ID/start" \
    -H "Authorization: Bearer $TOKEN" \
    -X POST > /dev/null 2>&1 || true
  echo "      Started."
  
  TASK_IDS+=("$TASK_ID")
done

if [ ${#TASK_IDS[@]} -eq 0 ]; then
  echo "FATAL: No tasks created"
  exit 1
fi

# --- Step 3: Poll until completion ---
echo "[3] Polling tasks (max ${MAX_POLL_SECONDS}s)..."
START_TIME=$(date +%s)
ALL_DONE=false

while [ "$ALL_DONE" = "false" ]; do
  ELAPSED=$(( $(date +%s) - START_TIME ))
  if [ $ELAPSED -ge $MAX_POLL_SECONDS ]; then
    echo "    TIMEOUT after ${ELAPSED}s"
    break
  fi
  
  ALL_DONE=true
  for task_id in "${TASK_IDS[@]}"; do
    STATUS=$(curl -sf "$BACKEND_URL/api/v1/tasks/$task_id" \
      -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json;d=json.load(sys.stdin);t=d.get('task',d);print(t.get('status','?'))" 2>/dev/null || echo "unknown")
    if [ "$STATUS" = "running" ] || [ "$STATUS" = "pending" ]; then
      ALL_DONE=false
    fi
  done
  
  if [ "$ALL_DONE" = "false" ]; then
    echo "    [${ELAPSED}s] Still running..."
    sleep $POLL_INTERVAL
  fi
done

# --- Step 4: Collect statistics ---
echo "[4] Collecting statistics..."
echo ""

for task_id in "${TASK_IDS[@]}"; do
  TASK_DIR="$ARTIFACTS_DIR/task-$task_id"
  mkdir -p "$TASK_DIR"
  
  # Get task detail
  DETAIL=$(curl -sf "$BACKEND_URL/api/v1/tasks/$task_id" -H "Authorization: Bearer $TOKEN")
  echo "$DETAIL" | python3 -m json.tool > "$TASK_DIR/task_detail.json" 2>/dev/null || true
  
  TASK_STATUS=$(echo "$DETAIL" | python3 -c "import sys,json;d=json.load(sys.stdin);t=d.get('task',d);print(t.get('status','?'))" 2>/dev/null || echo "?")
  TASK_NAME=$(echo "$DETAIL" | python3 -c "import sys,json;d=json.load(sys.stdin);t=d.get('task',d);print(t.get('name','?'))" 2>/dev/null || echo "?")
  
  echo "=== Task $task_id: $TASK_NAME (status: $TASK_STATUS) ==="
  
  # Get timeline
  curl -sf "$BACKEND_URL/api/v1/tasks/$task_id/timeline" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool > "$TASK_DIR/timeline.json" 2>/dev/null || true
  
  # Get tool runs
  curl -sf "$BACKEND_URL/api/v1/tasks/$task_id/tool-runs" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool > "$TASK_DIR/tool_runs.json" 2>/dev/null || true
  
  # Get evidence
  curl -sf "$BACKEND_URL/api/v1/tasks/$task_id/evidence" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool > "$TASK_DIR/evidence.json" 2>/dev/null || true
  
  # Get findings
  curl -sf "$BACKEND_URL/api/v1/tasks/$task_id/findings" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool > "$TASK_DIR/findings.json" 2>/dev/null || true
  
  # DB statistics via psql
  echo "  --- DB Statistics ---"
  
  # Intent types
  echo "  IntentType distribution:"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT intent_type, count(*) FROM ai_intents WHERE task_id=$task_id GROUP BY intent_type ORDER BY count DESC;" 2>/dev/null | head -10 || echo "    (psql unavailable)"
  
  # Clue nodes
  echo "  Clue nodes:"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT node_type, count(*) FROM ai_blackboard_nodes WHERE task_id=$task_id AND node_type LIKE 'clue_%' GROUP BY node_type ORDER BY count DESC;" 2>/dev/null | head -10 || echo "    (psql unavailable)"
  
  # Clue edges
  echo "  Clue edges:"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT edge_type, count(*) FROM ai_blackboard_edges WHERE task_id=$task_id AND edge_type LIKE 'clue_%' GROUP BY edge_type ORDER BY count DESC;" 2>/dev/null | head -10 || echo "    (psql unavailable)"
  
  # Audit events
  echo "  Audit events (clue-driven):"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT event_type, count(*) FROM ai_audit_events WHERE task_id=$task_id AND event_type LIKE 'agent.%' GROUP BY event_type ORDER BY count DESC;" 2>/dev/null | head -15 || echo "    (psql unavailable)"
  
  # Capabilities
  echo "  Capabilities:"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT strength, count(*) FROM ai_capabilities WHERE task_id=$task_id GROUP BY strength;" 2>/dev/null || echo "    (psql unavailable)"
  
  # Findings
  echo "  Findings:"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT status, count(*) FROM ai_findings WHERE task_id=$task_id GROUP BY status;" 2>/dev/null || echo "    (psql unavailable)"
  
  # Reports
  echo "  Reports:"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT status, count(*) FROM ai_reports WHERE task_id=$task_id GROUP BY status;" 2>/dev/null || echo "    (psql unavailable)"
  
  # Check for legacy vuln-type intents
  echo "  Legacy vuln-type intents (should be 0 at phase=3):"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT intent_type, count(*) FROM ai_intents WHERE task_id=$task_id AND intent_type NOT IN ('clue_collect','clue_validate','clue_refute','clue_chain_extend','scope_observation') GROUP BY intent_type;" 2>/dev/null || echo "    (psql unavailable)"
  
  # Check for delivery writeback (contract-generated intents)
  echo "  Contract-generated intents (should be 0):"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT count(*) FROM ai_intents WHERE task_id=$task_id AND created_by='contract';" 2>/dev/null || echo "    (psql unavailable)"
  
  # Model call logs
  echo "  Model calls:"
  PGPASSWORD=shenji psql -h localhost -p 25440 -U shenji -d shenji -t -c \
    "SELECT call_type, count(*), avg(latency_ms)::int as avg_ms FROM ai_model_call_logs WHERE task_id=$task_id GROUP BY call_type;" 2>/dev/null || echo "    (psql unavailable)"
  
  echo ""
done

echo "=== Phase 5 Verification Complete ==="
echo "Artifacts saved to: $ARTIFACTS_DIR/"
echo ""
echo "Next steps:"
echo "  1. Review artifacts/phase5/task-*/task_detail.json for full task state"
echo "  2. Review timeline.json for audit events and model calls"
echo "  3. Check if new_clue_facts / clue_chain_link / refuted_clue appeared in GraphDelta"
echo "  4. Verify no vuln_type / cwe / severity fields in model output"
