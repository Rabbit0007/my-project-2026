#!/bin/bash
set -euo pipefail
cd /Users/rabbit/Desktop/1/shenji

BACKEND=http://localhost:18190
TOKEN=$(curl -sf "$BACKEND/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))")

echo "=== Phase 5-B: Re-run with fixed workspace ==="
echo "HOST_WORKSPACE_ROOT in container:"
docker exec shenji-backend-1 env | grep HOST_WORKSPACE_ROOT

# Create task
TASK_ID=$(curl -sf "$BACKEND/api/v1/tasks" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"Phase5B-raw-query","taskType":"code_audit","objective":"Clue-driven exploration","targets":[],"includePaths":[],"excludePaths":[],"authorizationLevel":1,"allowChainExploration":true,"allowReadOnlyCommands":true,"isTestTask":true}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',0))")
echo "Task ID: $TASK_ID"

# Upload
curl -sf "$BACKEND/api/v1/tasks/$TASK_ID/upload" -H "Authorization: Bearer $TOKEN" -F "file=@/tmp/rqc.zip" > /dev/null
echo "Uploaded."

# Start
curl -sf "$BACKEND/api/v1/tasks/$TASK_ID/start" -H "Authorization: Bearer $TOKEN" -X POST > /dev/null
echo "Started. Polling (max 15min)..."

# Poll
for i in $(seq 1 90); do
  sleep 10
  STATUS=$(curl -sf "$BACKEND/api/v1/tasks/$TASK_ID" -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json;d=json.load(sys.stdin);t=d.get('task',d);print(t.get('status','?'))" 2>/dev/null || echo "error")
  if [ "$STATUS" != "running" ] && [ "$STATUS" != "pending" ]; then
    echo "DONE: $STATUS at $((i*10))s"
    break
  fi
  if [ $((i % 6)) -eq 0 ]; then
    echo "  [$((i*10))s] $STATUS"
  fi
done

# Results
echo ""
echo "=== RESULTS ==="
curl -sf "$BACKEND/api/v1/tasks/$TASK_ID" -H "Authorization: Bearer $TOKEN" > /tmp/phase5b_result.json
python3 << 'PYEOF'
import json
with open('/tmp/phase5b_result.json') as f:
    d = json.load(f)
t = d.get('task', d)
print(f"Status: {t.get('status')}")
print(f"Progress: {t.get('progressStage')}")
intents = d.get('intents', [])
print(f"Intents: {len(intents)}")
types = {}
for i in intents:
    tp = i.get('intentType', '?')
    types[tp] = types.get(tp, 0) + 1
for tp, cnt in sorted(types.items(), key=lambda x: -x[1]):
    print(f"  {tp}: {cnt}")
modern_set = {'clue_collect','clue_validate','clue_refute','clue_chain_extend','scope_observation'}
legacy = [i for i in intents if i.get('intentType','') not in modern_set]
print(f"Legacy vuln-type intents: {len(legacy)}")
findings = d.get('findings', [])
print(f"Findings: {len(findings)}")
reports = d.get('reports', [])
print(f"Reports: {len(reports)}")
evidence = d.get('evidence', [])
print(f"Evidence: {len(evidence)}")
toolruns = d.get('toolRuns', [])
print(f"ToolRuns: {len(toolruns)}")
tr_status = {}
for tr in toolruns:
    s = tr.get('status', '?')
    tr_status[s] = tr_status.get(s, 0) + 1
print(f"  Statuses: {tr_status}")
contract_intents = [i for i in intents if i.get('createdBy') == 'contract']
print(f"Contract-generated intents: {len(contract_intents)}")
print()
print("=== VERIFICATION ===")
print(f"[{'PASS' if len(legacy)==0 else 'FAIL'}] All IntentTypes modern")
print(f"[{'PASS' if len(contract_intents)==0 else 'FAIL'}] No contract intents")
print(f"[{'PASS' if len(reports)>0 else 'FAIL'}] Report generated")
print(f"[{'PASS' if tr_status.get('success',0)>0 else 'FAIL'}] ToolRun success > 0")
print(f"[{'PASS' if len(evidence)>0 else 'FAIL'}] Evidence > 0")
print(f"[{'PASS' if t.get('status')=='completed' else 'FAIL'}] Task completed")
PYEOF
