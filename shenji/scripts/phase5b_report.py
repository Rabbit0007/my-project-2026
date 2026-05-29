import json, sys

path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/phase5b_final.json'
with open(path) as f:
    d = json.load(f)

t = d.get('task', d)
print("=" * 60)
print("PHASE 5-B FINAL REPORT: Task 90")
print("=" * 60)
print(f"Status: {t.get('status')}")
print(f"Progress: {t.get('progressStage')}")
print()

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
print(f"\nLegacy vuln-type intents: {len(legacy)}")
for l in legacy[:5]:
    print(f"  LEGACY: {l.get('intentType')} - {l.get('title','')[:50]}")

findings = d.get('findings', [])
print(f"\nFindings: {len(findings)}")
for f_item in findings[:5]:
    print(f"  [{f_item.get('severity')}] {f_item.get('title','')[:60]}")

reports = d.get('reports', [])
print(f"\nReports: {len(reports)}")
for r in reports:
    print(f"  [{r.get('status')}] {r.get('title','')[:50]}")

evidence = d.get('evidence', [])
print(f"\nEvidence: {len(evidence)}")
for e in evidence[:5]:
    print(f"  [{e.get('evidenceType')}] {e.get('title','')[:50]}")

toolruns = d.get('toolRuns', [])
print(f"\nToolRuns: {len(toolruns)}")
tr_status = {}
for tr in toolruns:
    s = tr.get('status', '?')
    tr_status[s] = tr_status.get(s, 0) + 1
print(f"  Statuses: {tr_status}")

contract_intents = [i for i in intents if i.get('createdBy') == 'contract']
print(f"\nContract-generated intents: {len(contract_intents)}")

print()
print("=" * 60)
print("VERIFICATION CHECKLIST")
print("=" * 60)
print(f"[{'PASS' if len(legacy)==0 else 'FAIL'}] All IntentTypes in modern set")
print(f"[{'PASS' if len(contract_intents)==0 else 'FAIL'}] No contract-generated intents")
print(f"[{'PASS' if len(reports)>0 else 'FAIL'}] Report generated")
print(f"[{'PASS' if tr_status.get('success',0)>0 else 'FAIL'}] ToolRun success > 0 (got {tr_status.get('success',0)})")
print(f"[{'PASS' if len(evidence)>0 else 'FAIL'}] Evidence > 0 (got {len(evidence)})")
print(f"[{'PASS' if t.get('status')=='completed' else 'FAIL'}] Task completed (status={t.get('status')})")
print(f"[INFO] ToolRun failed: {tr_status.get('failed',0)}")
print(f"[INFO] Findings: {len(findings)}")
