# Phase 5 Verification and Hardening

## Scope

This pass reviews and hardens Phase 5 / Phase 5.1. It does not implement Phase 6 and does not introduce a workflow engine, new Intent table, new Runner behavior, report UI, graph visualization, CVE database, or round-based branch decay.

The planner remains a deterministic ordering layer immediately before `IntentService.NextPending`.

## Verified Integration

The Cairn loop calls `StateExpansionPlannerService.ScorePendingValidationIntents` before selecting the next pending intent. Selection still flows through:

```text
IntentService.NextPending
ORDER BY priority_score DESC, created_at ASC
```

The planner does not execute intents, does not replace the Runner, and does not replace the model-assisted reasoner.

## Hardening Changes

### Auditability

The planner audit event now records:

- pending intent count
- scored intent count
- skipped intents without validation metadata
- skipped intents with missing hypothesis
- top intent ID and top score
- number of branches with NegativeFact penalty
- number of branches with EnvironmentModel boost or penalty

This gives enough signal to debug ranking behavior without logging sensitive payloads.

### Branch Value Integrity

Each scored ValidationIntent writes:

- `AIIntent.PriorityScore`
- `AIIntent.ConstraintsJSON.branch_value`

`branch_value.final_score` is the same value used for `PriorityScore`.

### Accessor Compatibility

The typed accessors preserve each other:

- writing `BranchValue` does not remove validation metadata
- writing validation metadata does not remove `BranchValue`
- unrelated `ConstraintsJSON` fields are preserved
- old intents without `branch_value` return nil safely

### Weight Ordering

Default weights are centralized in `DefaultStateExpansionScoringWeights()` and preserve:

```text
Capability expansion > Graph expansion > Risk value > Novelty > Coverage gain
```

Coverage remains secondary and cannot dominate capability or graph expansion in the regression tests.

### NegativeFact Penalty

Duplicate or refuted branches:

- receive a real duplicate penalty
- score lower than equivalent clean branches
- record `negative_fact_refs`
- explain the penalty source in `reason`

### Environment Confidence

Environment alignment distinguishes:

- `confirmed`
- `validated`
- `strong`
- `plausible`
- `suspected`
- `unknown`
- `refuted`

Confirmed and validated signals score no lower than strong signals. Refuted signals lower branch value and are recorded in `matched_environment_refs` and `reason`.

### Evidence Quality and Novelty

Evidence quality is no longer constant. It considers baseline evidence, response diffs, marker behavior, raw request/response snapshots, reproducibility, authorization, and safety context.

Novelty is no longer constant. It considers new targets, parameter-like targets, new hypothesis types, new capability types, and overlap with NegativeFacts or already acquired capabilities.

## Test Coverage

Tests now cover:

- terminal goal capability prioritization
- expansion goal Objective Ladder explanation
- coverage not dominating capability unlock
- NegativeFact penalty lowering score
- NegativeFact reason and refs
- NegativeFact-penalized branch ranking below equivalent clean branch
- strong EnvironmentModel alignment outranking suspected
- confirmed / validated no lower than strong
- refuted EnvironmentModel lowering score
- `branch_value` typed accessor round-trip
- `WithBranchValue` preserving validation metadata
- `WithValidationMetadata` preserving branch value
- evidence quality is not constant
- novelty score is not constant
- `branch_value.final_score` equals assigned intent priority
- default weight ordering keeps coverage secondary

Run:

```bash
cd backend
go test ./...
```
