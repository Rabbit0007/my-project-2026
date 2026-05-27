# Phase 6 Acceptance and Hardening

## Scope

This pass verifies and hardens Phase 6. It keeps `ExplorationBudgetManager` as a guardrail layer only.

It does not add:

- new workflow engine
- new Intent table
- new Runner behavior
- fingerprint side probes
- CVE database
- packet template library
- report UI
- graph visualization
- advanced round-based decay engine

The main flow remains:

```text
Observation
-> Hypothesis
-> ValidationIntent
-> Runner
-> Evidence
-> Capability / NegativeFact / UnverifiedRisk
```

## Runtime Integration

Budget checks run before both dynamic expansion paths:

- Evidence-triggered expansion
- Capability-triggered expansion

Before `IntentService.NextPending`, the main loop still runs:

```text
StateExpansionPlanner scoring
-> ExplorationBudgetManager low-value suppression
-> IntentService.NextPending
```

BudgetManager does not execute intents, create findings, select tools, or replace `NextPending`.

## BudgetDecision

`BudgetDecision` now includes:

- `allowed`
- `decision`: `allowed`, `clamped`, `suppressed`, or `blocked`
- `reason`
- `max_generate`
- requested / allowed generation counts
- metrics snapshot
- thresholds snapshot
- suppressed hypothesis IDs
- suppressed intent IDs
- `triggered_by`

This replaces boolean-only reasoning with auditable decisions.

## Audit Events

Budget decisions emit `exploration_budget.decision` with:

- task ID
- decision
- reason
- metrics snapshot
- thresholds snapshot
- requested and allowed generation counts
- suppressed hypothesis / intent IDs
- trigger source

Suppression emits `exploration_budget.low_value_suppressed` with the same core context and explicit suppressed IDs.

Trigger sources include:

- `evidence_expansion`
- `capability_expansion`
- `pre_next_pending_suppression`

## Metrics Status

Current implementation status:

- `active_branch_count`: implemented; counts pending / validating hypotheses only.
- `pending_hypothesis_count`: implemented; mirrors active branch count in this first version.
- `pending_validation_intent_count`: implemented; counts pending intents per task.
- `intent_generation_rate`: partially implemented; dynamic-expander-created intents in the last hour.
- `graph_expansion_velocity`: partially implemented; blackboard nodes created in the last hour.
- `average_branch_value`: implemented for pending intents with `branch_value`.
- `context_growth_rate`: partially implemented; currently mirrors graph expansion velocity.

All metrics are scoped by `task_id`.

## Active Branch Definition

Active branch means:

```text
AIHypothesisNode.status IN (pending, validating)
```

Excluded:

- validated
- refuted
- suppressed
- inconclusive
- archived-like terminal states

Suppressed branches are deferred due to budget and branch value control. They are not NegativeFacts, UnverifiedRisks, validation failures, or findings.

## Low-Value Suppression

Suppression only applies to:

- pending intents
- hypothesis-backed ValidationIntents
- `priority_score <= low_value_branch_threshold`

It does not suppress:

- running intents
- completed intents
- failed intents
- cancelled intents
- non-validation intents without hypothesis metadata
- high-priority pending intents

Suppression marks:

- `AIIntent.status = suppressed`
- linked `AIHypothesisNode.status = suppressed`

`IntentService.NextPending` still filters only `status = pending`, so suppressed intents are not selected.

## Generation Limits

`max_generated_intents_per_round` is enforced through `BudgetDecision.max_generate`.

If a generator requests more than the configured limit, the decision becomes `clamped`, and expansion only keeps top branch-value candidates according to expected capability priority.

Default limits remain centralized:

- max active branches: 24
- max pending hypotheses: 80
- max pending validation intents: 40
- max generated intents per round: 3
- branch decay rounds: 3
- low-value threshold: 0.24
- low-value suppress batch: 8

## Verification

Tests cover:

- pending validation intent limit blocking
- active branch limit blocking
- per-task decision isolation
- per-round generation clamping
- BudgetDecision reason / metrics / thresholds / trigger metadata
- suppressed intent not being eligible for `NextPending`
- suppressed hypothesis not being treated as NegativeFact
- high-priority pending ValidationIntent not suppressible
- active branch status inclusion / exclusion
- low-value suppress batch limit
- top expected-capability candidates retained first
- default config values

Run:

```bash
cd backend
go test ./...
```
