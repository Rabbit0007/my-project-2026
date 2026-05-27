# Phase 6: Exploration Budget Manager

## Scope

This phase adds `ExplorationBudgetManager` as a guardrail layer for hypothesis-driven exploration. It does not introduce a new workflow engine, new Intent table, new Runner behavior, fingerprint side probes, CVE database, report UI, or graph visualization.

The manager limits exploration growth while preserving the existing flow:

```text
Observation -> Hypothesis -> ValidationIntent -> Runner -> Evidence -> Capability / NegativeFact / UnverifiedRisk
```

## Responsibilities

`ExplorationBudgetManager` tracks:

- `active_branch_count`
- `pending_hypothesis_count`
- `pending_validation_intent_count`
- `intent_generation_rate`
- `graph_expansion_velocity`
- `average_branch_value`
- `context_growth_rate`

It enforces:

- `max_active_branches_per_task`
- `max_pending_hypotheses_per_task`
- `max_pending_validation_intents_per_task`
- `max_generated_intents_per_round`
- low-value branch suppression

## Runtime Integration

The budget manager is used by both dynamic expansion paths:

- Evidence-triggered expansion
- Capability-triggered expansion

Before forming new hypotheses and ValidationIntents, the expander asks the budget manager for a `BudgetDecision`.

If budget remains:

- generation is allowed
- max generated items are clamped to the configured per-round limit

If budget is exceeded:

- low-value branches are suppressed first
- if still over limit, generation is blocked
- an audit event records the reason and metrics

## Low-Value Branch Suppression

After planner scoring and before `IntentService.NextPending`, the Cairn loop asks the manager to suppress low-value pending branches.

Suppression only applies to:

- pending intents
- hypothesis-backed validation intents
- branch priority at or below `low_value_branch_threshold`

When suppressed, both the pending `AIIntent` and linked `AIHypothesisNode` are marked `suppressed`.

## Design Boundaries

The manager does not:

- execute intents
- choose tools
- replace `IntentService.NextPending`
- replace model-assisted reasoning
- create a parallel workflow engine
- directly create findings

It only gates generation and suppresses stale or low-value pending work.

## Defaults

Default limits:

- max active branches: 24
- max pending hypotheses: 80
- max pending validation intents: 40
- max generated intents per round: 3
- branch decay rounds: 3
- low-value threshold: 0.24
- low-value suppress batch: 8

These are intentionally conservative and can be tuned later.

## Verification

Tests cover:

- blocking when pending validation intent limit is exceeded
- blocking when active branch limit is exceeded
- per-round generation clamping
- low-value suppression eligibility

Run:

```bash
cd backend
go test ./...
```

## Remaining Work

This phase implements hard limits and low-value suppression. More advanced round-based decay can later use loop iteration history to reduce branch value over time, but that is intentionally not introduced here as a separate workflow mechanism.
