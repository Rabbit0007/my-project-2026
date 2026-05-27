# Phase 5.1: State Expansion Planner Explainability and Weight Hardening

## Scope

This phase hardens the Phase 5 State Expansion Planner. It does not introduce a new workflow engine, new Intent table, round-based decay, ExplorationBudgetManager, fingerprint side probes, CVE database, report UI, or graph visualization.

The goal is to make planner scoring:

- explainable
- auditable
- centrally weighted
- testable
- backward compatible with existing `AIIntent.ConstraintsJSON`

## Branch Value Structure

Every scored ValidationIntent stores a typed `branch_value` object in `AIIntent.ConstraintsJSON`.

The structure includes:

- capability unlock score
- graph expansion score
- novelty score
- risk value
- coverage gain
- execution cost
- safety risk
- duplicate penalty
- evidence quality
- goal type boost
- environment alignment boost
- final score
- human-readable reason
- negative fact references
- matched environment references
- scored timestamp

`branch_value.final_score` is written back to `AIIntent.PriorityScore`, so persisted score details and scheduler priority remain aligned.

## Typed Accessors

`AIIntent` now exposes:

- `BranchValue() (*BranchValue, error)`
- `WithBranchValue(BranchValue) error`

These accessors preserve existing fields in `ConstraintsJSON`, including validation metadata written by:

- `ValidationMetadata()`
- `WithValidationMetadata()`

Old intents without `branch_value` safely return `nil`.

## Central Weights

Weights are defined by `StateExpansionScoringWeights` and `DefaultStateExpansionScoringWeights()`.

The default ordering preserves the core exploration principle:

```text
Capability expansion
>
Graph expansion
>
Risk value
>
Novelty
>
Coverage gain
```

Coverage remains a secondary factor. It can help order similar branches, but it cannot dominate high capability or graph expansion branches.

## NegativeFact Explainability

When a hypothesis branch matches a refuted pattern:

- `duplicate_penalty` is increased.
- `negative_fact_refs` records the matching `NegativeFact` ID.
- `reason` names the penalty source.

This keeps suppression and deprioritization auditable rather than silently changing scheduler behavior.

## Environment Confidence

Environment-aware scoring now distinguishes confidence states:

- `confirmed` / `validated`: high boost
- `strong`: medium-high boost
- `plausible`: medium boost
- `suspected`: low boost
- `unknown`: no boost
- `refuted`: negative boost

Matched signals are recorded in `matched_environment_refs`, such as:

```text
orchestration_layer.kubernetes=strong
```

If an environment signal refutes a branch, the final score is lowered and the reason says so.

## Evidence Quality and Novelty

Evidence quality now considers whether validation expects or preserves:

- baseline evidence
- response diff evidence
- successful marker behavior
- raw request / response snapshots
- reproducible proof conditions
- authorization and safety context

Novelty now considers:

- new target / endpoint
- parameter-like targets
- new hypothesis type
- new capability type
- overlap with NegativeFacts

These are intentionally simple first-pass heuristics with clear extension points.

## Verification

Tests cover:

- terminal goal capability prioritization
- coverage gain not dominating capability unlock
- NegativeFact duplicate penalty lowering score
- NegativeFact reason and refs
- strong environment alignment outranking suspected
- refuted environment signal lowering score
- branch value typed accessor round-trip
- branch value write preserving validation metadata

Run:

```bash
cd backend
go test ./...
```
