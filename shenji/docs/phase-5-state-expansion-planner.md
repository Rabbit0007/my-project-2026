# Phase 5: State Expansion Planner

## Scope

This phase adds a first executable State Expansion Planner layer. It does not replace the existing model-assisted reasoner. Instead, it gives the current Cairn loop a deterministic branch-value scoring pass before selecting the next pending `AIIntent`.

## What Was Implemented

### Branch Value Scoring

`StateExpansionPlannerService` scores each pending ValidationIntent that is linked to a `HypothesisNode`.

The score includes:

- `capability_unlock_score`
- `graph_expansion_score`
- `novelty_score`
- `risk_value`
- `coverage_gain`
- `execution_cost`
- `safety_risk`
- `duplicate_penalty`
- `evidence_quality`

The final value is written back to:

- `AIIntent.PriorityScore`
- `AIIntent.ConstraintsJSON.branch_value`

### Goal-Aware Priority

Scoring changes by `GoalProfile.GoalType`:

- `terminal`: boosts branches aligned with the explicit proof objective.
- `coverage`: keeps coverage gain as a secondary scoring factor.
- `expansion`: boosts capabilities that advance the Objective Ladder, such as credentials, authenticated session, internal service access, lateral access, and admin access.

### Environment-Aware Expansion Value

The planner reads `AIEnvironmentModel` and gives higher graph-expansion value when the hypothesis matches the detected environment.

Examples:

- Kubernetes environment + service account / namespace hypothesis
- Java/Spring environment + deserialization / XXE hypothesis
- PHP environment + upload / file / SQL hypothesis
- token or cookie session model + auth/session hypotheses

### NegativeFact Penalty

Branches matching an existing `NegativeFact.SimilarPatternKey` receive a strong duplicate penalty. This supports the requirement that refuted paths reduce priority of similar hypotheses and intents.

### Runtime Integration

Before every `NextPending` selection, the Cairn loop runs the planner scoring pass. Existing `IntentService.NextPending` still selects by `priority_score desc, created_at asc`, so this phase does not introduce a parallel workflow engine.

## Files

- `backend/internal/service/state_expansion_planner_service.go`
- `backend/internal/service/agent_orchestrator.go`
- `backend/internal/service/state_expansion_planner_service_test.go`

## Verification

Automated tests cover:

- terminal goal capability prioritization
- NegativeFact duplicate penalty
- EnvironmentModel alignment boosting graph expansion

Run:

```bash
cd backend
go test ./...
```

## Remaining Work

This phase provides branch-value scoring but not full round-based decay. Phase 6 should introduce the ExplorationBudgetManager with active branch limits, pending hypothesis and intent limits, intent generation throttling, and low-value branch decay over time.
