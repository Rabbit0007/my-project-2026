# Hypothesis-Driven Autonomous Security Exploration

## Purpose

This document defines the first implementation milestone for evolving Shenji from a checklist-oriented security audit loop into a hypothesis-driven exploration system.

Rabbit is not a scanner. Rabbit is not a CVE/PoC search engine. Rabbit is not a report-first vulnerability formatter. Rabbit is a Cairn-style state-space exploration system.

Tools only observe or validate. Findings are delivery artifacts. Contracts are report quality gates. Reports are outputs. The graph exploration loop is the product.

The first milestone must prove this loop end to end:

```text
Observation
-> Hypothesis
-> ValidationIntent
-> Runner execution
-> Evidence
-> Hypothesis validated/refuted/inconclusive
-> Capability / NegativeFact / UnverifiedRisk
-> DynamicIntentExpander creates the next high-value hypothesis
```

Report UI, graph visualization, CVE/PoC lookup, and coverage matrix polish are intentionally out of scope until this loop works.

## Architecture Slice

The implementation reuses the existing Cairn runtime:

- `AIIntent` remains the ValidationIntent storage primitive.
- `ConstraintsJSON` carries backward-compatible validation metadata.
- Typed accessors on `AIIntent` keep planners and expanders from raw JSON parsing.
- `AIBlackboardNode` / `AIBlackboardEdge` mirror every lifecycle transition.
- `AICapability` remains the capability table, now with nullable hypothesis backing fields.
- New first-class tables store GoalProfile, HypothesisNode, NegativeFact, UnverifiedRisk, CoverageItem, and EnvironmentModel.

## Data Model

### GoalProfile

`AIGoalProfile` frames the exploration goal.

- `GoalType`: `terminal`, `coverage`, `expansion`
- `Mode`: `code_audit`, `web_pentest`, `internal_pentest`, `terminal_proof`
- `CompletionPolicy`: JSON thresholds and budgets

Default inference:

- `code_audit` -> `coverage`
- `pentest` -> `coverage`
- `internal_pentest` -> `expansion`
- explicit proof language -> `terminal`
- `hybrid` -> infer from user objective, default `coverage`

### HypothesisNode

`AIHypothesisNode` represents a potential security truth requiring validation.

Lifecycle states:

- `suspected`, `plausible`, `strong`
- `validated`, `refuted`, `inconclusive`

Status values track execution state:

- `pending`, `validating`, `validated`, `refuted`, `inconclusive`, `suppressed`

### ValidationIntent Metadata

The existing `AIIntent.ConstraintsJSON` stores:

- `hypothesis_id`
- `validation_method`
- `expected_evidence`
- `expected_capability`
- `success_condition`
- `failure_condition`
- `safety_level`
- `environment_context_snapshot`

Code must use `ValidationMetadata()` / `WithValidationMetadata()` instead of hand-parsing these fields.

### Capability Backing

Every new `AICapability` should be linked to:

- `ValidatedByHypothesisID`
- `DerivedFromEvidenceRefs`

If legacy code creates a capability without a hypothesis, the lifecycle service creates a synthetic `legacy_hypothesis` node before capability promotion.

## Runtime Flow

1. Task creation ensures a default GoalProfile.
2. Bootstrap creates an initial HypothesisNode from task origin and user objective.
3. The initial AIIntent is annotated as a ValidationIntent for that hypothesis.
4. Runner execution produces ToolRun and Evidence nodes.
5. After execution, the lifecycle service resolves the linked hypothesis:
   - evidence + success -> validated
   - failed validation -> NegativeFact
   - blocked or inconclusive -> UnverifiedRisk
6. Validated hypotheses can create capabilities.
7. Capability creation mirrors graph edges:
   - `capability -> derived_from -> evidence`
   - `capability -> validated_by -> hypothesis`
8. Dynamic expansion receives the capability and forms contextual follow-up hypotheses, with duplicate and NegativeFact suppression.

## Contextual Expansion v1

The first implementation uses conservative contextual patterns as scaffolding, but each generated hypothesis carries source observations, expected capability, validation method, environment snapshot, and graph links.

Examples:

- `file_read` over config-like targets -> secret discovery hypothesis
- `secret_discovered` -> credential reuse / authenticated session hypothesis
- `command_execution` with Kubernetes environment signal -> service account / namespace secret hypothesis
- `authenticated_session` -> authorization boundary / admin access hypothesis

These are not findings. They only become findings after validation evidence and capability chains exist.

## Budget Guardrails v1

The first milestone includes simple hard limits:

- pending hypotheses per task
- pending validation intents per task
- generated intents per expansion round

Later phases should replace these with branch value decay, graph velocity, and context growth tracking.

## Audit Trail

The system records audit events for:

- default goal profile creation
- hypothesis formation
- validation intent generation
- hypothesis validation/refutation/inconclusive resolution
- capability generation
- dynamic expansion suppression and generation

## Next Phases

After the lifecycle loop is proven:

1. EnvironmentModel updates from facts/evidence/tool runs
2. State Expansion Planner branch value scoring
3. ExplorationBudgetManager decay and throttling
4. Fingerprint as EnvironmentModel / Blackboard Fact signal only
5. Evidence-backed exploration narrative in reports
