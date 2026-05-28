# Coverage-Oriented GoalState Diagnosis

## 1. Current stop behavior

The loop stops when iteration budget is exhausted, repeated no-progress rounds reach the configured threshold, or no actionable runtime intents remain after verified capabilities exist. Finding count is not used as a termination signal.

## 2. VerifiedCapability behavior

Before this phase, `ShouldFinalizeWithNoProgressLimit` still had a legacy fallback: if a verified capability existed, iteration number was greater than five, and no runtime intent was pending, the task could finalize. That was safe for single-path terminal goals but too early for coverage-oriented security discovery.

After this phase, verified capabilities are output artifacts. They can mark a matching coverage surface as `resolved_verified`, but they do not satisfy the global goal while high-priority unresolved surfaces or high-priority intents remain.

## 3. Open intent participation

Pending runtime intents already prevented finalization. This phase adds coverage-aware high-priority intent accounting through `CoverageState.open_high_priority_intents`, including intent priority and unresolved surface references.

## 4. NegativeFact participation

Before this phase, NegativeFacts suppressed repeated intents and contributed to graph context, but they did not directly resolve coverage surfaces. This phase maps NegativeFacts onto matching coverage surfaces as `resolved_refuted`, `blocked`, `out_of_scope`, or `inconclusive`, then exposes those transitions in `CoverageState`.

## 5. GraphSummary coverage

Before this phase, GraphSummary had facts, intents, evidence, negative facts, capability candidates, verified capabilities, unknowns, hints, and budget state. It did not include surface coverage or a coverage-oriented goal state.

After this phase, GraphSummary includes `coverage_state` and a richer `goal_state` with status, coverage summary, unresolved high-priority surface count, open high-priority intent count, stop reason, and `should_continue`.

## 6. Reason prompt

Before this phase, prompts preferred generic graph-search intents and treated vulnerability type as a result label, but did not explicitly state that a verified capability is not a global stop condition.

After this phase, planner and worker prompts state that verified capability is an output item, not a global stop condition, and that unresolved high-priority surfaces should continue unless budget is exhausted or coverage is sufficient.

## 7. Finding / Report / Contract direction

Core exploration remains driven by GraphSummary, CoverageState, Evidence, NegativeFacts, Capabilities, and Intents. Findings, reports, and contracts remain delivery-layer artifacts and are not included as core planning inputs in GraphSummary.

## 8. Minimal refactor

The implementation reuses existing `AICoverageItem`, `AIIntent`, `AINegativeFact`, `AICapability`, `AIEvidence`, and blackboard nodes. It adds coverage-oriented summary structures, stop logic, prompt rules, coverage priority scoring, and tests without adding a separate isolated goal/fact/intent/evidence model.
