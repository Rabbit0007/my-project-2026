# Clue-Driven Exploration Realignment — Requirements

> EARS 风格硬性要求。每条 requirement 使用 WHERE / WHILE / WHEN / IF / THEN / THE / SHALL 关键词。
> 对应 design.md 中的分层架构、Clue 模型、Migration Plan。

---

## Introduction

本文档定义 Rabbit 系统从 vulnerability/finding/report-driven 回正为 clue-driven 的硬性验收要求。所有 requirement 必须在对应 Phase 上线前通过测试验证。

## Glossary

| 术语 | 定义 |
|---|---|
| Clue | 安全探索中的第一对象：Fact / Intent / Evidence / NegativeFact / Capability 的统称 |
| ClueChain | 由 clue_origin → clue_link(s) → clue_impact 组成的有向路径，通过 AIBlackboardEdge 连接 |
| Clue Role | Clue 在安全影响链中的作用：origin_or_entry / trigger_or_control / reachability_or_relation / security_effect_or_impact / control_state_or_missing_control / verification_or_observation |
| Role Coverage | ClueChain 上所有节点 roles 并集覆盖 requiredClueRoles 的程度 |
| Kernel | Layer 1，Cairn Loop 内核 |
| Exploration | Layer 2，Security Exploration 策略层 |
| Tool Collection | Layer 3，工具采集层 |
| Evidence Gate | Layer 4，证据闸门层 |
| Delivery Layer | Layer 5，交付层（Finding / Contract / Report） |
| Sanitizer | 模型输出落图前的清洗器，剥离 vuln-type / report-style 字段 |
| NormalizeIntentType | 将 legacy vuln-type intent 映射为通用 clue intent 的纯函数 |

---

## Requirements

### Requirement 1: Layer Separation — Reason Path

**User Story:** As a platform maintainer, I want the Reason path (Kernel + Exploration) to not depend on Finding / Contract / Report services for its core decisions, so that the exploration loop stays clue-driven.

#### Acceptance Criteria

1. WHEN the Kernel or Exploration layer performs scheduling, reasoning, graph mutation, promotion, or termination decisions, THE system SHALL NOT invoke or depend on `FindingService`, `ContractService`, or `ReportService`.
2. WHEN the Kernel or Exploration layer executes, THE system SHALL NOT read `AIFinding` / `AIContractCheckResult` / `AIReport` rows as input to scheduling or termination decisions.
3. WHERE a function in `agent_orchestrator.go` or `cairn_loop.go` currently calls `FindingService` or `ContractService` for Reason purposes, THE system SHALL remove or relocate that call to the Delivery Layer.

### Requirement 2: Layer Separation — Delivery Writeback Isolation

**User Story:** As a platform maintainer, I want the Delivery Layer to never write back Intent / Hypothesis / Capability / Edge / Node into the kernel graph, so that report concerns cannot pollute exploration.

#### Acceptance Criteria

1. THE Delivery Layer SHALL NOT create or modify `AIIntent` / `AIHypothesisNode` / `AICapability` / `AIBlackboardNode` / `AIBlackboardEdge` records.
2. IF `ContractService` detects an incomplete contract, THEN THE system SHALL only emit an audit event and a Delivery-internal diagnostic; it SHALL NOT spawn an Intent.
3. THE `ReportService` SHALL NOT trigger any ClueDelta or graph mutation.
4. WHERE the runtime toggle `RABBIT_DELIVERY_WRITEBACK` is set to `on`, THE system SHALL temporarily re-enable the legacy writeback path for rollback purposes only.

### Requirement 3: Clue Model

**User Story:** As a security engineer, I want all new graph nodes written by the core exploration path to use clue_* NodeTypes, so that the blackboard is semantically aligned with clue-driven exploration.

#### Acceptance Criteria

1. WHEN the Graph Search, Exploration, or Evidence Gate core path creates a new `AIBlackboardNode`, THE NodeType SHALL be one of: `clue_origin`, `clue_observation`, `clue_link`, `clue_refuted`, `clue_impact`, or `tool_error_clue`.
2. WHEN the system creates a new `AIBlackboardEdge` for clue relationships, THE EdgeType SHALL be one of: `clue_supports`, `clue_refutes`, `clue_chains_to`.
3. WHILE legacy NodeTypes (`fact`, `surface_fact`, `code_fact`, `hypothesis`, `negative_fact`, etc.) exist in the database, THE system SHALL read them via a mapping function that assigns default Clue Roles without modifying the stored NodeType.
4. THE system SHALL NOT require a DB migration to rename existing NodeType values.
5. THE Delivery Layer and historical compatibility paths are NOT constrained by criterion 1; they MAY continue to read/write legacy NodeTypes for internal bookkeeping without violating this requirement.

### Requirement 4: Clue Roles

**User Story:** As a security engineer, I want each clue node to declare which roles it fills in the security impact chain, so that the Capability Gate can evaluate role coverage rather than vulnerability templates.

#### Acceptance Criteria

1. WHEN a new clue node is written, THE `ContentJSON.roles` field SHALL contain one or more values from the set: `origin_or_entry`, `trigger_or_control`, `reachability_or_relation`, `security_effect_or_impact`, `control_state_or_missing_control`, `verification_or_observation`.
2. THE system SHALL allow a single clue node to declare multiple roles simultaneously.
3. WHEN reading legacy nodes that lack a `roles` field, THE system SHALL infer default roles from the legacy NodeType mapping table defined in design.md.
4. THE Capability Gate SHALL evaluate role coverage (not vulnerability type) as the primary promotion criterion.

### Requirement 5: Tool Observation Contract

**User Story:** As a tool developer, I want a clear contract for what tools can and cannot output, so that tools remain clue-observation producers without making vulnerability judgments.

#### Acceptance Criteria

1. WHEN a tool execution completes, THE ToolRun output SHALL be expressible as a list of ClueObservations, each with: `observation_type` ∈ {supporting, refuting, blocked, no_signal, error}, `clue_kind`, `summary`, `evidence_refs`, `target_clue_refs`, `suggested_roles`.
2. THE Tool Collection layer SHALL NOT output fields named `vulnerability_type`, `cwe`, `severity`, `finding_title`, or `capability_promote`.
3. THE Tool Collection layer SHALL NOT directly persist `AICapability`, `AIFinding`, or `AINegativeFact` records.
4. WHEN a tool produces a refuting / blocked / no_signal / error observation, THE system SHALL pass it to Evidence Gate for potential upgrade to NegativeFact; it SHALL NOT discard negative observations.

### Requirement 6: GraphDelta Structured Clue Preservation

**User Story:** As a platform maintainer, I want Worker/Reasoner outputs to preserve structured clue fields, so that clue semantics are not lost during graph merging.

#### Acceptance Criteria

1. WHEN a Worker or Reasoner returns a GraphDelta containing `new_clue_facts`, `clue_chain_link`, or `refuted_clue` fields, THE system SHALL use these structured fields as the primary source for graph writes.
2. IF both structured clue fields and legacy flat fields (`NewFacts`, `NewNegativeFacts`) are present in the same GraphDelta, THEN THE system SHALL treat legacy fields as observation-only and SHALL NOT use them for Capability Promotion decisions.
3. WHEN merging a GraphDelta, THE system SHALL NOT flatten structured clue fields into untyped string facts or hypothesis nodes.
4. EACH GraphDelta SHALL be scoped to the current Intent; THE system SHALL reject or demote to diagnostic any GraphDelta that attempts global report-style output.

### Requirement 7: Legacy Intent Normalization

**User Story:** As a platform maintainer, I want all legacy vuln-type intents to be transparently mapped to clue intents, so that the system converges on a single intent vocabulary.

#### Acceptance Criteria

1. WHEN any code path creates an `AIIntent`, THE system SHALL pass the IntentType through `NormalizeIntentType` before persisting.
2. IF the original IntentType is a legacy vuln-type (e.g., `sql_injection_validation`, `idor_test`, `xss_test`), THEN THE system SHALL map it to the corresponding clue intent type and store the original value in `ConstraintsJSON.legacy_hint`.
3. WHEN a legacy intent is normalized, THE system SHALL emit an audit event `agent.legacy_intent_normalized` with the original and mapped types.
4. THE `NormalizeIntentType` function SHALL be idempotent: applying it twice SHALL produce the same result as applying it once.
5. IF an unknown IntentType is encountered, THE system SHALL map it to `clue_collect` as a safe default and emit an audit event.

### Requirement 8: Evidence Gate Role Coverage

**User Story:** As a security engineer, I want Capability promotion to require ClueChain role coverage rather than delivery proof fields, so that only properly evidenced security impact chains become verified Capabilities.

#### Acceptance Criteria

1. WHEN evaluating a ClueChain for Capability promotion, THE Evidence Gate SHALL check that all six required clue roles are covered by at least one node in the chain.
2. FOR each covered role, THE Evidence Gate SHALL require at least one supporting evidence ref.
3. IF any active NegativeFact directly refutes a node in the chain, THEN THE Evidence Gate SHALL NOT promote the Capability to `verified`.
4. THE Evidence Gate SHALL NOT use delivery proof fields (`bash_poc`, `python_poc`, `propagation_path`, `sensitive_sink_or_behavior`) as promotion criteria.
5. WHERE the escape hatch `RABBIT_PROMOTION_GATE` is set to `legacy`, THE system SHALL fall back to the old delivery-proof-based gate.

### Requirement 9: ShouldFinalize Clue-Based Stop Condition

**User Story:** As a platform maintainer, I want the loop termination to be based on clue progress rather than finding counts or contract status, so that exploration stops only when clue coverage is sufficient or budget is exhausted.

#### Acceptance Criteria

1. THE ShouldFinalize function SHALL NOT read `AIFinding` count or `AIContractCheckResult` status as termination inputs.
2. THE system SHALL support three termination reasons: `budget-exhausted`, `clue-coverage-sufficient`, `clue-plateau`.
3. WHEN `SurfaceCount == 0` AND no recent clue/evidence/capability/surface progress AND no pending high-value intents, THE system SHALL terminate with reason `clue-plateau` (P1 fallback).
4. WHEN the system terminates, THE system SHALL emit an audit event `agent.shouldfinalize_reason` with the termination reason.
5. WHERE the escape hatch `RABBIT_FINALIZE_FALLBACK` is set to `legacy`, THE system SHALL use the old ShouldFinalize logic.

### Requirement 10: Prompt / Output Sanitizer

**User Story:** As a platform maintainer, I want LLM outputs to be sanitized before entering the graph, so that vulnerability-type language and report-style content cannot pollute the clue-driven loop.

#### Acceptance Criteria

1. WHEN the LLM output contains fields named `vuln_type`, `cwe`, `severity`, `finding_title`, or `vulnerability_type`, THE sanitizer SHALL strip these fields and emit audit event `agent.vuln_type_field_ignored`.
2. WHEN the LLM output contains a legacy vuln intent type, THE sanitizer SHALL invoke `NormalizeIntentType` and emit audit event `agent.legacy_intent_normalized`.
3. WHEN the LLM output contains report-style language patterns in `thought_summary` / `planned_action` / `objective`, THE sanitizer SHALL demote the content to `diagnostics` only and emit audit event `agent.llm_output_sanitized`.
4. IF the LLM output lacks `operation`, `intent_goal`, `expected_clue_roles`, or `target_clue_refs` fields, THE sanitizer SHALL use empty defaults and emit audit event `agent.legacy_intent_schema_observed`.
5. IF the sanitizer itself fails (exception), THE system SHALL fall back to deterministic mode without blocking the loop.

### Requirement 11: Deterministic Fallback

**User Story:** As a platform maintainer, I want the deterministic fallback (no-model mode) to also be clue-driven, so that the system never produces vuln-type intents regardless of model availability.

#### Acceptance Criteria

1. WHEN the model is unavailable, THE deterministic fallback SHALL only produce Intent types from the set: `clue_collect`, `clue_validate`, `clue_refute`, `clue_chain_extend`, `scope_observation`.
2. THE deterministic fallback SHALL NOT reference vulnerability type names in any generated Intent title, objective, or constraints.
3. THE deterministic fallback SHALL populate `operation` and `intent_goal` fields with clue-progress descriptions.

### Requirement 12: Backward Compatibility

**User Story:** As a user with running tasks, I want existing tasks to continue functioning without interruption after the system is updated, so that no data is lost or corrupted.

#### Acceptance Criteria

1. WHILE legacy NodeType values exist in the database, THE system SHALL read and display them correctly via the mapping function.
2. WHILE legacy IntentType values exist on pending intents, THE system SHALL normalize them transparently on next access without requiring a manual migration.
3. THE system SHALL NOT require a destructive DB migration (ALTER TABLE / DROP COLUMN / UPDATE NodeType) in any phase.
4. IF a mapping function encounters an unknown NodeType or IntentType, THE system SHALL use a safe default (`clue_observation` / `clue_collect`) and SHALL NOT panic or abort the task.

### Requirement 13: Runtime Toggle Controllability

**User Story:** As an operator, I want fine-grained runtime toggles to control the rollout and enable emergency rollback, so that high-risk changes can be reverted independently.

#### Acceptance Criteria

1. THE system SHALL support a phase toggle `RABBIT_CLUE_DRIVEN_PHASE` with values 0–4 controlling the overall migration stage.
2. THE system SHALL support independent escape hatches: `RABBIT_PROMOTION_GATE` (clue_chain|legacy), `RABBIT_FINALIZE_FALLBACK` (clue|legacy), `RABBIT_DELIVERY_WRITEBACK` (off|on).
3. WHEN an escape hatch conflicts with the phase toggle, THE escape hatch SHALL take precedence (fine-grained override).
4. THE system SHALL log the active toggle configuration at startup via structured logging.

### Requirement 14: Property-Based Correctness

**User Story:** As a developer, I want formal correctness properties to be testable, so that regressions in core invariants are caught automatically.

#### Acceptance Criteria

1. THE `EvaluateClueChain` function SHALL exhibit monotonicity: adding supporting evidence or clue nodes to a chain SHALL NOT cause its Strength to decrease.
2. THE `ShouldFinalize` function SHALL be deterministic: given the same (coverage, progress, budget) input, it SHALL always return the same (stop, reason) output.
3. THE `NormalizeIntentType` function SHALL be idempotent: `NormalizeIntentType(NormalizeIntentType(x)) == NormalizeIntentType(x)` for all x.
4. THE sanitizer SHALL preserve all valid `new_clue_facts` / `clue_chain_link` / `refuted_clue` entries while stripping only prohibited fields.
