# Requirements Document

## Introduction

The security audit platform must evolve into a **Hypothesis-Driven Autonomous Security Exploration System**. The core loop is:

**Observation → Hypothesis → ValidationIntent → Evidence → Capability → Contextual Expansion → State Expansion**

NOT a capability-rule engine, NOT a coverage checklist, NOT a deterministic expansion chain.

Capabilities emerge through **validated hypotheses**. Exploration is driven by **contextual reasoning** that considers the current environment model, graph state, session state, existing NegativeFacts, and risk signals — not by static `if capability == X: create intents A/B/C` rules.

The system's core question after every action is: **"What new hypotheses can be formed from this observation, and which hypothesis validation most expands reachable state?"**

This feature introduces:
1. GoalProfile / GoalType model (terminal / coverage / expansion) for goal framing
2. **HypothesisNode** as a first-class graph primitive — potential security truths that must be validated
3. Capability as a first-class graph primitive, acquired only through validated hypotheses
4. **Contextual Capability Expansion** — capability + environment + session + goal + graph state + risk signals → hypothesis → validation intent
5. **DynamicIntentExpander** with hypothesis reasoning (not static rules)
6. **EnvironmentModel** continuously maintained during exploration
7. **ExplorationBudgetManager** preventing capability/intent/graph explosion
8. GoalDecomposer reduced to bootstrap-only logic
9. Reasoner refactored into State Expansion Planner with branch value estimation
10. Coverage as secondary support logic for completeness and reporting
11. NegativeFact and UnverifiedRisk as core primitives
12. Report output as evidence-backed exploration narrative with hypothesis chains

## Glossary

- **GoalProfile**: The top-level model representing a task's goal configuration, including goal type, mode, and completion policy
- **GoalType**: An enum with three values — terminal (clear endpoint proof), coverage (systematic audit), expansion (lateral movement)
- **HypothesisNode**: A first-class graph primitive representing a potential security truth that must be validated (e.g., "This endpoint may support SSRF", "This object may lack ownership validation")
- **Capability**: A first-class graph primitive representing a proven ability acquired through hypothesis validation (e.g., file_read, command_execution, admin_access). Capabilities are the exploration progression mechanism
- **CapabilityChain**: A sequence of capabilities where each unlocks hypotheses that lead to the next
- **ContextualExpansion**: The process of generating new hypotheses from a capability by considering environment model, session state, current goal, existing NegativeFacts, graph state, and risk signals — NOT static if/then rules
- **DynamicIntentExpander**: The subsystem that generates ValidationIntents from hypotheses formed when graph state materially changes
- **EnvironmentModel**: A continuously maintained model of the target environment (runtime, deployment, framework stack, cloud provider, identity model, network zone, execution context, container runtime, orchestration layer, auth mechanism, session model)
- **ExplorationBudgetManager**: The subsystem preventing capability/intent/graph explosion by tracking active branch count, intent generation rate, graph expansion velocity, and applying branch value decay
- **GoalDecomposer**: Bootstrap-only service that initializes attack surface, initial hypotheses, initial graph state, and objective ladder. Does NOT pre-plan the full audit
- **State_Expansion_Planner**: The refactored Reasoner that evaluates branch value (expected capability gain, graph expansion, novelty, risk value, cost, evidence quality) to select next actions
- **BranchValueEstimation**: Evaluation of every exploration branch using expected capability gain, graph expansion, novelty, risk value, cost, and evidence quality. Low-value branches decay automatically
- **CoverageItem**: A secondary metadata item tracking coverage status of an attack surface element
- **CoverageMatrix**: The complete set of CoverageItems, used for completeness estimation, gap detection, and reporting only
- **ExpansionGoal**: A goal type tracking progressive lateral movement through an Objective Ladder via hypothesis validation and capability acquisition
- **ObjectiveLadder**: A 6-level progression model (Foothold → Local Privilege → Reachable Assets → Identity Expansion → Critical Assets → High-Value Proof)
- **CompletionPolicy**: A JSON structure defining when a goal is complete
- **NegativeFact**: A core graph primitive recording tested but non-exploitable paths. Reduces duplicate probing, prevents exploration loops, influences hypothesis formation
- **UnverifiedRisk**: A core graph primitive recording potential risks that could not be verified, with explicit reasons
- **TestedPath**: A blackboard node recording a source-to-sink path tested with its outcome
- **ExplorationSummarizationLayer**: Rolling summary generation for validated paths, failed hypotheses, active capabilities, high-value branches, environment model, remaining hypotheses
- **System**: The security audit platform backend (Go services in `backend/internal/`)
- **Reasoner**: The State Expansion Planner component that selects actions maximizing reachable state expansion
- **Runner**: The sandboxed execution environment performing actual security testing actions
- **Blackboard**: The graph-based knowledge store holding all facts, evidence, hypotheses, capabilities, and relationships

## Requirements

### Requirement 1: GoalProfile Model

**User Story:** As a platform operator, I want each task to have a structured GoalProfile, so that the system knows whether to pursue terminal proof, hypothesis-driven coverage, or lateral expansion.

#### Acceptance Criteria

1. THE System SHALL define a GoalType enum with values "terminal", "coverage", and "expansion"
2. THE System SHALL define a GoalProfile struct with fields: ID, TaskID, GoalType, Name, Description, RawUserGoal, NormalizedGoal, Mode, CompletionPolicy, CreatedAt, UpdatedAt
3. WHEN a GoalProfile is created, THE System SHALL store the Mode field as one of: code_audit, web_pentest, internal_pentest, terminal_proof
4. THE System SHALL store CompletionPolicy as a JSON structure defining thresholds and budget constraints for goal completion
5. WHEN a task has no GoalProfile, THE System SHALL auto-assign a default GoalProfile based on the task's TaskType field (code_audit and pentest tasks receive coverage type, hybrid tasks receive terminal type)
6. THE System SHALL ensure all GoalProfile fields have defaults or are nullable to maintain backward compatibility with existing tasks

### Requirement 2: HypothesisNode as First-Class Graph Primitive

**User Story:** As a platform developer, I want hypotheses to be first-class graph primitives that represent potential security truths requiring validation, so that exploration is driven by reasoning rather than static rules.

#### Acceptance Criteria

1. THE System SHALL define a HypothesisNode model with fields: ID, TaskID, HypothesisType, Title, Description, ConfidenceState, Status, SourceObservationRefs (JSON), SupportingEvidenceRefs (JSON), TargetEntity, ExpectedCapability, ValidationIntentRefs (JSON), NegativeFactRefs (JSON), UnverifiedRiskRefs (JSON), CreatedAt, UpdatedAt, ValidatedAt
2. THE System SHALL support HypothesisType enum values: injection_candidate, authz_bypass_candidate, idor_candidate, mass_assignment_candidate, file_read_candidate, file_write_candidate, upload_bypass_candidate, command_execution_candidate, ssrf_candidate, xss_candidate, ssti_candidate, xxe_candidate, deserialization_candidate, secret_reuse_candidate, credential_reuse_candidate, lateral_access_candidate, known_vuln_candidate, business_logic_candidate, information_disclosure_candidate, session_weakness_candidate, dependency_vulnerability_candidate
3. THE System SHALL support ConfidenceState values: suspected (weak signal only), plausible (context supports it), strong (multiple observations support it), validated (evidence validated it), refuted (evidence disproved it), inconclusive (validation attempted but insufficient)
4. THE System SHALL support the hypothesis lifecycle: Observation → Hypothesis → ValidationIntent → Evidence → Capability (if validated) or NegativeFact (if refuted) or UnverifiedRisk (if inconclusive)
5. WHEN new observations (Facts, Evidence, ToolRun results, Capabilities, EnvironmentModel updates) appear, THE System SHALL form hypotheses based on patterns, environment context, and existing graph state
6. THE System SHALL NOT allow new Capabilities to be created without a validated hypothesis backing them (for legacy compatibility, existing Capabilities may be linked to synthetic legacy_hypothesis nodes)
7. WHEN a hypothesis is refuted, THE System SHALL create a NegativeFact and reduce priority of similar hypotheses
8. WHEN a hypothesis is confirmed with Evidence, THE System SHALL promote it to a Capability with full evidence and hypothesis chain

### Requirement 3: Capability as Graph Primitive with Hypothesis Backing

**User Story:** As a platform developer, I want Capabilities to be first-class graph primitives that are always backed by validated hypotheses, so that exploration progression is evidence-driven.

#### Acceptance Criteria

1. THE System SHALL treat CapabilityNode as a first-class graph primitive with edges: Capability → derived_from → Evidence, Capability → validated_by → HypothesisNode, Capability → enables → HypothesisNode (new hypotheses), Capability → expands_to → AttackSurface
2. THE System SHALL support Capability types: authenticated_session, admin_access, source_code_read, secret_discovered, file_read, file_write, command_execution, database_read, internal_service_access, browser_execution, upload_write, config_read, credential_obtained, lateral_access
3. WHEN a new Capability is acquired, THE System SHALL use contextual expansion (not static rules) to form new hypotheses considering: the capability + environment model + session state + current goal + existing NegativeFacts + current graph state + risk signals
4. THE System SHALL support Capability chaining through hypothesis chains (e.g., file_read capability → hypothesis "config may contain secrets" → validation → secret_discovered capability → hypothesis "secret may enable auth" → validation → authenticated_session)
5. THE System SHALL record Capability chains with hypothesis links for report output

### Requirement 4: Contextual Capability Expansion

**User Story:** As a platform developer, I want capability expansion to be contextual rather than rule-based, so that the system adapts its exploration to the specific target environment rather than following generic if/then patterns.

#### Acceptance Criteria

1. WHEN a new Capability is acquired, THE System SHALL generate hypotheses by considering: the capability type, current EnvironmentModel, active session state, current GoalProfile, existing NegativeFacts, current graph state, and active risk signals
2. THE System SHALL NOT use static `if capability == X: create intents A/B/C` rules as the primary expansion mechanism (static templates may be used as bootstrap scaffolding, but every generated hypothesis must include context, source observations, expected capability, and validation method)
3. THE System SHALL support contextual expansion patterns: file_read + .env readable → hypotheses about database credentials, cloud keys, JWT secrets, authenticated access; file_read + nginx.conf → hypotheses about internal upstreams, hidden admin routes, alias misconfiguration; command_execution + kubernetes environment → hypotheses about serviceaccount token, api-server reachability, namespace secrets, pod privilege; command_execution + windows_domain → hypotheses about domain discovery, privileged group membership, credential material, lateral movement
4. THE System SHALL maintain expansion context that evolves as the environment model is refined during exploration
5. THE System SHALL use the EnvironmentModel to filter out hypotheses that are irrelevant to the target (e.g., no Kubernetes hypotheses if environment is bare-metal, no Windows AD hypotheses if environment is Linux)

### Requirement 5: Environment Model

**User Story:** As a platform developer, I want the system to continuously maintain an environment model of the target, so that hypothesis formation is contextually relevant.

#### Acceptance Criteria

1. THE System SHALL maintain an EnvironmentModel for each task as a JSON structure tracking: runtime_environment, deployment_model, framework_stack, cloud_provider, identity_model, network_zone, execution_context, container_runtime, orchestration_layer, authentication_mechanism, session_model, with per-field confidence levels
2. WHEN new Evidence or Facts reveal environment characteristics, THE System SHALL update the EnvironmentModel accordingly and mirror it into the blackboard as an environment_model node
3. THE System SHALL use the EnvironmentModel as input to hypothesis formation and contextual capability expansion
4. THE EnvironmentModel SHALL influence hypothesis priority: hypotheses aligned with the detected environment receive higher confidence scores
5. THE System SHALL support confidence levels per environment field (e.g., "spring_boot": "strong", "docker": "suspected") to express certainty about detected characteristics

### Requirement 6: Dynamic Intent Expander with Hypothesis Reasoning

**User Story:** As a platform developer, I want the DynamicIntentExpander to generate ValidationIntents from hypotheses rather than static capability rules, so that exploration emerges from reasoning about observations.

#### Acceptance Criteria

1. THE DynamicIntentExpander SHALL trigger whenever: a new Fact appears, new Evidence appears, a new Capability appears, a new Hypothesis is formed, a new NegativeFact is recorded, EnvironmentModel is updated, or graph state materially changes
2. THE DynamicIntentExpander SHALL form hypotheses from observations and generate ValidationIntents from high-value pending hypotheses, prioritized by expected capability gain and branch value
3. THE DynamicIntentExpander SHALL reuse the existing AIIntent infrastructure for ValidationIntents, adding metadata fields: hypothesis_id, validation_method, expected_evidence, expected_capability, success_condition, failure_condition, safety_level, environment_context_snapshot (stored in ConstraintsJSON)
4. THE DynamicIntentExpander SHALL check existing NegativeFacts, refuted hypotheses, and existing Intents before generating new ValidationIntents to prevent exploration loops and duplicates
5. THE DynamicIntentExpander SHALL respect the ExplorationBudgetManager limits on active branch count, pending hypothesis count, and intent generation rate
6. THE DynamicIntentExpander SHALL write all hypothesis formation and intent generation decisions to the audit trail

### Requirement 7: Exploration Budget Manager

**User Story:** As a platform developer, I want the system to prevent capability/intent/hypothesis/graph explosion through active budget management, so that exploration remains focused and efficient.

#### Acceptance Criteria

1. THE ExplorationBudgetManager SHALL track: active_branch_count, pending_hypothesis_count, pending_validation_intent_count, intent_generation_rate, graph_expansion_velocity, average_branch_value, context_growth_rate
2. WHEN active branch count exceeds the configured max_active_branches_per_task threshold, THE ExplorationBudgetManager SHALL pause low-value hypothesis formation until existing branches resolve
3. WHEN intent generation rate exceeds the configured max_generated_intents_per_round threshold, THE ExplorationBudgetManager SHALL throttle the DynamicIntentExpander
4. THE ExplorationBudgetManager SHALL apply automatic decay to low-value branches: branches that have not produced new observations within branch_decay_rounds lose priority and are eventually suppressed
5. THE ExplorationBudgetManager SHALL enforce limits: max_pending_hypotheses_per_task, max_pending_validation_intents_per_task, and prefer high expected capability gain when thresholds are exceeded
6. WHEN thresholds are exceeded, THE ExplorationBudgetManager SHALL suppress duplicate hypotheses and decay stale branches before blocking new high-value hypothesis formation

### Requirement 8: State Expansion Planner (Refactored Reasoner)

**User Story:** As a platform developer, I want the Reasoner to function as a State Expansion Planner that evaluates branch value for hypothesis-driven exploration, so that the system maximizes meaningful state expansion.

#### Acceptance Criteria

1. THE Reasoner SHALL evaluate every exploration branch using: expected capability gain, expected graph expansion, expected novelty, expected risk value, expected cost, expected evidence quality
2. WHEN the GoalType is "terminal", THE Reasoner SHALL prioritize hypothesis validation paths that lead most directly to goal proof through capability chains
3. WHEN the GoalType is "coverage", THE Reasoner SHALL score hypotheses and their ValidationIntents using: capability_unlock_score + graph_expansion_score + novelty_score + risk_value + coverage_gain - execution_cost - safety_risk - duplicate_penalty
4. WHEN the GoalType is "expansion", THE Reasoner SHALL prioritize hypotheses that advance the Objective Ladder through capability acquisition chains
5. THE Reasoner SHALL enforce scoring priority order: high capability expansion > high graph expansion > high novelty > coverage gain > low-value probing
6. THE Reasoner SHALL apply duplicate_penalty to ValidationIntents targeting hypotheses similar to existing NegativeFacts
7. THE Reasoner SHALL automatically decay low-value branches that have not produced new observations within N rounds

### Requirement 9: GoalDecomposer as Bootstrap-Only Logic

**User Story:** As a platform developer, I want the GoalDecomposer to only initialize the exploration state with initial observations and hypotheses, so that all meaningful exploration emerges dynamically.

#### Acceptance Criteria

1. WHEN a code audit GoalProfile is created, THE GoalDecomposer SHALL initialize: attack surface observations (entry point categories), initial hypotheses about high-risk patterns, initial Intents for surface discovery (enumerate_entrypoints, enumerate_auth_boundaries, enumerate_user_controlled_sources, enumerate_sensitive_sinks), initial CoverageItems for tracking, and initial graph state (origin and goal nodes)
2. WHEN a web pentest GoalProfile is created, THE GoalDecomposer SHALL initialize: attack surface observations (page/API/form categories), initial hypotheses, initial Intents for surface discovery (crawl_pages, extract_js_apis, classify_endpoints, model_sessions_and_roles), initial CoverageItems, and initial graph state
3. WHEN an expansion GoalProfile is created, THE GoalDecomposer SHALL initialize: ObjectiveLadder with 6 levels, initial hypotheses about foothold opportunities, initial Intents, and initial graph state
4. THE GoalDecomposer SHALL NOT pre-plan the full audit, generate exhaustive workflows, statically enumerate all testing logic, or behave like a workflow engine
5. THE GoalDecomposer SHALL support code audit Intent types for initial bootstrap: inspect_entrypoint, trace_dataflow, inspect_auth_boundary, inspect_owner_check, inspect_mass_assignment, inspect_idor, inspect_file_operation, inspect_command_execution, inspect_template_render, inspect_deserialization, inspect_ssrf, inspect_upload_flow, inspect_download_flow, inspect_business_logic, validate_candidate_path, record_negative_fact
6. THE GoalDecomposer SHALL support web pentest endpoint classification rules for initial categorization: search/list/filter → SQLi/XSS/filter bypass; download/view/file/log → path traversal/IDOR/arbitrary file read; upload/import/xml/csv → upload bypass/XXE/deserialization/parser bug; export/report/template/convert → command injection/SSTI/file write; profile/update/settings/config → mass assignment/CSRF/privilege escalation; admin/internal/debug → auth bypass/info leak/weak key; url/fetch/proxy/webhook/callback → SSRF/redirect/internal access; price/qty/coupon/order/purchase → negative number/repeated parameter/business logic; graphql → introspection/IDOR/hidden fields

### Requirement 10: NegativeFact as Core Primitive

**User Story:** As a platform developer, I want NegativeFact to be a core graph primitive that prevents exploration loops, influences hypothesis formation, and reduces duplicate probing.

#### Acceptance Criteria

1. THE System SHALL aggressively record NegativeFacts for: tested but non-exploitable paths, failed exploit attempts, refuted hypotheses, dead-end exploration branches
2. WHEN a NegativeFact is recorded, THE Reasoner SHALL reduce priority scores for hypotheses and Intents targeting the same path or similar patterns
3. THE DynamicIntentExpander SHALL check existing NegativeFacts before forming new hypotheses to prevent exploration loops
4. THE System SHALL include NegativeFacts in the graph state summary and environment model for contextual hypothesis formation
5. THE Report SHALL list all NegativeFact nodes with their tested paths, refuted hypotheses, and reasons for negative determination

### Requirement 11: UnverifiedRisk as Core Primitive

**User Story:** As a platform developer, I want UnverifiedRisk to be a first-class output that clearly communicates what could not be verified and why, so that the platform stops implying "not verified" equals "not vulnerable."

#### Acceptance Criteria

1. THE System SHALL record UnverifiedRisk nodes with explicit reasons: insufficient authorization, insufficient budget, insufficient capability, missing credentials, safety restriction, inconclusive evidence
2. WHEN a hypothesis cannot be validated due to authorization or safety constraints, THE System SHALL create an UnverifiedRisk node rather than silently skipping the hypothesis
3. WHEN budget is exhausted with remaining high-value hypotheses, THE System SHALL create UnverifiedRisk nodes for each unvalidated high-risk hypothesis
4. THE Report SHALL clearly expose all UnverifiedRisk nodes with their reasons and the observations that formed the hypothesis
5. THE System SHALL distinguish UnverifiedRisk from NegativeFact: UnverifiedRisk means "could not validate", NegativeFact means "validated and found not exploitable"

### Requirement 12: Coverage as Secondary Support Logic

**User Story:** As a platform operator, I want coverage tracking to serve as a completeness metric and reporting dimension without driving exploration.

#### Acceptance Criteria

1. THE System SHALL define a CoverageItem struct with fields: ID, TaskID, GoalProfileID, Category, Name, TargetRef, RiskHint, Status, Reason, EvidenceRefs (JSON), NodeRefs (JSON), CreatedAt, UpdatedAt
2. THE System SHALL support CoverageItem Category values: entrypoint, auth_boundary, sink, endpoint, form, upload, download, business_logic, internal_asset
3. THE System SHALL support CoverageItem Status values: discovered, tested, validated, negative, unverified, skipped
4. THE System SHALL use CoverageItems for: completeness estimation, reporting, gap detection, duplicate reduction, prioritization hints, and termination logic
5. THE System SHALL NOT use CoverageItems as the exploration driver, exploration planner, or exploration controller
6. WHEN a CoverageItem status changes, THE System SHALL record the Reason for the transition and update EvidenceRefs

### Requirement 13: Dynamic Termination Conditions

**User Story:** As a platform operator, I want termination to be based on exploration stagnation and hypothesis exhaustion, so that the system stops when it can no longer form valuable hypotheses.

#### Acceptance Criteria

1. THE System SHALL terminate exploration when ALL of: no meaningful graph expansion in N consecutive rounds, no new Capabilities acquired in N consecutive rounds, no new high-value hypotheses formed, AND coverage threshold reached OR budget exhausted
2. THE System SHALL NOT terminate based solely on coverage threshold being met
3. WHEN budget is exhausted before exploration stagnates, THE System SHALL output remaining high-value hypotheses, uncovered attack surfaces, and unverified risks as a Coverage Gap report section
4. WHEN a safety policy blocks further action, THE System SHALL output blocked actions and reasons in the report
5. WHEN the GoalType is "expansion", THE System SHALL terminate when: no further Objective Ladder advancement is possible through hypothesis validation, budget is exhausted, maximum objective level is reached, or safety policy requires human takeover
6. THE System SHALL avoid endless low-value probing by detecting when remaining hypotheses have low expected capability gain and low branch value

### Requirement 14: Expansion Goal with Hypothesis-Driven Advancement

**User Story:** As a platform operator, I want internal network expansion to advance through hypothesis validation and capability acquisition rather than host enumeration checklists.

#### Acceptance Criteria

1. WHEN an expansion GoalProfile is created, THE GoalDecomposer SHALL generate an ObjectiveLadder with 6 levels: Foothold Context, Local Privilege/Secrets, Reachable Assets, Identity/Credential Expansion, Critical Assets, High-Value Proof
2. THE System SHALL advance ObjectiveLadder levels through validated hypotheses producing Capabilities (credential_obtained → hypothesis about lateral access → validation → internal_access → hypothesis about privilege → validation → critical_asset_access)
3. THE System SHALL enforce safety constraints on expansion goals: only within authorized scope, no destructive operations, no unauthorized public scanning, no persistence/log clearing, high-risk actions require human approval, all lateral actions are logged
4. WHEN a high-risk lateral action is proposed, THE System SHALL pause execution and request human approval before proceeding
5. THE System SHALL log all hypothesis formation, validation attempts, capability generation, and ladder advancement in the audit trail

### Requirement 15: Exploration Summarization Layer

**User Story:** As a platform developer, I want rolling exploration summaries to maintain context efficiency, so that the Reasoner can make decisions without overwhelming context.

#### Acceptance Criteria

1. THE System SHALL generate rolling summaries tracking: validated paths, failed hypotheses, active capabilities, high-value branches, current environment model, remaining high-value hypotheses
2. THE System SHALL compress exploration history into summaries when context size exceeds configured thresholds
3. THE System SHALL preserve key decision points in summaries: capability acquisitions, hypothesis confirmations/refutations, environment model updates, and objective ladder advancements
4. THE Reasoner SHALL use exploration summaries as input for branch value estimation when full graph state exceeds context limits

### Requirement 16: Fingerprint as Environment Context

**User Story:** As a platform developer, I want fingerprint matches to update EnvironmentModel and Blackboard facts without becoming an external lookup workflow.

#### Acceptance Criteria

1. WHEN a fingerprint is detected, THE System SHALL write EnvironmentModel / Blackboard Fact / Evidence context only
2. THE System SHALL NOT perform external vulnerability lookup, mass template execution, direct finding generation, or scanner-like behavior from fingerprint matches
3. THE System SHALL allow later hypothesis formation to use the environment signal through the same validation lifecycle as all other observations
4. THE System SHALL require Evidence and Capability chains before any Finding can be created

### Requirement 17: External Intelligence Constraints

**User Story:** As a platform developer, I want all non-tool intelligence to remain ordinary observation context and never bypass the validation lifecycle.

#### Acceptance Criteria

1. THE System SHALL treat external or historical knowledge as observation context only
2. THE System SHALL NOT allow metadata matches to directly generate Findings, bypass evidence requirements, bypass hypothesis validation, or bypass capability generation
3. THE Runner SHALL execute only registered in-scope tools governed by SafePolicy
4. THE System SHALL ensure all Findings originate from validated hypotheses backed by Evidence + Capability chains, not from metadata match alone

### Requirement 18: Report as Evidence-Backed Exploration Narrative

**User Story:** As a security analyst, I want the report to be an evidence-backed exploration narrative showing hypothesis chains and capability progression.

#### Acceptance Criteria

1. THE Report SHALL include: Goal Profile summary, Hypothesis chains showing exploration reasoning, Capability chains showing progression, Graph progression narrative, Coverage Matrix (for coverage goals) or Objective Ladder progress (for expansion goals), Verified Findings with evidence and hypothesis lineage, Negative Facts with refuted hypotheses, Unverified Risks with unvalidated hypotheses, Coverage Gaps, Remaining high-value hypotheses, Blocked paths with reasons, Evidence chains and reproduction steps
2. WHEN the GoalType is "coverage", THE Report SHALL include a coverage matrix showing CoverageItems with category, risk hint, status, and evidence references
3. WHEN the GoalType is "expansion", THE Report SHALL include the Objective Ladder showing levels achieved through hypothesis validation chains
4. THE Report SHALL present hypothesis → validation → capability chains as the primary narrative structure
5. THE Report SHALL clearly distinguish: confirmed findings (hypothesis validated with evidence), unverified risks (hypothesis formed but not validated), negative facts (hypothesis refuted with evidence)

### Requirement 19: Enhanced Graph Node Types and Edges

**User Story:** As a platform developer, I want the blackboard graph to support hypothesis-driven exploration with proper node types and edge relationships.

#### Acceptance Criteria

1. THE System SHALL support additional blackboard node types: hypothesis, capability, environment_model, coverage_goal, expansion_goal, entrypoint, attack_surface, auth_boundary, dataflow, sink, tested_path, unverified_risk, coverage_item
2. THE System SHALL support graph edge types: Observation → forms → Hypothesis, Hypothesis → generates → ValidationIntent, ValidationIntent → produces → Evidence, Evidence → validates → Hypothesis, Evidence → refutes → Hypothesis, Hypothesis → produces → Capability, Capability → enables → Hypothesis, Capability → derived_from → Evidence, Capability → expands_to → AttackSurface, NegativeFact → refutes → Hypothesis, UnverifiedRisk → blocks → Hypothesis
3. WHEN a Capability is created, THE System SHALL create corresponding graph nodes and edges linking it to its source hypothesis, evidence, and newly enabled hypotheses
4. WHEN a data flow path is traced, THE System SHALL create a "dataflow" node linking entrypoint, transform, and sink nodes via edges

### Requirement 20: Backward Compatibility and Development Constraints

**User Story:** As a platform developer, I want the new hypothesis-driven system to integrate without breaking existing functionality.

#### Acceptance Criteria

1. THE System SHALL reuse existing database tables and services where possible, adding new tables only for GoalProfile, CoverageItem, ObjectiveLadder, and HypothesisNode
2. THE System SHALL reuse existing AIIntent infrastructure for ValidationIntents (adding hypothesis metadata fields to ConstraintsJSON rather than creating a parallel workflow engine)
3. THE System SHALL ensure new database migrations are backward compatible with existing data
4. WHEN an existing task has no GoalProfile, THE System SHALL auto-assign a default GoalProfile matching the task's TaskType
5. THE System SHALL link existing Capabilities and Findings to synthetic legacy_hypothesis nodes for backward compatibility
6. THE System SHALL ensure all new model fields have defaults or are nullable
7. THE System SHALL NOT introduce uncontrollable external service dependencies
8. THE System SHALL retain authorization scope checks on all Runner actions
9. THE System SHALL log hypothesis formation, DynamicIntentExpander decisions, contextual expansion reasoning, Reasoner branch evaluation, coverage updates, and capability generation in the audit trail
10. THE System SHALL NOT break existing Task, Evidence, Finding, Runner, or Intent functionality
