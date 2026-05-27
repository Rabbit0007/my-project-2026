# Requirements Document

## Introduction

This document specifies the requirements for overhauling the Rabbit AI Security Validation Platform's core agent loop, finding generation, and code analysis subsystems. The platform currently fails to identify vulnerabilities due to premature loop termination, complete model dependency for Finding generation, insufficient context building, and silent failure handling. This overhaul addresses P0/P1/P2 issues identified in the root cause analysis to ensure the platform reliably identifies security vulnerabilities even when the AI model is unavailable or underperforming.

## Glossary

- **Agent_Loop**: The main execution loop in `AgentOrchestrator` that iterates through Intents, executes tools, writes Evidence / Facts, resolves Hypotheses, expands Capabilities / NegativeFacts / UnverifiedRisks, and performs reasoning phases until graph exploration termination conditions are met.
- **Reason_Phase**: The phase within the Agent_Loop where the model analyzes the current blackboard graph and generates new exploration Intents when no pending Intents remain.
- **Reasoning_Effort**: A configuration parameter passed to the model API controlling analysis depth (values: "none", "minimal", "low", "medium", "high", "xhigh").
- **Finding**: A delivery artifact (`AIFinding`) produced from an evidence-backed validated path; it is not the exploration driver.
- **Hypothesis_Expander**: A subsystem that forms Hypothesis / ValidationIntent records from Source+Sink co-occurrence, response differences, capabilities, negative facts, and environment signals.
- **Context_Builder**: The service (`ContextBuilder`) that assembles information from the blackboard, evidence, and findings into a structured context for model consumption.
- **Blackboard**: The graph-based knowledge store (`AIBlackboardNode` + `AIBlackboardEdge`) recording all facts, intents, evidence, and findings discovered during a task.
- **Negative_Fact**: A blackboard node of type `negative_fact` recording a failed operation and its reason, enabling the system to avoid repeating failed paths.
- **Contract**: The delivery quality-check mechanism (`ContractService`) that validates Finding completeness, downgrades incomplete delivery artifacts, and records evidence gaps. It is not the main planner.
- **Source**: A code pattern representing user-controllable input (e.g., `$_FILES`, `$_GET`, `$_POST`, `request.getParameter`).
- **Sink**: A code pattern representing a security-sensitive operation (e.g., `move_uploaded_file`, `exec`, `eval`, `mysql_query`).
- **Code_Slice**: The tool that extracts a focused code snippet around a target line from a source file.
- **Code_Project_Index**: The tool that builds a project-level knowledge graph identifying language, framework, routes, auth middleware, data models, and sensitive operations.
- **Bootstrap_Phase**: An initial phase in the agent loop that attempts to directly reach the task Goal in the first iteration before falling back to incremental exploration.
- **Budget_Exhaustion**: The condition when the Agent_Loop reaches its maximum iteration count (`MAX_ITERATIONS`) without achieving smart termination.

## Requirements

### Requirement 1: Reasoning Effort Configuration Passthrough

**User Story:** As a platform operator, I want the model reasoning effort to respect my configured value, so that the AI model performs deep analysis when I configure high reasoning effort.

#### Acceptance Criteria

1. WHEN a user configures a reasoning effort value in the model configuration, THE Model_Runtime_Service SHALL pass that exact value to the model API without modification.
2. WHEN the reasoning effort configuration is empty or unset, THE Model_Runtime_Service SHALL default to "medium" reasoning effort.
3. THE Model_Runtime_Service SHALL accept all valid reasoning effort values: "none", "minimal", "low", "medium", "high", "xhigh".

### Requirement 2: Hypothesis Formation From Code Observations

**User Story:** As a security analyst, I want the platform to generate Hypotheses and ValidationIntents from code pattern co-occurrence even when the AI model is unavailable, so that exploration does not completely depend on model availability.

#### Acceptance Criteria

1. WHEN the AI model is unavailable or returns empty results, THE Hypothesis_Expander SHALL analyze collected Evidence for Source+Sink co-occurrence patterns within the same file.
2. WHEN a Source pattern and a Sink pattern co-occur in the same file, THE Hypothesis_Expander SHALL create a Hypothesis and a ValidationIntent, not a confirmed Finding.
3. THE Hypothesis_Expander SHALL map Source+Sink pattern pairs to hypothesis type and expected capability hints.
4. WHEN a Hypothesis is created, THE StateExpansionPlanner SHALL score the resulting ValidationIntent before NextPending selection.
5. THE Hypothesis_Expander SHALL not duplicate active Hypotheses that already exist for the same target and pattern key.

### Requirement 3: Reason Phase Budget Increase

**User Story:** As a platform operator, I want the agent loop to persist longer in its reasoning phase before giving up, so that the system has more opportunities to generate useful exploration Intents.

#### Acceptance Criteria

1. THE Agent_Loop SHALL allow up to 5 consecutive no-progress reasoning passes before terminating the reason phase (increased from the current limit of 2).
2. WHEN the reason phase has no pending Intents, THE Agent_Loop SHALL ask the graph reasoner for high-value next exploration Intents rather than using Contract status as the planner.
3. WHEN the reason budget is exhausted, THE Agent_Loop SHALL log an audit event recording the number of passes attempted and the reason for termination.

### Requirement 4: Enhanced Context Builder

**User Story:** As a platform developer, I want the Context Builder to provide richer information to the model, so that the model can make better-informed reasoning decisions.

#### Acceptance Criteria

1. THE Context_Builder SHALL include a list of missing fields extracted from Contract check results (hint-type blackboard nodes) in the agent context.
2. THE Context_Builder SHALL include summaries of the most recent failed ToolRuns (up to 10) with their error reasons in the agent context.
3. THE Context_Builder SHALL include the file structure list from code_search hits and the project index in the agent context.
4. THE Context_Builder SHALL include Source/Sink pairing relationships discovered during code analysis in the agent context.
5. WHEN building context, THE Context_Builder SHALL not exceed 6000 characters total to maintain Cairn-style small prompt sizes.

### Requirement 5: Code Slice Failure Recording

**User Story:** As a platform developer, I want code_slice failures to be recorded on the blackboard, so that the system can learn from failures and avoid repeating them.

#### Acceptance Criteria

1. WHEN a code_slice tool execution fails, THE Agent_Loop SHALL write a negative_fact node to the Blackboard containing the failed file path and the error reason.
2. THE negative_fact node SHALL have an importance score that allows it to appear in subsequent Context Builder outputs.
3. WHEN the Reason_Phase encounters negative_fact nodes about code_slice failures, THE Agent_Loop SHALL avoid generating new Intents targeting the same file path with the same parameters.

### Requirement 6: Same-File Source+Sink Full-File Slicing

**User Story:** As a security analyst, I want the system to automatically perform full-file code slicing when both Source and Sink patterns are found in the same file, so that the model receives complete context for vulnerability analysis.

#### Acceptance Criteria

1. WHEN code_search identifies both a Source pattern and a Sink pattern in the same file, THE Agent_Loop SHALL create a code_slice request for the entire file content (full-file radius).
2. THE full-file slice SHALL be stored as a single Evidence item with relation type "code_source" and include both the Source and Sink line numbers in its metadata.
3. WHEN the same file has already been fully sliced in a previous iteration, THE Agent_Loop SHALL skip redundant full-file slicing for that file.

### Requirement 7: Code Project Index Integration

**User Story:** As a security analyst, I want the agent to build a project-level understanding before diving into pattern matching, so that code analysis has structural context about entry points, routes, and data flow.

#### Acceptance Criteria

1. WHEN a code audit task starts, THE Agent_Loop SHALL execute the code_project_index tool as the first operation before code_search.
2. THE code_project_index results SHALL be written to the Blackboard as structured code_fact nodes covering: language, framework, entry files, routes, auth middleware, data models, and sensitive operations.
3. THE Context_Builder SHALL include the project index summary in all subsequent model calls for the task.

### Requirement 8: Bootstrap Phase Implementation

**User Story:** As a platform developer, I want the agent to attempt a direct path to the Goal in its first iteration, so that simple vulnerabilities can be identified quickly without exhaustive exploration.

#### Acceptance Criteria

1. WHEN the Agent_Loop starts a new task, THE Agent_Loop SHALL execute a Bootstrap phase that attempts to directly reach the task Goal before entering the normal Explore/Reason cycle.
2. WHEN the Bootstrap phase succeeds in generating observations, THE Agent_Loop SHALL form Hypotheses / ValidationIntents before continuing exploration.
3. WHEN the Bootstrap phase does not produce new observations, THE Agent_Loop SHALL transition to the normal Cairn-style Explore/Reason cycle without error.
4. THE Bootstrap phase SHALL complete within a single iteration and SHALL NOT consume more than one iteration from the total budget.

### Requirement 9: Budget Exhaustion Graceful Handling

**User Story:** As a security analyst, I want the platform to generate a complete report even when the iteration budget is exhausted, so that partial findings are not lost.

#### Acceptance Criteria

1. WHEN the Agent_Loop reaches MAX_ITERATIONS, THE Agent_Loop SHALL promote all verified capabilities to Findings and proceed to report generation without returning an error.
2. WHEN budget is exhausted, THE Agent_Loop SHALL include all Findings regardless of their contract status (hypothesis, candidate, contract_incomplete) in the generated report.
3. THE Report_Service SHALL clearly indicate in the report when findings have incomplete evidence due to budget exhaustion.
4. WHEN budget is exhausted, THE Agent_Loop SHALL log an audit event with the iteration count, number of findings, and number of pending intents that were not executed.
