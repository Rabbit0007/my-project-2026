# Implementation Plan: Security Audit Platform Overhaul

## Overview

This plan implements requirements for re-centering the core agent loop, evidence lifecycle, and code analysis subsystems around Cairn-style state-space exploration. Tasks are ordered to respect dependencies: foundational changes (reasoning effort, context builder types) come first, then the bootstrap phase and project index (which other features depend on), followed by the core loop enhancements (negative_fact, full-file slicing as evidence, hypothesis formation, validation intent creation), graph expansion controls, and finally budget exhaustion handling.

## Tasks

- [x] 1. Reasoning effort passthrough fix
  - [x] 1.1 Fix `codeAuditReasoningEffort` in `model_runtime_service.go`
    - Ensure the function passes through the configured value without modification
    - When empty/unset, default to "medium"
    - Accept all valid values: "none", "minimal", "low", "medium", "high", "xhigh"
    - _Requirements: 1.1, 1.2, 1.3_
  - [ ]* 1.2 Write unit tests for reasoning effort passthrough
    - Test that configured values pass through unchanged
    - Test empty/unset defaults to "medium"
    - Test all valid values are accepted
    - _Requirements: 1.1, 1.2, 1.3_

- [ ] 2. Enhanced ContextBuilder types and structure
  - [~] 2.1 Add new types to `context_builder.go`
    - Add `FailedToolRunSummary` struct (ToolName, FilePath, Error, Timestamp)
    - Add `SourceSinkPair` struct (FilePath, SourceLine, SinkLine, SourceType, SinkType)
    - Add `ProjectIndexSummary` struct (Language, Framework, EntryFiles, Routes, SensitiveOps)
    - Extend `AgentContext` with new fields: MissingFields, FailedToolRuns, FileStructure, SourceSinkPairs, ProjectIndex
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - [~] 2.2 Implement enhanced `Build` method in `context_builder.go`
    - Query hint-type blackboard nodes for MissingFields
    - Query failed AIToolRun records (limit 10, ordered by started_at DESC) for FailedToolRuns
    - Extract unique file paths from evidence for FileStructure
    - Group evidence by file to identify Source/Sink pairs for SourceSinkPairs
    - Query code_fact blackboard nodes (dedup_seed "project-index") for ProjectIndex
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - [~] 2.3 Implement `enforceCharBudget` in `context_builder.go`
    - Add `estimateSize` helper that JSON-marshals and returns character count
    - Implement progressive trimming with priority order: Task > Intent > ProjectIndex > OpenFindings > KeyFacts > SourceSinkPairs > MissingFields > FailedToolRuns > FileStructure > Evidence
    - Enforce 6000 character maximum on the assembled context
    - _Requirements: 4.5_
  - [ ]* 2.4 Write unit tests for ContextBuilder enhancements
    - Test that MissingFields are populated from hint nodes
    - Test that FailedToolRuns are populated and limited to 10
    - Test that enforceCharBudget trims lower-priority fields first
    - Test that output never exceeds 6000 characters
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [~] 3. Checkpoint - Verify foundation builds cleanly
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Code Project Index integration and Bootstrap phase
  - [~] 4.1 Implement `runBootstrapProjectIndex` in `agent_orchestrator.go`
    - Execute `code_project_index` tool as the first operation in the bootstrap phase
    - Pass taskID and root to the tool
    - _Requirements: 7.1_
  - [~] 4.2 Implement `writeProjectIndexFacts` in `agent_orchestrator.go`
    - Parse the project index result using `tools.ParseProjectIndex`
    - Write a code_fact blackboard node with dedup_seed "project-index" and importance 0.95
    - Include language, framework, entryFiles, routes, authMiddleware, dataModels, sensitiveOps in content
    - _Requirements: 7.2_
  - [~] 4.3 Implement Bootstrap phase entry point in `runLoopIterations`
    - Add bootstrap phase logic at the start of the loop (iteration 0)
    - Execute project index first, then code_search, then hypothesis formation from observations
    - If bootstrap produces source/sink or pattern observations, write Blackboard facts and create ValidationIntent entries
    - If bootstrap produces no new hypothesis, transition to the normal Explore/Reason cycle
    - Ensure bootstrap consumes only one iteration from the total budget
    - _Requirements: 8.1, 8.2, 8.3, 8.4_
  - [ ]* 4.4 Write unit tests for Bootstrap phase
    - Test that code_project_index runs first in bootstrap
    - Test that bootstrap transitions to normal cycle when no findings produced
    - Test that bootstrap consumes exactly one iteration
    - _Requirements: 7.1, 7.2, 8.1, 8.2, 8.3, 8.4_

- [ ] 5. Negative fact recording for code_slice failures
  - [~] 5.1 Implement negative_fact writing in `runCodeAuditIntent` and `runSingleFileAudit`
    - When code_slice execution fails, write a negative_fact node to the blackboard
    - Include file path, error reason, and line number in the node content
    - Use dedup_seed format: `negative-code-slice-{filePath}-{line}`
    - Set importance score to 0.75
    - _Requirements: 5.1, 5.2_
  - [~] 5.2 Implement `isFailedPath` avoidance logic in `agent_orchestrator.go`
    - Query blackboard for active negative_fact nodes matching a given file path
    - Integrate into reason phase intent generation to skip files with recorded failures
    - _Requirements: 5.3_
  - [ ]* 5.3 Write unit tests for negative_fact recording
    - Test that failed code_slice writes a negative_fact node
    - Test that isFailedPath returns true for files with negative_fact nodes
    - Test that reason phase skips files with negative_fact nodes
    - _Requirements: 5.1, 5.2, 5.3_

- [ ] 6. Same-file Source+Sink full-file slicing
  - [~] 6.1 Implement `triggerFullFileSlicing` in `agent_orchestrator.go`
    - After code_search completes, call `buildFileSecurityIndex` to identify files with both Source and Sink patterns
    - For each file with co-occurring patterns, request a full-file slice (radius = 9999)
    - Store metadata including sourceLines, sinkLines, and fullFile flag
    - On failure, write a negative_fact node with dedup_seed `negative-fullslice-{filePath}`
    - _Requirements: 6.1, 6.2_
  - [~] 6.2 Implement `hasFullFileSlice` deduplication check
    - Query AIEvidence for existing full-file slices of the same file
    - Skip redundant slicing when a full-file slice already exists
    - _Requirements: 6.3_
  - [~] 6.3 Wire `triggerFullFileSlicing` into `runCodeAuditIntent`
    - Call after code_search outcomes are collected
    - Append full-file slice outcomes to the iteration's evidence
    - _Requirements: 6.1, 6.2, 6.3_
  - [ ]* 6.4 Write unit tests for full-file slicing
    - Test that files with both Source and Sink patterns trigger full-file slicing
    - Test that already-sliced files are skipped
    - Test that failures write negative_fact nodes
    - _Requirements: 6.1, 6.2, 6.3_

- [~] 7. Checkpoint - Verify code audit enhancements
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Hypothesis-first code observation handling
  - [~] 8.1 Convert code observations into hypotheses and validation intents
    - After model graph decisions are computed, treat code_search hits and Source/Sink co-occurrence as observations
    - Create or update Hypothesis / Blackboard Fact entries before any delivery Finding is considered
    - Ensure model silence still allows ordinary graph expansion from observed facts
    - _Requirements: 2.1, 2.5_
  - [~] 8.2 Verify observation-to-hypothesis mapping
    - Confirm file upload source + file write sink forms an upload-path Hypothesis, not a confirmed Finding
    - Confirm input source + database query sink forms a dataflow ValidationIntent, not a confirmed Finding
    - Confirm input source + dynamic execution sink forms a command-path ValidationIntent, not a confirmed Finding
    - _Requirements: 2.3_
  - [~] 8.3 Ensure Findings remain delivery artifacts
    - Verify Source/Sink observations are not submitted directly as confirmed Findings
    - Confirm evidence-backed validated capabilities can be promoted to Findings at delivery time
    - Confirm ContractService only checks report quality and may request supplemental evidence without replacing DynamicIntentExpander
    - _Requirements: 2.4_
  - [ ]* 8.4 Write unit tests for hypothesis-first code observations
    - Test Source+Sink co-occurrence produces Hypothesis / ValidationIntent
    - Test deduplication prevents duplicate hypotheses for the same file and path
    - Test pattern hits do not directly produce confirmed Findings
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [ ] 9. Reason phase budget increase
  - [~] 9.1 Increase no-progress threshold in `runLoopIterations`
    - Change `consecutiveNoProgress >= 3` to `consecutiveNoProgress >= 5`
    - _Requirements: 3.1_
  - [~] 9.2 Verify graph expansion before exhaustion
    - Confirm DynamicIntentExpander and StateExpansionPlanner are consulted before the reason phase terminates
    - Ensure only meaningful graph expansion resets consecutiveNoProgress
    - _Requirements: 3.2_
  - [~] 9.3 Add audit event logging on reason budget exhaustion
    - Log an audit event with type "agent.reason_exhausted" recording passes attempted and termination reason
    - _Requirements: 3.3_
  - [ ]* 9.4 Write unit tests for reason budget increase
    - Test that loop allows 5 consecutive no-progress passes
    - Test that graph expansion resets the counter
    - Test that audit event is logged on exhaustion
    - _Requirements: 3.1, 3.2, 3.3_

- [ ] 10. Budget exhaustion graceful handling
  - [~] 10.1 Implement capability promotion on budget exhaustion in `cairn_loop.go`
    - When MAX_ITERATIONS is reached, call `PromoteCapabilitiesToFindings` before report generation
    - Do not return an error on budget exhaustion — proceed to report generation
    - _Requirements: 9.1_
  - [~] 10.2 Include all findings regardless of contract status in report
    - Modify `ReportService.loadSnapshot` or `Generate` to include hypothesis and contract_incomplete findings when budget is exhausted
    - Pass a flag or check task status to determine if budget was exhausted
    - _Requirements: 9.2_
  - [~] 10.3 Add incomplete evidence indicators in `report_service.go`
    - In `buildFindingViews` or `writeMarkdownFinding`, add a visual indicator when a finding has contract_incomplete status
    - Include a note explaining evidence is incomplete due to budget exhaustion
    - Apply the same indicator in HTML report rendering
    - _Requirements: 9.3_
  - [~] 10.4 Add audit event logging on budget exhaustion
    - Log an audit event with iteration count, number of findings, and number of pending unexecuted intents
    - _Requirements: 9.4_
  - [ ]* 10.5 Write unit tests for budget exhaustion handling
    - Test that capabilities are promoted to findings on exhaustion
    - Test that all finding statuses are included in the report
    - Test that incomplete evidence indicators appear in markdown and HTML output
    - Test that audit event contains correct metadata
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

- [~] 11. Final checkpoint - Full integration verification
  - Ensure all tests pass, ask the user if questions arise.

## Task Dependency Graph

```json
{
  "waves": [
    {
      "name": "Foundation",
      "tasks": ["1", "2"],
      "description": "Reasoning effort fix and ContextBuilder type extensions (no dependencies)"
    },
    {
      "name": "Bootstrap & Negative Facts",
      "tasks": ["4", "5"],
      "description": "Project index integration, bootstrap phase, and negative_fact recording (depends on ContextBuilder types from wave 1)"
    },
    {
      "name": "Code Audit Enhancements",
      "tasks": ["6", "8"],
      "description": "Full-file slicing, hypothesis formation, and validation intent creation (depends on negative_fact and bootstrap from wave 2)"
    },
    {
      "name": "Loop Tuning",
      "tasks": ["9", "10"],
      "description": "Graph expansion controls and budget exhaustion handling (depends on all prior features)"
    }
  ]
}
```

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- The implementation language is Go, matching the existing backend codebase
- Task ordering respects dependencies: ContextBuilder types (Task 2) are needed by Bootstrap (Task 4), negative_fact recording (Task 5) is used by full-file slicing (Task 6), and budget exhaustion (Task 10) depends on the graph exploration lifecycle being in place
