# Rabbit Runtime Proof Verification Result

## Test Result

- backend `go test ./...`: PASS
- frontend build: PASS

Commands run:

```bash
cd backend
go test ./...
```

```bash
cd frontend
npm run build
```

Frontend note: `npm run build` runs `vue-tsc -b && vite build`. Vite emitted third-party Rollup PURE annotation warnings from `@vueuse/core`; build still completed successfully.

## Final Verdict

Current system is Cairn-style runtime exploration:

- YES

Reason:

- A new runtime proof test now exercises the minimum loop with real DB, real `ToolRunService`, real `ResponseDiffTool`, real `EvidenceService`, real artifact storage, real Blackboard writes, real Hypothesis lifecycle, real Capability creation, real DynamicIntentExpander, real StateExpansionPlanner, and real `IntentService.NextPending`.
- The test does not call an external network target; it uses deterministic `response_diff` input to keep the proof safe and stable.
- The broader logic vulnerability smoke test still uses synthetic evidence for the user A / user B ownership story, so logic vulnerability readiness is marked partial for multi-session realism.

## Minimum Loop Proof

- test file: `backend/internal/service/recentering_regression_test.go`
- test function: `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
- real service chain: yes
- mock-only parts: none in ToolRun/Evidence path; input is deterministic and local
- flow proven:
  - Task row exists
  - Hypothesis is formed
  - ValidationIntent is created
  - real `ToolRunService.Execute` runs real `response_diff`
  - real `EvidenceService.CreateFromDraft` stores evidence hash/raw ref
  - Blackboard evidence node is written
  - DynamicIntentExpander creates follow-up Hypothesis / Intent from evidence
  - Hypothesis is resolved with evidence
  - Capability is written
  - Capability expansion creates next Intent
  - Planner scores pending intents
  - `NextPending` returns a follow-up pending intent
- missing parts: no external HTTP call; this is an intentionally safe deterministic runner proof

Key assertions:

- `outcome.ToolRun.ID != 0`
- `outcome.ToolRun.Status == success`
- `len(outcome.Evidence) == 1`
- evidence has non-empty `Hash`
- evidence has non-empty `RawRef`
- evidence Blackboard node ID is non-zero
- `ExpandFromEvidence` creates at least one follow-up hypothesis
- `WriteCapability` succeeds
- `NextPending` returns a new pending intent distinct from the executed one

## Runtime Call Chain

| Step | File | Function | Runtime Used | Test |
|---|---|---|---|---|
| Task Start | `backend/internal/service/task_service.go` | `TaskService.Create` | yes | `TestTaskCreationStillBootstrapsGoalHypothesisAndIntent` |
| Origin/Goal | `backend/internal/service/task_service.go` | `Create` lines creating `origin`, `goal`, GoalProfile, initial hypothesis, initial intent | yes | `TestTaskCreationStillBootstrapsGoalHypothesisAndIntent` |
| Observation/Fact | `backend/internal/service/agent_orchestrator.go` | `upsertFactsFromPentestEvidence`, `upsertFactsFromCodeEvidence`, `applyGraphDecision` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`, service-level graph tests |
| Hypothesis | `backend/internal/service/hypothesis_lifecycle_service.go` | `FormHypothesis` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent` |
| Intent | `backend/internal/service/hypothesis_lifecycle_service.go` | `CreateValidationIntent` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent` |
| Planner | `backend/internal/service/state_expansion_planner_service.go` | `ScorePendingValidationIntents` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`, planner tests |
| Budget | `backend/internal/service/exploration_budget_manager_service.go` | `AllowIntentGenerationFor`, `SuppressLowValueBranchesFor` | yes | budget manager tests |
| NextPending | `backend/internal/service/intent_service.go` | `NextPending` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`, `TestNextPendingSkipsRemovedExternalRepositoryIntentRows` |
| Runner/ToolRun | `backend/internal/service/toolrun_service.go` | `Execute` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent` |
| Evidence | `backend/internal/service/evidence_service.go` | `CreateFromDraft` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent` |
| Graph Update | `backend/internal/service/blackboard_service.go` | `UpsertNode`, `AddEdge` | yes | runtime proof test and lifecycle tests |
| Hypothesis Resolution | `backend/internal/service/hypothesis_lifecycle_service.go` | `ResolveIntentResult`, `ValidateHypothesis`, `RefuteHypothesis`, `MarkInconclusive` | yes | `TestEvidenceLifecycleStillProducesCapabilityNegativeFactAndUnverifiedRisk` |
| Capability/NegativeFact/UnverifiedRisk | `backend/internal/service/cairn_loop.go`, `hypothesis_lifecycle_service.go` | `WriteCapability`, `RefuteHypothesis`, `MarkInconclusive` | yes | lifecycle and runtime proof tests |
| Dynamic Expansion | `backend/internal/service/dynamic_intent_expander_service.go`, `hypothesis_lifecycle_service.go` | `ExpandFromEvidence`, `ExpandFromCapability` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`, `TestDynamicIntentExpanderCreatesOnlyMainLoopValidationIntent` |
| Next Intent | `backend/internal/service/intent_service.go` | `NextPending` | yes | `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent` |

## Runtime Call Chain Detail

### Task Start

- file: `backend/internal/service/task_service.go`
- function: `TaskService.Create`
- responsibility:
  - validates task type and authorization level
  - creates workspace and task
  - writes safe policy
  - writes authorized targets
  - initializes graph origin / goal / hypothesis / intent
- test coverage:
  - `TestTaskCreationStillBootstrapsGoalHypothesisAndIntent`

### Goal / Origin Initialization

- file: `backend/internal/service/task_service.go`
- function: `Create`
- creates:
  - GoalProfile: yes, via `EnsureDefaultGoalProfile`
  - origin node: yes, `NodeType: origin`
  - goal node: yes, `NodeType: goal`
  - initial hypothesis: yes, `FormHypothesis`
  - initial intent: yes, pending `AIIntent`
- test coverage:
  - `TestTaskCreationStillBootstrapsGoalHypothesisAndIntent`

### Observation / Fact Creation

- file: `backend/internal/service/agent_orchestrator.go`
- functions:
  - `runSingleIteration`
  - `upsertFactsFromPentestEvidence`
  - `upsertFactsFromCodeEvidence`
  - `applyGraphDecision`
- source:
  - code_search: yes
  - code_slice: yes
  - fingerprint: yes, as information-gathering evidence only
  - http_request / response_diff: yes
  - model graph reasoning: yes, facts only
- writes:
  - Evidence: yes, through `ToolRunService.Execute` and `EvidenceService.CreateFromDraft`
  - BlackboardNode: yes
  - BlackboardEdge: yes
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
  - `TestFingerprintEvidenceDoesNotTriggerExternalRepositorySideProbe`

### Hypothesis Creation

- file: `backend/internal/service/hypothesis_lifecycle_service.go`
- function: `FormHypothesis`
- input:
  - `HypothesisDraft`
  - source observation refs
  - target entity
  - expected capability
- output:
  - `AIHypothesisNode`
- creates AIHypothesisNode: yes
- creates graph node: yes, Blackboard node type `hypothesis`
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
  - `TestDynamicIntentExpanderCreatesOnlyMainLoopValidationIntent`
  - `TestLogicVulnerabilityStateExplorationSmoke`

### Intent Creation

- file: `backend/internal/service/hypothesis_lifecycle_service.go`
- function: `CreateValidationIntent`
- input:
  - `AIHypothesisNode`
  - intent type
  - validation method
  - priority
- output:
  - `AIIntent`
- creates AIIntent: yes
- writes ValidationMetadata: yes, `WithValidationMetadata`
- writes Blackboard intent node: yes
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
  - `TestTaskCreationStillBootstrapsGoalHypothesisAndIntent`

### Planner

- file: `backend/internal/service/state_expansion_planner_service.go`
- function: `ScorePendingValidationIntents`
- when called:
  - before selecting or continuing high-value validation branches
  - explicitly called in the runtime proof test after new pending intents exist
- writes PriorityScore / BranchValue: yes
- does not execute intent: confirmed yes
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
  - `TestScoreBranchValuePenalizesNegativeFactDuplicate`
  - `TestNegativeFactPenaltyRanksBelowEquivalentUnpenalizedIntent`
  - `TestBranchValueFinalScoreEqualsIntentPriorityAssignment`

### Budget Manager

- file: `backend/internal/service/exploration_budget_manager_service.go`
- functions:
  - `AllowIntentGenerationFor`
  - `SuppressLowValueBranchesFor`
- when called:
  - `ExpandFromEvidence`
  - `ExpandFromCapability`
  - branch-growth guardrail paths
- suppresses low-value branches: yes
- preserves high-value branches: yes
- test coverage:
  - `TestExplorationBudgetBlocksWhenPendingIntentLimitExceeded`
  - `TestExplorationBudgetBlocksWhenActiveBranchLimitExceeded`
  - `TestExplorationBudgetClampsGeneratedPerRound`
  - `TestLowValueSuppressBatchSelectsAtMostConfiguredLowestValue`
  - `TestDynamicCandidateSortingKeepsTopBranchValueCandidates`

### NextPending

- file: `backend/internal/service/intent_service.go`
- function: `NextPending`
- selection order:
  - `status = pending`
  - `intent_type IN runtimeIntentTypeList()`
  - `priority_score desc`
  - `created_at asc`
- removed Phase 7 intents skipped: yes
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
  - `TestNextPendingSkipsRemovedExternalRepositoryIntentRows`
  - `TestSuppressedIntentIsNotEligibleForNextPending`

### Runner / ToolRun

- file: `backend/internal/service/toolrun_service.go`
- function: `Execute`
- real ToolRun created: yes
- mock only: no
- runner type:
  - `http`, from real `ResponseDiffTool`
- tool name:
  - `response_diff`
- safety policy checked: yes, `tool.Validate(ctx, inputRaw, policy)`
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`

### Evidence Creation

- file: `backend/internal/service/evidence_service.go`
- function: `CreateFromDraft`
- evidence type:
  - `response_diff`
- hash created: yes
- raw ref / snapshot stored: yes, `LocalStore.PutText`
- blackboard evidence node created: yes, in runtime proof test and orchestrator runtime path
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`

### Hypothesis Resolution

- file: `backend/internal/service/hypothesis_lifecycle_service.go`
- function: `ResolveIntentResult`
- validated path:
  - evidence IDs present and no tool failure/block
- refuted path:
  - no evidence IDs or tool failed
- inconclusive path:
  - tool blocked
- test coverage:
  - `TestEvidenceLifecycleStillProducesCapabilityNegativeFactAndUnverifiedRisk`
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`

### Capability / NegativeFact / UnverifiedRisk

- files:
  - `backend/internal/service/cairn_loop.go`
  - `backend/internal/service/hypothesis_lifecycle_service.go`
- functions:
  - `WriteCapability`
  - `RefuteHypothesis`
  - `MarkInconclusive`
- capability created from evidence: yes
- negative fact created from refutation: yes
- unverified risk created from blocked/inconclusive: yes
- test coverage:
  - `TestEvidenceLifecycleStillProducesCapabilityNegativeFactAndUnverifiedRisk`
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`

### Dynamic Expansion

- file: `backend/internal/service/dynamic_intent_expander_service.go`
- functions:
  - `ExpandFromEvidence`
  - `ExpandFromCapability`
- trigger:
  - new evidence: yes
  - new capability: yes
  - negative fact: affects suppression / duplicate penalty
  - unverified risk: retained as graph state; no direct expansion test yet
- creates next intent: yes
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
  - `TestDynamicIntentExpanderCreatesOnlyMainLoopValidationIntent`
  - `TestLogicVulnerabilityStateExplorationSmoke`

### Next Round

- new pending intent exists: yes
- eligible for NextPending: yes
- test coverage:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`

## Core Tests

### Minimum Loop Test

- test file: `backend/internal/service/recentering_regression_test.go`
- test function: `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
- uses real DB: yes, sqlite in-memory with `database.AutoMigrate`
- uses real service chain: yes
- uses mock model: no model involved
- uses mock runner: no; uses real `ResponseDiffTool` through real `ToolRunService`
- creates task: yes, persisted `AISecurityTask`
- creates hypothesis: yes
- creates intent: yes
- selects NextPending: yes
- creates ToolRun: yes
- creates Evidence: yes
- creates Capability: yes
- creates next Intent: yes
- key assertions:
  - ToolRun persisted and status is success
  - Evidence persisted with hash/raw ref
  - Evidence node written to Blackboard
  - Evidence expansion creates hypothesis
  - Intent resolution validates hypothesis
  - Capability write succeeds
  - Planner scores pending intents
  - NextPending returns follow-up intent

### NegativeFact Path Test

- test file: `backend/internal/service/recentering_regression_test.go`
- test function: `TestEvidenceLifecycleStillProducesCapabilityNegativeFactAndUnverifiedRisk`
- refuted hypothesis: `refuted branch`
- evidence:
  - no supporting evidence IDs
- negative fact:
  - created by `ResolveIntentResult` → `RefuteHypothesis`
- duplicate penalty source:
  - `SimilarPatternKey` in `AINegativeFact`
- planner ranking affected: yes
- key assertions:
  - `AINegativeFact` count for refuted hypothesis is `1`
  - `TestScoreBranchValuePenalizesNegativeFactDuplicate`
  - `TestNegativeFactPenaltyRanksBelowEquivalentUnpenalizedIntent`

### UnverifiedRisk Path Test

- test file: `backend/internal/service/recentering_regression_test.go`
- test function: `TestEvidenceLifecycleStillProducesCapabilityNegativeFactAndUnverifiedRisk`
- blocked / timeout / inconclusive reason:
  - `ToolBlocked: true`
  - reason: authorized safety gate blocked validation
- created UnverifiedRisk:
  - yes, via `ResolveIntentResult` → `MarkInconclusive`
- not treated as NegativeFact: yes
- retained in graph/report context: yes, stored as `AIUnverifiedRisk` and Blackboard node type `unverified_risk`
- key assertions:
  - `AIUnverifiedRisk` count for blocked hypothesis is `1`

### Dynamic Expansion Test

- test file: `backend/internal/service/recentering_regression_test.go`
- test function:
  - `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent`
  - `TestDynamicIntentExpanderCreatesOnlyMainLoopValidationIntent`
  - `TestLogicVulnerabilityStateExplorationSmoke`
- capability:
  - `cross_user_object_access`
- expander input:
  - real `response_diff` evidence in minimum runtime proof
  - verified capability in logic smoke
- generated intent:
  - follow-up pending validation intent
- dedup check:
  - `FormHypothesis` and `CreateValidationIntent` check existing hypothesis/intent
- budget check:
  - `AllowIntentGenerationFor`
- eligible for NextPending: yes
- key assertions:
  - generated hypothesis count > 0
  - follow-up pending intent count > 0
  - `NextPending` returns a new pending intent

### Logic Vulnerability Smoke Test

- test file: `backend/internal/service/recentering_regression_test.go`
- test function: `TestLogicVulnerabilityStateExplorationSmoke`
- scenario:
  - User B may access User A object
- actor/session model:
  - partial, represented in hypothesis text and response-diff evidence
- object ownership model:
  - yes, target `/owner-check/objects/123`
- runner/toolrun:
  - smoke test itself uses synthetic evidence
  - runtime minimum loop uses real `response_diff` ToolRun for the same ownership class
- evidence:
  - `response_diff`
- result:
  - Capability: `cross_user_object_access`
  - NegativeFact: covered by lifecycle test
  - UnverifiedRisk: covered by lifecycle test
- next intent:
  - yes, capability expansion creates follow-up intent
- real execution or mocked:
  - PARTIAL: logic smoke evidence is synthetic
  - Runtime proof test uses real `ResponseDiffTool`, but not a full multi-session HTTP client fixture
- key assertions:
  - capability count is `1`
  - next pending intent count is non-zero
- current limitations:
  - no full two-session HTTP fixture yet
  - no persistent actor/session object model table yet

## Removed Feature Verification

- Phase 7 ProofPacket runtime removed: yes
- External PoC/CVE mainline removed: yes
- DeepCodeAudit finding-first path removed: yes
- Remaining references:
  - runtime: none found by the requested grep scans
  - tests: removed-regression strings exist only as concatenated inert intent names in tests, used to prove skipped/removed behavior
  - docs: `docs/rabbit-recentering-modification-summary.md` intentionally names removed features and old flows as historical summary
  - false positives:
    - report/delivery fields such as `curl_poc`, `bash_poc`, `python_poc` still exist in report rendering; these are delivery formatting fields, not external PoC lookup or ProofPacket runtime

### Removed Feature Scan

#### Runtime code

- remaining references:
  - none for:
    - `ProofPacket`
    - `proof_packet`
    - `RepoSourceManager`
    - `SafeProbe`
    - `safe_packet_validate`
    - `proof_packet_search`
    - `proof_packet_normalize`
    - `DeepCodeAudit`
    - `deepCodeAudit`
- explanation:
  - runtime code no longer contains Phase 7 repository side-probe, SafeProbe, or DeepCodeAudit finding-first path.

#### Tests only

- remaining references:
  - `removedIntentTypes()` builds removed intent names by concatenation.
- explanation:
  - these strings are only used to assert inert/removed behavior in `NextPending`.

#### Docs

- remaining references:
  - `docs/rabbit-recentering-modification-summary.md`
- explanation:
  - this is a historical summary document describing what was removed. It is not runtime design guidance.

#### False positives

- remaining references:
  - `curl_poc`, `bash_poc`, `python_poc`
- why safe:
  - these are report delivery fields for evidence-backed validation output. They do not fetch public PoC repositories, do not trigger CVE lookup, and do not plan exploration.

## Scanner / CVE / PoC / ProofPacket Residuals

| Path | Status | File / Function |
|---|---|---|
| fingerprint → CVE Search | removed | no runtime reference found |
| fingerprint → external PoC lookup | removed | no runtime reference found |
| fingerprint → ProofPacket | removed | no runtime reference found |
| pattern hit → confirmed Finding | removed | `ExpandFromEvidence` creates hypotheses; `TestFindingIsDeliveryArtifactOnlyAfterValidatedCapability` asserts no finding |
| model guess → confirmed Finding | removed | DeepCodeAudit path removed; `SecurityGraphDecision` has facts and next intents only |
| Contract repair → main planner | removed | `ContractService` can create supplemental evidence intent, but orchestrator no-progress reset no longer uses contract repair |
| Finding count → main termination | removed | `CairnLoop.ShouldFinalize` comment and logic use budget/no-progress/capability/pending-intent signals |

## Finding / Contract Boundary

- Finding is delivery artifact: yes
- Contract is report quality gate: yes
- model guess cannot confirmed Finding: yes
- pattern hit cannot confirmed Finding: yes
- fingerprint cannot Finding: yes

### Finding Guardrails

- file: `backend/internal/service/finding_service.go`
- function:
  - `NewFindingService`
  - `UpsertCandidate`
  - `CreateCandidate`
- evidence requirement:
  - Findings are created from evidence refs and currently promoted from verified capabilities in `CairnLoop.PromoteCapabilitiesToFindings`.
- capability requirement:
  - delivery promotion path uses `AICapability` with `strength = verified` and `can_advance_goal = true`.
- validation status requirement:
  - delivery promotion supplies `ValidationDynamicallyValidated`; Contract can downgrade incomplete delivery artifacts.
- tests:
  - `TestFindingIsDeliveryArtifactOnlyAfterValidatedCapability`
  - `TestContractDowngradesIncompleteFindingWithoutConfirmingIt`

### Contract Boundary

- file: `backend/internal/service/contract_service.go`
- function:
  - `CheckFinding`
- can downgrade incomplete finding: yes
- can request supplemental evidence intent: yes
- cannot replace DynamicIntentExpander: yes
- cannot reset no-progress just because report fields missing: yes
- cannot become main planner: yes
- tests:
  - `TestContractDowngradesIncompleteFindingWithoutConfirmingIt`

## Code Audit Flow

- code_search only Observation/Evidence: yes
- Source/Sink co-occurrence only Hypothesis/Intent: yes
- Finding requires evidence-backed validated path: yes

Details:

- `runCodeAuditIntent` executes `code_search`.
- `buildFileSecurityIndex` identifies Source/Sink co-occurrence and creates `code_trace` intents.
- `upsertFactsFromCodeEvidence` writes code observations as Blackboard facts.
- `ExpandFromEvidence` maps code evidence to Hypothesis / ValidationIntent.
- No code path creates confirmed Finding directly from code_search or model snippet analysis.

Tests:

- `TestDynamicIntentExpanderCreatesOnlyMainLoopValidationIntent`
- `TestFindingIsDeliveryArtifactOnlyAfterValidatedCapability`

## Pentest Flow

- fingerprint only EnvironmentModel/Fact: yes
- no external PoC lookup: yes
- response_diff supports Hypothesis resolution: yes
- Runner HTTP validation works: yes

Details:

- `runPentestIntent` runs recon/fingerprint/validation tools.
- fingerprint evidence is information-gathering only.
- `TestFingerprintEvidenceDoesNotTriggerExternalRepositorySideProbe` asserts fingerprint evidence does not create side-probe hypotheses/intents.
- `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent` proves `response_diff` can produce real Evidence and drive Hypothesis resolution / Capability / next Intent.

## Planner / Budget Boundary

- Planner executes intent: no
- Planner creates Finding: no
- Planner writes branch_value: yes
- Budget executes intent: no
- Budget creates Finding: no
- Budget suppresses low-value branch: yes
- Budget preserves high-value branch: yes
- tests:
  - `TestScoreBranchValuePenalizesNegativeFactDuplicate`
  - `TestNegativeFactPenaltyRanksBelowEquivalentUnpenalizedIntent`
  - `TestExplorationBudgetBlocksWhenPendingIntentLimitExceeded`
  - `TestExplorationBudgetBlocksWhenActiveBranchLimitExceeded`
  - `TestExplorationBudgetClampsGeneratedPerRound`
  - `TestLowValueSuppressBatchSelectsAtMostConfiguredLowestValue`
  - `TestDynamicCandidateSortingKeepsTopBranchValueCandidates`

## Logic Vulnerability Readiness

| Capability | Status | Evidence |
|---|---|---|
| multi-session / actor comparison | partial | represented in hypothesis/evidence text; no full two-session HTTP fixture |
| object ownership validation | yes | `TestLogicVulnerabilityStateExplorationSmoke`, `TestRuntimeMinimumLoopUsesRealToolRunEvidenceAndNextIntent` |
| state transition validation | partial | capability ladder exists from `cross_user_object_access` to `unauthorized_state_transition`; no full workflow fixture |
| pre/post state comparison | partial | `response_diff` supports observable difference; no persistent state fixture yet |
| business value tampering | partial | capability exists and planner scores it; no end-to-end business fixture |

## Risks

- Full AgentOrchestrator end-to-end test with a real local HTTP fixture is still absent.
- Logic vulnerability smoke is partially synthetic for actor/session modeling.
- `ContractService.CheckFinding` can still create supplemental evidence intents, but this is bounded to report quality; future changes should keep it out of no-progress reset and main planning.
- Historical summary docs intentionally contain removed feature names; future grep scans should classify them as docs/history, not runtime.

## Required Fixes

- None required for current acceptance.

Recommended hardening:

- Add a local two-account HTTP fixture to test full IDOR flow through `runPentestIntent`.
- Add a code-audit fixture ZIP that proves `code_search → code_trace intent → code_slice evidence → hypothesis resolution`.
- Add an explicit report snapshot test proving UnverifiedRisk and NegativeFact are retained in final report context.

## Final Decision

- ACCEPTED

Reason:

- The runtime now has a tested Fact → Intent → Explore → Fact loop with real ToolRun/Evidence services.
- Phase 7 and DeepCodeAudit finding-first runtime paths are absent.
- Finding and Contract are bounded to delivery/report quality.
- Backend and frontend verification commands pass.
