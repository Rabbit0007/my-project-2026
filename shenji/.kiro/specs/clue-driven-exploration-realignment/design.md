# Clue-Driven Exploration Realignment — Design

> **Spec scope**：本 spec 是对 Rabbit 现有系统的核心回正，不是新增孤立功能。
> 目标：把循环驱动力从 vulnerability/finding/report-driven 回正为 clue-driven，
> 让 Kernel / Security Exploration / Tool Collection / Evidence Gate / Delivery Layer
> 五层职责硬分离。
>
> 本文件是 Design-First 工作流的产物，覆盖 High-Level + Low-Level Design，
> 同时把 Migration Plan、Risks、Decisions 一起落齐。Requirements 与 Tasks 拆到
> 同目录的 `requirements.md` / `tasks.md`，在本 design 通过用户确认后再产出。
>
> 本版本已合并 design review 反馈第 1–14 条修正。

## Overview

Rabbit 当前的实现仍保留了若干 vulnerability/finding/report-driven 的耦合，
违反了项目宪章中的 Cairn-style state-space exploration 定位。本 spec 把系统
回正为 **clue-driven**：

- **Clue 是第一对象**。所有循环输入与输出都是 Clue：
  - **Fact** = 已确认的线索（confirmed clue）
  - **Intent** = 下一步线索收集 / 验证任务
  - **Evidence** = 线索的证明材料
  - **NegativeFact** = 已被证伪的线索
  - **Capability** = 一条闭合 ClueChain（origin → links → impact）所代表的
    安全影响能力
- 主循环的所有调度、扩展、终止判定都来自图（blackboard）上的 Clue 状态。
- 漏洞类型枚举、source/sink 模板、Finding/Report/Contract 都从 Reason 路径上
  摘除，仅在 Delivery Layer 内部使用。
- LLM Reasoner 的 prompt 不再列举漏洞类型，也不再要求模型返回 vuln-type
  intent。

### Goals

- 把 Rabbit 的循环驱动力从 finding/report 回正为 clue。
- 强制 Kernel / Security Exploration / Tool Collection / Evidence Gate /
  Delivery Layer 五层职责分离。
- 保留 Capability / Finding / Report 的产物，但解耦它们与主循环的反馈路径。
- 修正用户提示词中明确列出的 6 个代码级问题（P1–P6，详见 Architecture
  §"Existing Issues"）。
- 提供分阶段、可独立 ship、可独立回滚的 Migration Plan。

### Non-Goals（硬约束，不允许扩张）

1. **不把语言 extractor / AST / source-sink 规则模板当作核心 Reason 驱动力或
   漏洞判断来源**。边界澄清（防止矫枉过正）：
   - **允许**：工具层使用 AST / symbol / route / call candidate / call graph /
     code navigation 等能力作为 ClueObservation 的采集手段。
   - **允许**：static analyzer / language-aware extractor 作为 Tool
     Collection 层的实现细节存在。
   - **禁止**：让这些能力直接产出 vulnerability classification、severity、
     CWE 标签、Finding 草稿。
   - **禁止**：在 Reason / Explore prompt 或 deterministic 分支里以
     "source/sink/pattern hit"为主体决定 Intent。
   AST / symbol / route / call graph 可以是线索采集工具，**不能是漏洞判断
   主体**。
2. **不基于漏洞类型枚举（SQLi / XSS / SSRF / IDOR / RCE 等）生成 Intent**。
   所有 Intent 类型统一收敛到 clue_collect / clue_validate / clue_refute /
   clue_chain_extend / scope_observation 五个通用动词。具体操作意图通过
   `operation` / `intent_goal` 字段表达。
3. **不把 Finding / Report / Contract 当作主循环驱动**。
   - Finding 数量不能作为终止条件。
   - Contract incomplete 不能反向写回 Reason 路径产出 Intent；只能在 Delivery
     Layer 内部写 diagnostic / audit。
   - Report 是单向 sink，不向上游写回任何状态。
4. **不删除已有 Finding / Report / Contract 表与视图**。它们仍是 Delivery
   产物，前端依然能看到；只是从 Reason / Promotion 路径上解耦。
5. **不重写工具实现**（http_request / code_search / sandbox_exec 等）。只重新
   定义它们对 Clue 的输出契约（Tool Observation Contract，详见 Components 章节），
   工具内部代码尽量保持稳定。
6. **不引入新表**。所有 Clue 概念用现有 `AIBlackboardNode` + `AIBlackboardEdge`
   承载，靠 NodeType / EdgeType 枚举扩展。
7. **不破坏正在跑的任务**。已写入 DB 的旧 NodeType / IntentType 必须能继续被
   读出并降级映射，不允许出现"老任务跑不完"或"老 finding 看不到"的情况。
8. **不做"纯 LLM 盲审"**。LLM 是 Reasoner，不是 oracle。任何 Capability 提升
   都必须有 ClueChain 闭合 + 工具/静态/运行 evidence 支撑；模型输出经过
   sanitizer 后才能进入图。

## Architecture

### Existing Issues（来自用户提示词，本 spec 必须修复）

| ID | 问题 | 现状（文件 / 函数） | 期望 |
|---|---|---|---|
| P1 | ShouldFinalize 在 SurfaceCount=0 时退化为 plateau，会过早或过晚终止 | `cairn_loop.go::BuildCoverageGoalState` | 引入 clue-progress fallback，三类终止：clue-coverage-sufficient / budget-exhausted / clue-plateau |
| P2 | Worker GraphDelta 合并时把结构化 clue 字段扁平化成字符串 fact / hypothesis | `cairn_loop.go::GraphDelta`、`worker_driver_service.go` | 保留结构化字段：`new_clue_facts` / `clue_chain_link` / `refuted_clue`；非结构化老字段降级为 observation-only |
| P3 | legacy vuln-type intent 仍硬编码（sql_injection_validation / idor_test 等） | `agent_orchestrator.go::isPentestRuntimeIntent`、`model_runtime_service.go` 各 prompt | 全部降级为通用 clue_validate；保留 alias 映射表 + audit 事件 |
| P4 | Capability Promotion Gate 仍以 delivery proof 字段（curl/python_poc/entrypoint→sink 模板）作为通过条件 | `agent_orchestrator.go::deliveryProofSummaryForCapability` 在 Promotion 路径被调用、`cairn_loop.go::CapabilityPromotionGate` | Promotion Gate 改为评估 ClueChain role coverage。delivery proof 函数保留，但仅 Delivery Layer 调用 |
| P5 | LLM prompt 列举漏洞类型，模型返回也按漏洞类型组织 | `model_runtime_service.go::buildPlannerPrompt` / `buildSecurityGraphPrompt` | 改为 clue-driven prompt 骨架，要求模型返回结构化 Clue 操作 |
| P6 | deterministic fallback（无模型情况）也在生成 vuln-type intent | `model_runtime_service.go::deterministicIterationPlan`、`deterministicEvidenceIntent` | fallback 也必须 clue-driven |

### 五层架构

> 五层之间的写入方向必须是 **下游不允许写上游图**。
> Delivery 不写 Kernel，Tools 不写 Capability，Exploration 不直接调工具。

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5: Delivery Layer                                        │
│  - Finding / Contract / Report                                  │
│  - 仅消费 closed ClueChain + Capability，做包装/导出             │
│  - 禁止：写 Intent / Hypothesis / Capability / Edge              │
└──────────────────────────────▲──────────────────────────────────┘
                               │ read-only (closed clue chains)
┌──────────────────────────────┴──────────────────────────────────┐
│  Layer 4: Evidence Gate                                         │
│  - 把 ClueObservation 升格为 Evidence / Fact / NegativeFact      │
│  - ClueChain 闭合判定 + Capability 提升                          │
│  - 禁止：调用工具、生成 Finding/Report                            │
└──────────────────────────────▲──────────────────────────────────┘
                               │ ToolRun + ClueObservation
┌──────────────────────────────┴──────────────────────────────────┐
│  Layer 3: Tool Collection                                       │
│  - tool registry / runner / SafePolicy                           │
│  - 接收 Intent，输出 ToolRun + ClueObservation 草稿              │
│  - 禁止：写 Capability / NegativeFact / Finding；不感知漏洞类型    │
└──────────────────────────────▲──────────────────────────────────┘
                               │ Intent
┌──────────────────────────────┴──────────────────────────────────┐
│  Layer 2: Security Exploration                                  │
│  - Reasoner（LLM 多模型） / ClueExpander / CoverageTracker       │
│  - 只读图，写 Intent 与 ClueDelta                                 │
│  - 禁止：直接调用 tools；引用漏洞类型枚举；引用 Finding/Report     │
└──────────────────────────────▲──────────────────────────────────┘
                               │ next-clue dispatch
┌──────────────────────────────┴──────────────────────────────────┐
│  Layer 1: Kernel (Cairn Loop)                                   │
│  - 状态空间循环、Clue 调度、终止判定、预算控制                    │
│  - 不感知漏洞类型，不感知 Finding/Report                          │
└─────────────────────────────────────────────────────────────────┘
```

### 主循环（Kernel）

```
loop iterationNo in 1..MaxIterations:
  if ShouldFinalize(coverage, recentProgress, budget):
    break
  intent ← Kernel.PickNextClueIntent(blackboard)
  if intent == nil:
    delta ← Exploration.Reason(blackboard)        // LLM or deterministic
    Kernel.IngestClueDelta(delta)                 // structured clue write-back
    if delta.spawned_intents == 0:
      consecutiveNoProgress++
    continue
  toolRun, observation ← Tools.Execute(intent)
  EvidenceGate.Ingest(observation)                // 升格 / 否决 / 链接
  if EvidenceGate.ChainClosed(intent.targetClue):
    Capability ← EvidenceGate.PromoteCapability(chain)
finalize:
  Delivery.GenerateArtifacts(closedCapabilities)  // 单向 sink
```

要点：
- `PickNextClueIntent` 优先级：未闭合 ClueChain 上的下一步 > 高优先级
  clue_collect > scope_observation。
- Reason 阶段必须返回**结构化 ClueDelta**（GraphDelta），否则视为 no-op。
- Tools 不感知 Capability/Finding，只产 ClueObservation。
- 终止决策只读 Coverage + RecentProgress + Budget，不读 finding / contract。

### ShouldFinalize（含 plateau fallback，修复 P1）

判定式（伪代码）：

```go
func ShouldFinalize(c CoverageState, p RecentProgress, b BudgetState) (stop bool, reason string) {
    if b.Remaining <= 0 {
        return true, "budget-exhausted"
    }
    if c.OpenHighPriorityIntents == 0 &&
       c.UnresolvedHighPriorityClues == 0 &&
       c.ScopeSummary.SurfaceCount > 0 {
        return true, "clue-coverage-sufficient"
    }
    // P1 fallback: SurfaceCount == 0 时不再直接判 plateau，
    // 改成「最近 N 轮无任何 clue / evidence / capability / 新 surface 增长 + 无 pending high-value clue」
    if p.NewClueFactsLastN == 0 &&
       p.NewEvidenceLastN == 0 &&
       p.NewCapabilitiesLastN == 0 &&
       p.NewSurfacesLastN == 0 &&
       c.OpenHighPriorityIntents == 0 {
        return true, "clue-plateau"
    }
    return false, ""
}
```

`RecentProgress` 必须新增 `NewClueFactsLastN` 字段（`GraphRecentProgress`，
`cairn_loop.go`）。`SurfaceCount > 0` 不再是 coverage_sufficient 的唯一前提，
但仍保留以避免误判没有 surface 的纯代码审计任务。

### Capability Promotion Gate（修复 P4 + Role Coverage）

旧逻辑（要废）：依赖 `entrypoint / propagation_path / sensitive_sink_or_behavior /
trigger_payload_or_action / bash_poc / python_poc` 等 delivery proof 字段。

新逻辑必须基于 **Clue Role Coverage**（详见 Data Models 章节中的 Clue Roles
and Closure Semantics），而不是简单的 "origin + link + impact + evidence"
包装。这是为了防止模型用模糊话术构造一个形式上闭合、但缺少安全语义关键
角色的 ClueChain，导致 Capability 过早 verified。

伪代码：

```go
type ClueChainEval struct {
    Allowed         bool
    Strength        string                  // suspected | observed | verified
    Missing         []string                // 缺失的 role 名称
    EvidenceRefs    []uint
    NodeRefs        []uint                  // chain 上的 clue 节点
    Relations       []string                // clue_supports / clue_chains_to / ...
    RoleCoverage    map[string][]uint       // role -> nodes covering this role
    RoleEvidence    map[string][]uint       // role -> evidence refs supporting this role
    NegativeRefutes []uint                  // 命中本 chain 的 active NegativeFact ids
}

// requiredClueRoles:
//   origin_or_entry
//   trigger_or_control
//   reachability_or_relation
//   security_effect_or_impact
//   control_state_or_missing_control
//   verification_or_observation
func EvaluateClueChain(chainID uint) ClueChainEval {
    chain := loadChain(chainID)
    coverage := chain.RoleCoverage()                  // map[role][]nodeID
    evidence := chain.RoleSupportingEvidence()        // map[role][]evidenceID
    refutes  := chain.ActiveRefutationsAgainst()      // []NegativeFact
    missing  := []string{}
    for _, role := range requiredClueRoles {
        nodes := coverage[role]
        if len(nodes) == 0 {
            missing = append(missing, role)
            continue
        }
        if len(evidence[role]) == 0 {
            missing = append(missing, role+":evidence")
        }
    }
    if !chain.AllNodesActive() {
        missing = append(missing, "active_nodes")
    }
    if len(refutes) > 0 {
        missing = append(missing, "refuted_by_negative_fact")
    }
    strength := classifyChainStrength(chain, coverage, evidence, missing)
    return ClueChainEval{
        Allowed: len(missing) == 0, Strength: strength, Missing: missing,
        EvidenceRefs: chain.SupportingEvidenceIDs(), NodeRefs: chain.NodeIDs(),
        Relations: chain.EdgeKinds(), RoleCoverage: coverage,
        RoleEvidence: evidence, NegativeRefutes: idsOf(refutes),
    }
}

// 三档语义（见 Resolved Decisions 章节）
func classifyChainStrength(chain Chain, coverage map[string][]uint,
                           evidence map[string][]uint, missing []string) string {
    if len(missing) == 0 {
        return "verified"
    }
    hasObservationalSupport := len(evidence["verification_or_observation"]) > 0 ||
                               len(coverage["security_effect_or_impact"]) > 0
    if hasObservationalSupport {
        return "observed"
    }
    return "suspected"
}
```

边界规则：
- `deliveryProofSummaryForCapability` **不再被 Promotion 调用**，只在 Delivery
  Layer 写 Finding rich detail 时使用。
- 老的 `requiredCapabilityEvidenceRelations`（entrypoint_or_exposure 等五项）
  改名为 `clueChainRelationHints`，仅作 hint，不参与 gating。
- ClueChain 上若存在任何 active NegativeFact 直接反驳本 chain 的 link/impact，
  Promotion 失败（Strength 退回 `observed` 或 `suspected`）。
- 一个 Clue 节点可以同时承担多个 role（详见 Data Models），所以 role coverage
  不要求 6 个独立节点，但每个 role 必须有 evidence 支撑。

### Worker GraphDelta 合并（修复 P2 + Explore 输出契约）

**Explore 输出契约**：Explore（无论 LLM Reasoner 还是 deterministic fallback，
无论 brain 模型还是 worker 模型）的输出**统一是 GraphDelta**，不是单个 Fact，
不是 Finding 草稿，不是 Report 段落。GraphDelta 可以包含多个 clue
observations / evidence refs / refutations / new intents / diagnostics，
但**每个 GraphDelta 必须围绕当前 Intent**，不允许做全局报告式输出（例如
"列出本次任务发现的全部漏洞"会被 sanitizer 直接丢弃）。

合并规则：
1. 优先用新结构化字段写图。`NewClueFacts` → blackboard upsert（NodeType 用
   `ClueFact.NodeKind`）。
2. `ClueChainLinks` → 写 `AIBlackboardEdge`，EdgeType 来自 `link_kind` 经
   标准映射。
3. `RefutedClues` → 写 `clue_refuted` 节点 + `clue_refutes` Edge，并把目标
   clue 节点状态置为 suppressed。
4. **旧字段**（`NewFacts` / `NewNegativeFacts` / `NewCapabilityCandidates`）若
   同时出现，仅作 observation-only 入图，不参与 Promotion 决策。
5. Worker 不返回任何 `vuln_type` / `propagation_path` 字段；若返回则忽略
   （带 audit）。

## Components and Interfaces

### Layer 1 · Kernel
- **输入**：当前任务 ID、blackboard 状态。
- **输出**：next dispatch（pick clue → spawn intent → run → ingest → finalize?）。
- **禁止**：感知 NodeType 之外的业务语义；引用 vuln-type / finding / report 字段。
- **关键函数（待迁移）**：`AgentOrchestrator.runLoopIterations`、
  `CairnLoop.ShouldFinalize*`、`CairnLoop.BuildCoverageGoalState`、
  `CairnLoop.PromoteCapabilitiesToFindings`（promote 部分要拆出去到 Layer 4）。

```go
type ClueKernel interface {
    PickNextClueIntent(ctx context.Context, taskID uint) (*model.AIIntent, error)
    ShouldFinalize(ctx context.Context, taskID uint, budget BudgetState) (stop bool, reason string)
    IngestClueDelta(ctx context.Context, taskID uint, delta GraphDelta) error
}
```

### Layer 2 · Security Exploration
- **输入**：blackboard 子集（GraphSummary）、模型配置。
- **输出**：Intent（clue_collect / clue_validate / ...）、ClueDelta
  （new_clue_facts / clue_chain_link / refuted_clue）。
- **禁止**：直接调用 tool registry；prompt 中提及具体漏洞类型；读
  Finding/Report。
- **关键函数（待迁移）**：`AgentOrchestrator.runReasonPhase`、
  `ModelRuntimeService.PlanIteration` / `AnalyzeSecurityGraph`、
  `DynamicIntentExpanderService`、`StateExpansionPlannerService`。

```go
type ClueExpander interface {
    // 输入是任务 + 压缩后的 GraphSummary；输出是 GraphDelta（围绕当前
    // pickedIntent，包含结构化 clue 字段、新 Intent、diagnostics）。
    // GraphDelta 已经过 sanitizer，不会带 vuln_type / cwe / severity。
    Reason(ctx context.Context, task model.AISecurityTask,
           summary GraphSummary,
           pickedIntent *model.AIIntent) (GraphDelta, error)
}
```

### Layer 3 · Tool Collection
- **输入**：单条 Intent + workspace。
- **输出**：ToolRun（持久化）+ ClueObservation 草稿（结构化，遵循 Tool
  Observation Contract，详见 Data Models）。一次工具执行可产生 0..N 个
  observation，每个 observation 带 `observation_type` ∈ {supporting /
  refuting / blocked / no_signal / error}。
- **允许**：使用 AST / symbol / route / call candidate / call graph / code
  navigation 等能力作为采集手段；输出 refuting / blocked / no_signal /
  error observation —— 这些是重要线索，不能丢。
- **禁止**：
  - 直接持久化 `AICapability` / `AIFinding` / `AINegativeFact`。
  - ToolResult 中带 `vulnerability_type` / `cwe` / `severity` /
    `finding_title` 等漏洞分类字段。
  - 自行决定 ClueChain 闭合或 Capability 提升。
- **NegativeFact 路径**：工具不能直接写 `AINegativeFact`，但**必须**允许输出
  refuting / blocked / no_signal / error observation；Evidence Gate 决定是否
  升格为 NegativeFact / `clue_refuted` 节点。否则验证失败、路径阻塞、无差异
  响应等关键负向线索会被丢失。
- **关键文件**：`backend/internal/tools/*`、
  `backend/internal/runner/manager.go`、`ToolRunService.Execute`。

### Layer 4 · Evidence Gate
- **输入**：ToolRun + ClueObservation 草稿、当前 ClueChain 状态。
- **输出**：
  - Evidence / Fact 节点（来自 supporting observation）；
  - `clue_refuted` 节点 + `AINegativeFact`（来自 refuting / blocked /
    no_signal observation 的升格）；
  - Edge（clue_supports / clue_refutes / clue_chains_to）；
  - 新版 Capability（Strength = ClueChain role coverage 完成度）。
- **禁止**：调工具；调用 Finding/Report；引用漏洞类型字段做 Promotion 决策。
- **核心职责**：判定 ClueChain 闭合与否（Architecture §"Capability Promotion
  Gate"），是 Capability Promotion 的唯一权威。
- **新增组件**：`ClueChainService`（新文件
  `backend/internal/service/clue_chain_service.go`）。

```go
type EvidenceGate interface {
    PromoteObservation(ctx context.Context, taskID uint, obs ClueObservation) (Evidence, error)
    LinkClues(ctx context.Context, taskID uint, link ClueChainLink) error
    Refute(ctx context.Context, taskID uint, ref ClueRefutation) error
    EvaluateChain(ctx context.Context, chainID uint) ClueChainEval
    PromoteCapability(ctx context.Context, taskID uint, eval ClueChainEval) (*model.AICapability, error)
}
```

### Layer 5 · Delivery Layer
- **输入**：closed Capability（含 ClueChain ref）+ 任务元信息。
- **输出**：Finding / ContractCheck / Report 持久化。
- **禁止**：向上游写 Intent / Hypothesis / Capability / Edge / Fact / Node；
  调用 ModelRuntime 的 `PlanIteration` / `AnalyzeSecurityGraph`（仅允许调
  `GenerateReportNarrative`）。
- **关键函数**：`FindingService`、`ContractService`、`ReportService`。

```go
type DeliveryLayer interface {
    BuildFindingFromCapability(ctx context.Context, cap model.AICapability) (model.AIFinding, error)
    GenerateReport(ctx context.Context, taskID uint) (model.AIReport, error)
}
```

`FindingService` / `ReportService` / `ContractService` 现有方法保留；新增
`BuildFindingFromCapability` 取代 `agent_orchestrator.go::deliveryProofSummaryForCapability`
被 Promotion 路径直接调用的现状。

### LLM Prompt 骨架（修复 P5）

#### Planner system prompt（替代 `buildPlannerPrompt`）

```
You are the Reasoner of a clue-driven security exploration system.
Your job: read the current blackboard summary, decide which CLUE to advance,
and emit STRUCTURED clue operations. You MUST NOT classify findings, propose
specific vulnerability types, or output report-style language.

Output JSON shape:
{
  "thought_summary": "...",
  "planned_action": "...",
  "next_intents": [
    {
      "intent_type": "clue_collect | clue_validate | clue_refute | clue_chain_extend | scope_observation",
      "operation": "resolve_unknown | correlate_clues | compare_behavior | expand_surface | recheck_inconclusive | inspect_auth_boundary | inspect_runtime_behavior | inspect_business_object | <other free-form operation phrase>",
      "intent_goal": "concrete clue-progress sentence describing what this intent advances on the chain",
      "title": "...",
      "objective": "...",
      "target_clue_refs": [<node ids>],
      "expected_evidence": "...",
      "expected_clue_roles": ["origin_or_entry" | "trigger_or_control" | "reachability_or_relation" | "security_effect_or_impact" | "control_state_or_missing_control" | "verification_or_observation"],
      "success_criteria": "...",
      "failure_criteria": "...",
      "allowed_tools": ["http_request", "code_search", ...],
      "priority": 1..5
    }
  ]
}

Rules:
- Never reference vulnerability names (SQLi, XSS, IDOR, RCE, SSRF, etc.) in any field.
- Do NOT emit fields named vuln_type / cwe / severity / finding_title; if you do,
  they will be stripped by the sanitizer and an audit event will be emitted.
- Each next_intent MUST cite at least one target_clue_refs (or, for
  scope_observation bootstrapping, an explicit scope handle).
- intent_type stays in the five-verb set; richer intent semantics live in
  `operation` and `intent_goal`.
- expected_clue_roles tells the Evidence Gate which roles this intent intends
  to fill on the ClueChain.
- If you have no high-value clue to advance, return an empty next_intents and
  explain in thought_summary.
- Output is a GraphDelta scoped to the current intent. Do NOT produce a global
  summary of all findings or a report draft.
```

实施细节：
- `IntentSuggestion` Go 结构体新增 `Operation string` / `IntentGoal string` /
  `ExpectedClueRoles []string` 三个字段（与 model_runtime / cairn_loop 同步）。
- `AIIntent.ConstraintsJSON` 在写入时把 `operation` / `intent_goal` /
  `expected_clue_roles` 一并落库；Reason / Tool 选择都可以读到。
- 模型若返回旧 schema（缺 operation/intent_goal），fallback 用空字符串，
  并在 audit 记 `agent.legacy_intent_schema_observed`。

#### Graph reasoner prompt（替代 `buildSecurityGraphPrompt`）

要求模型返回结构化字段（new_clue_facts / clue_chain_link / refuted_clue），
同样必须带 `operation` / `expected_clue_roles`，禁止漏洞类型词汇。所有输出
在落图前经过 sanitizer。

#### Deterministic fallback（修复 P6）

`deterministicIterationPlan` 改为：
- Reason 没有 clue 候选时，发 `scope_observation` Intent，operation =
  `expand_surface`，intent_goal = "采集授权范围内首层暴露面线索"。
- 有未链接的 `clue_observation` 时，发 `clue_chain_extend`，operation =
  `correlate_clues`，intent_goal = 描述需要链接的 from/to clue。
- 有 `clue_observation` 强信号但缺 verification 时，发 `clue_validate`，
  operation = `recheck_inconclusive`。
- 任何分支都不允许产出 vuln-type intent。

### Tool Observation Contract

工具层只能"建议"，不能"裁决"。

#### 输出 schema

```json
{
  "tool_run_id": 1001,
  "observations": [
    {
      "observation_type": "supporting | refuting | blocked | no_signal | error",
      "clue_kind": "runtime_behavior_clue",
      "summary": "...",
      "evidence_refs": [1, 2],
      "target_clue_refs": [],
      "suggested_roles": ["verification_or_observation"]
    }
  ]
}
```

字段说明：
- `observation_type`：观察性质。`refuting` / `blocked` / `no_signal` /
  `error` 都是合法且有价值的输出 —— Evidence Gate 决定是否升格为
  `clue_refuted` 节点 / `AINegativeFact`。
- `clue_kind`：工具对该观察的 clue 类型建议（描述性）。
- `summary`：人读摘要。
- `evidence_refs`：本 observation 关联的 `AIEvidence` ID（支持创建时回填）。
- `target_clue_refs`：本 observation 指向的已有 clue 节点 ID（如有）。
- `suggested_roles`：工具建议本 observation 可承担的 role（在 Clue Roles
  集合内取值）。

#### 工具不得输出的字段

- `vulnerability_type` / `cwe` / `severity` / `finding_title`；
- `capability_promote` 类直接指令；
- delivery proof 字段（`bash_poc` / `python_poc` / `propagation_path` /
  `sensitive_sink_or_behavior` 等）。

历史 ToolResult.Metadata 中带的 statusDiff / lengthDiff / markerFound 保留
作为 clue 强度的 hint，但**不**等同于 vulnerability classification，且
不参与 Capability gating。

#### Evidence Gate 处理流程

1. 读取 ToolRun + observations；
2. 对 supporting observation：升格为 `AIEvidence`，落 NodeType
   `clue_observation`，按 `suggested_roles` 写入 `roles` 字段；
3. 对 refuting / blocked / no_signal observation：写 `clue_refuted` 节点
   + `AINegativeFact`（含 `tested_path` / `effect`），加 `clue_refutes` 边
   到目标 clue；
4. 对 error observation：仅落 audit + `tool_error_clue`（不参与 chain
   评估），用于诊断与重跑判定；
5. 重新评估命中的 ClueChain，必要时降级 / 升级 Capability。

### Prompt / Output Sanitizer

LLM 仍可能产出漏洞类型语言、legacy vuln intent、报告式段落，必须在 Reason /
Explore 输出落图前过一遍 sanitizer。

#### 规则

输入：模型原始 JSON 输出（planner / graph reasoner / evidence intent /
report narrative 任何路径都走）。

1. **剥离 vuln-type 字段**：`vuln_type` / `cwe` / `severity` /
   `finding_title` / `vulnerability_type` 等键名（精确 + 大小写不敏感）从
   输出中删除，记 audit 事件 `agent.vuln_type_field_ignored`。
2. **legacy vuln intent normalize**：若 `next_intents[].intent_type` 命中
   legacy 列表（如 `sql_injection_validation`），调用 `NormalizeIntentType`
   转为 clue intent，并把原值放进 `constraints.legacy_hint`，audit
   `agent.legacy_intent_normalized`。
3. **report-style 段落降级**：若 `thought_summary` / `planned_action` /
   `objective` 中出现"报告式"模式（如"综上所述"、"本次任务发现的全部漏洞"、
   bullet list 化的 finding 草稿，启发式判定 + 关键词），仅保留为
   `diagnostics`，不进入 ClueChain；audit `agent.llm_output_sanitized`。
4. **缺字段兜底**：若模型不返回 `operation` / `intent_goal` /
   `expected_clue_roles` / `target_clue_refs`，使用空值兜底，并 audit
   `agent.legacy_intent_schema_observed`。
5. **过载截断**：clue 字段（`new_clue_facts` / `clue_chain_link` /
   `refuted_clue`）应用与 GraphSummary 相同的 cap（参考
   `truncateGraphFacts` 等），防止 prompt/response 失控。

#### Audit 事件清单

| 事件类型 | 何时触发 | 必要 metadata |
|---|---|---|
| `agent.vuln_type_field_ignored` | sanitizer 剥离 vuln-type 字段 | 字段名、原值（hash 或截断） |
| `agent.legacy_intent_normalized` | legacy intent type 被映射 | 原 type、新 type、legacy_hint |
| `agent.llm_output_sanitized` | report-style 段落降级 | 路径（thought_summary 等）、降级长度 |
| `agent.legacy_intent_schema_observed` | 缺 operation/intent_goal 等字段 | 缺失字段名 |
| `agent.clue_delta_ingested` | sanitizer 输出落图成功 | counts of new_clue_facts / clue_chain_link / refuted_clue |
| `agent.shouldfinalize_reason` | ShouldFinalize 决议 | reason ∈ {budget-exhausted, clue-coverage-sufficient, clue-plateau} |

#### 实施位置

- 新文件 `backend/internal/service/llm_sanitizer.go` 或并入
  `model_runtime_service.go` 末段；
- 所有 `parsePlannerOutput` / `parseSecurityGraphDecisionOutput` /
  `parseEvidenceIntentOutput` / `parseReportNarrativeOutput` 的调用方
  必须在解析后、落图前调用 sanitizer；
- Sanitizer 失败（exception）时按 deterministic fallback 兜底，不阻塞循环。


## Data Models

### 处理方式总览

| 处理 | 项 | 说明 |
|---|---|---|
| 新增 | NodeType: `clue_origin`, `clue_observation`, `clue_link`, `clue_refuted`, `clue_impact` | 复用 `AIBlackboardNode`，不新建表 |
| 新增 | EdgeType: `clue_supports`, `clue_refutes`, `clue_chains_to` | 复用 `AIBlackboardEdge` |
| 新增 | IntentType: `clue_collect`, `clue_validate`, `clue_refute`, `clue_chain_extend`, `scope_observation` | 通用动词 |
| 新增 | ClueRole 常量集合 | `origin_or_entry` / `trigger_or_control` / `reachability_or_relation` / `security_effect_or_impact` / `control_state_or_missing_control` / `verification_or_observation` |
| 新增 | `IntentSuggestion` 字段 | `Operation string` / `IntentGoal string` / `ExpectedClueRoles []string` |
| 新增 | `GraphDelta` 字段 | `NewClueFacts []ClueFact` / `ClueChainLinks []ClueChainLink` / `RefutedClues []ClueRefutation` |
| 新增 | `GraphRecentProgress` 字段 | `NewClueFactsLastN int` |
| 修改 | `AICapability.Strength` 语义 | 由"delivery proof 是否齐全"改为"ClueChain role coverage 是否闭合"；字段名不变 |
| 降级 | legacy IntentType（sql_injection_validation / idor_test 等） | 入图前由 `NormalizeIntentType` 映射成 clue_validate；原值进 `ConstraintsJSON.legacy_hint` |
| 降级 | `deliveryProofSummaryForCapability` | 函数保留，但仅 Delivery Layer 调用 |
| 降级 | `intentExpectedCapability` / `outcomeSupportsCapability` 中的漏洞类型分支 | 保留作为 clue 强度提示（hint），不再作为 Promotion 通过条件 |
| 废弃（在 Reason 路径上） | `AIContractCheckResult` 反向生成 Intent 的分支 | 仅记录 audit + Delivery 内部 diagnostic |
| 废弃（作为终止条件） | finding 数量、Contract 状态作为 ShouldFinalize 输入 | 全部移除 |

### Clue 在 blackboard 上的表达

| 概念 | 落到 NodeType | 关键字段约定（在 ContentJSON 中） |
|---|---|---|
| 原始线索 | `clue_origin` | `origin_kind`（scope / endpoint / artifact / fingerprint）、`roles`、`evidence_refs` |
| 观察线索 | `clue_observation` | `observation_signal`（differential / response_change / static_pattern / behavior_change）、`roles`、`evidence_refs`、`source_intent_id` |
| 链接节点 | `clue_link` | `link_kind`（reachability / control_flow / authorization / data_flow / behavior_correlation）、`roles`、`from_clue`、`to_clue` |
| 被否定线索 | `clue_refuted` | `refute_reason`、`disproved_by_evidence` |
| 影响线索 | `clue_impact` | `impact_kind`（free-form 文本，不是漏洞枚举）、`roles`、`affected_target` |

兼容性：旧的 `fact` / `surface_fact` / `code_fact` / `business_fact` / `secret_fact` /
`negative_fact` / `hypothesis` / `capability` 等 NodeType **保留可读**。在 GraphSummary
构建期间通过映射函数视作 `clue_*` 等价物。

### Clue Roles and Closure Semantics

#### 概念区分

- **Clue kind** = 线索的种类（信息属性）。例如 `entrypoint_clue`、
  `runtime_behavior_clue`、`auth_state_clue`、`code_path_clue`、
  `data_relation_clue`、`fingerprint_clue`、`config_clue`。
  - Clue kind 是描述性的、可以无限扩展，不参与 gating。
- **Clue role** = 该线索在"安全影响链"中扮演的作用。
  - 一个 Clue 可以同时承担多个 role；一个 role 可以由多个 Clue 共同承担。
  - role 是 gating 的对象。

#### Required Clue Roles（用于 Capability Gate）

| Role | 含义 | 典型证据来源 |
|---|---|---|
| `origin_or_entry` | 入口 / 暴露面 / 起始线索 | 路由清单、URL、API endpoint、可读文件路径、暴露端口 |
| `trigger_or_control` | 可控触发 / 输入 / 状态 / 身份 / 条件线索 | 请求参数、可控字段、cookie/session、上传内容、配置开关 |
| `reachability_or_relation` | 调用关系 / 数据关系 / 控制流 / 行为关联 | call graph / data flow 观察、HTTP 链路、跨模块引用 |
| `security_effect_or_impact` | 安全影响行为 / 影响对象 / 敏感操作 | 数据库写入、文件落地、命令执行、对象越权访问、敏感数据暴露 |
| `control_state_or_missing_control` | 控制存在 / 控制不足 / 控制缺失 / 控制被绕开 / 控制不适用 | 鉴权检查的存在/缺失、ownership check、过滤函数命中/绕过 |
| `verification_or_observation` | 静态强证据、运行行为、响应差异、工具观察、复查路径 | code slice、HTTP response diff、sandbox 输出、marker 命中、回放可复现 |

> 这些是 clue roles，不是漏洞模板。它们可以被不同 clue kind 满足，**不**要求
> 所有问题都套传统 source / sink。

#### 节点表达约定

`AIBlackboardNode` 的 `ContentJSON` 中保留 `roles` 数组字段：

```json
{
  "clue_id": "clue_001",
  "kind": "entrypoint_clue",
  "roles": ["origin_or_entry"],
  "summary": "GET /documents/:id exposes object access by id",
  "evidence_refs": [101]
}
```

#### Closure Semantics（ClueChain 闭合）

ClueChain 闭合 ⇔ 满足全部以下条件：
1. `requiredClueRoles` 全部出现在 chain 节点的 `roles` 并集中；
2. 每个 role 至少有一条 evidence ref（来自 supporting observation 升格的 `AIEvidence`）；
3. chain 上所有节点 `Status == active`，无 `archived` / `suppressed`；
4. 没有 active `AINegativeFact` 直接反驳本 chain。

`Strength` 三档：
- `verified`  = 上面四条全部满足。
- `observed`  = roles 部分覆盖且有 supporting evidence，但缺 verification 或 control_state。
- `suspected` = 仅 origin / 部分 link，缺 evidence 或 impact。

#### 与旧 NodeType 的角色映射（read-time）

| Legacy NodeType | Default Roles |
|---|---|
| `surface_fact` / `fact` | `origin_or_entry`（若 title 含 endpoint/URL/path）；否则 `reachability_or_relation` |
| `code_fact` | `reachability_or_relation`（含 source/sink/path 字样时也覆盖 `trigger_or_control` 或 `security_effect_or_impact`） |
| `business_fact` | `security_effect_or_impact` |
| `secret_fact` / `credential_fact` | `security_effect_or_impact` |
| `technology_fingerprint` | `verification_or_observation`（弱证据） |
| `hypothesis` | `reachability_or_relation`（link_kind=hypothesis_legacy） |
| `negative_fact` | 不参与正向覆盖；进入 `ActiveRefutationsAgainst` |

映射不修改 DB 中的 NodeType 字段，仅在 ClueChain 评估读图时使用。

### GraphDelta 结构化字段

```go
type GraphDelta struct {
    // existing (保留，降级为 observation-only)
    NewFacts                []GraphFact
    UpdatedFacts            []GraphFact
    NewIntents              []IntentSuggestion
    CompletedIntents        []uint
    NewEvidence             []model.AIEvidence
    NewNegativeFacts        []GraphFact
    NewCapabilityCandidates []CapabilityDraft
    VerifiedCapabilities    []CapabilityDraft
    UpdatedCoverage         []CoverageUpdate
    GoalStateUpdate         map[string]any
    Diagnostics             []string
    Errors                  []string

    // 新增（保留结构化 clue）
    NewClueFacts            []ClueFact         `json:"new_clue_facts"`
    ClueChainLinks          []ClueChainLink    `json:"clue_chain_link"`
    RefutedClues            []ClueRefutation   `json:"refuted_clue"`
}

type ClueFact struct {
    NodeKind     string         `json:"node_kind"`     // clue_origin / clue_observation / clue_impact
    Title        string         `json:"title"`
    Summary      string         `json:"summary"`
    Signal       string         `json:"observation_signal,omitempty"`
    Roles        []string       `json:"roles,omitempty"`
    EvidenceIDs  []uint         `json:"evidence_ids,omitempty"`
    SourceIntent uint           `json:"source_intent_id,omitempty"`
    Extra        map[string]any `json:"extra,omitempty"`
}

type ClueChainLink struct {
    FromCluePath string         `json:"from_clue"`
    ToCluePath   string         `json:"to_clue"`
    LinkKind     string         `json:"link_kind"`     // reachability / control_flow / authorization / data_flow / behavior_correlation
    Roles        []string       `json:"roles,omitempty"`
    EvidenceIDs  []uint         `json:"evidence_ids,omitempty"`
    Extra        map[string]any `json:"extra,omitempty"`
}

type ClueRefutation struct {
    TargetCluePath string `json:"target_clue"`
    Reason         string `json:"refute_reason"`
    EvidenceIDs    []uint `json:"evidence_ids,omitempty"`
}
```

### Legacy Intent 降级映射表

| Legacy IntentType | Mapped IntentType | 备注 |
|---|---|---|
| `sql_injection_validation` | `clue_validate` | constraints 中保留 `legacy_hint=sql_injection` |
| `idor_test` | `clue_validate` | constraints 保留 `legacy_hint=cross_user_object_access` |
| `xss_test`, `ssrf_test`, `rce_test`, `lfi_test`, `xxe_test` | `clue_validate` | 同上 |
| `recon`, `fingerprint` | `scope_observation` | hint 保留 |
| `code_trace`, `dataflow_trace`, `inspect_auth_boundary`, `inspect_owner_check` | `clue_chain_extend` | hint 保留 |
| `validate_candidate_path` | `clue_validate` | |
| `collect_evidence` | `clue_collect` | 直译 |
| `validate` | `clue_validate` | 直译 |

实现位置：新增 `backend/internal/model/intent_alias.go`（纯函数
`NormalizeIntentType(legacy string) (modern string, hint string)`），所有写
`AIIntent` 的入口必须经过这个函数。Audit 事件类型：
`agent.legacy_intent_normalized`。

### Legacy NodeType 映射（read-time）

`GraphSummary` / `ClueChain` 评估器读图时，按 Clue Roles 章节的映射表把旧
NodeType 视作 clue。读出后写回时**不修改 NodeType**，保持兼容；新写入一律用
`clue_*`。

## Correctness Properties

1. **ClueChain 闭合单调性**：向 chain 补充 supporting evidence 或新 clue 节点
   后，闭合状态不会退化（verified 不会变回 observed/suspected）。
2. **ShouldFinalize 可重入性**：同一 (coverage, progress, budget) 多次调用
   结果一致。
3. **NormalizeIntentType 幂等性**：任意 legacy 输入经过 NormalizeIntentType
   两次结果与一次相同。
4. **Sanitizer 不丢有效 clue**：sanitizer 只剥离 vuln-type / report-style
   字段，不丢弃 new_clue_facts / clue_chain_link / refuted_clue 中的有效条目。
5. **Layer 隔离不变量**：Delivery Layer 的任何函数调用不会导致 `AIIntent` /
   `AIBlackboardNode` / `AIBlackboardEdge` / `AICapability` 的 INSERT 或
   UPDATE（Capability promotion 来源是 Evidence Gate，不是 Delivery）。
6. **Backward compatibility**：旧 NodeType / IntentType 的任务能继续读出 +
   完成生命周期，不会因为映射函数抛错而中断。

## Error Handling

- **Sanitizer 失败**：按 deterministic fallback 兜底，不阻塞循环；audit
  `agent.sanitizer_error`。
- **ClueChain 评估异常**（DB 读取失败、节点不存在）：返回 `Allowed=false,
  Strength="suspected"`，不 promote；audit `agent.clue_chain_eval_error`。
- **模型不可用**：走 deterministic fallback（已改为 clue-driven），不产出
  vuln-type intent。
- **Feature flag 冲突**（phase flag 与逃生 flag 矛盾）：逃生 flag 优先生效。
- **旧任务读图映射失败**：映射函数对未知 NodeType / IntentType 返回
  `clue_observation` / `clue_collect` 兜底，不 panic。

## Testing Strategy

### 单元测试

- `EvaluateClueChain` 闭合判定（origin/link/impact/evidence 缺失各组合）
- `ShouldFinalize` 三类分支（含 SurfaceCount=0 plateau fallback）
- `NormalizeIntentType` 全表映射 + 未知值兜底
- `GraphDelta` 结构化字段优先级合并
- Sanitizer 各规则（vuln-type 剥离、legacy intent normalize、report-style
  降级、缺字段兜底）
- ClueChain 闭合单调性 property test
- ShouldFinalize 可重入性 property test
- NormalizeIntentType 幂等性 property test

### 集成测试

- 跑完一个 code_audit 任务（不含外部 vuln 模板），验证：
  1. 没有 IntentType 落到 vuln-type；
  2. Capability 产出仅当 ClueChain 闭合；
  3. Report 仍可生成。
- 跑完一个 pentest 任务（同上）。
- 模型不可用场景：deterministic fallback 也只产 clue-driven Intent。

### 回归测试

- `graph_search_fixture_e2e_test.go` 不变绿化。
- `coverage_goalstate_test.go` 在 Phase 2 之后调整断言。
- 现有 smoke `scripts/smoke-first-stage.sh` 跑通（必要时加 flag 控制）。

## Migration Plan

每个 phase 独立 PR，可独立 ship，可独立回滚。

### Phase 0 · 类型扩展（仅常量与映射，不改行为）
- 新增 NodeType / EdgeType / IntentType / ClueRole 常量到 `model/constants.go`。
- 新增 `NormalizeIntentType` + 老→新映射表，但**不强制启用**（feature flag
  默认关闭）。
- 新增 `GraphRecentProgress.NewClueFactsLastN` 字段，新增 `GraphDelta`
  结构化 clue 字段；旧 worker 不返回这些字段时为空数组，行为不变。
- 新增统一阶段 flag `RABBIT_CLUE_DRIVEN_PHASE=0|1|2|3|4`（默认 0）。
- 回滚：直接 revert，无 DB schema 变更。

### Phase 1 · ClueChainService + Capability Gate 切换（修复 P4）
- 新增 `clue_chain_service.go`，实现 EvidenceGate 接口。
- `AgentOrchestrator.PromoteCapabilitiesToFindings` 与
  `cairn_loop.go::CapabilityPromotionGate` 切换为 role-coverage 评估。
- `deliveryProofSummaryForCapability` 在 Promotion 路径上的所有调用迁出，
  改由 Delivery Layer 在写 Finding 时调用。
- 兼容窗口：独立逃生开关 `RABBIT_PROMOTION_GATE=clue_chain|legacy`，
  默认 `clue_chain`，紧急回滚切 `legacy`。
- 回归测试：`coverage_goalstate_test.go` / `recentering_regression_test.go` /
  `hypothesis_lifecycle_service_test.go` 必须仍绿。

### Phase 2 · ShouldFinalize plateau fallback（修复 P1）+ GraphDelta 结构化合并（修复 P2）
- `cairn_loop.go::BuildCoverageGoalState` 接入新判定式。
- Worker 合并代码按结构化字段优先。
- Audit 事件：`agent.shouldfinalize_reason` / `agent.clue_delta_ingested`。
- 兼容窗口：`RABBIT_FINALIZE_FALLBACK=clue|legacy`。

### Phase 3 · Legacy vuln intent 降级（修复 P3）+ Prompt 改造（修复 P5、P6）+ Sanitizer
- 启用 `NormalizeIntentType`：所有 `AIIntent` 写入路径强制经过映射。
- 重写 `buildPlannerPrompt` / `buildSecurityGraphPrompt` 为 clue-driven 骨架。
- Deterministic fallback 改为 clue-driven。
- 上线 sanitizer。
- 回滚：phase flag 退回 ≤2 即恢复旧行为。

### Phase 4 · Delivery Layer 完全隔离
- 移除 `ContractService` 中"Contract incomplete → 生成补证据 Intent"分支，
  改为只发 audit 与 Delivery 内部 diagnostic。
- 引入 `DeliveryLayer` 接口，`AgentOrchestrator` 只在 finalize 阶段调一次
  `Delivery.GenerateArtifacts`。
- 兼容窗口：`RABBIT_DELIVERY_WRITEBACK=off|on`，默认 off。

### Phase 兼容性窗口
- Phase 0–2 同时上线时，旧任务仍按旧 NodeType / IntentType 跑完。
- Phase 3 上线后，新任务一律用新 IntentType；旧 pending 任务在下次 reload 时
  被 NormalizeIntentType 透明转换。
- Phase 4 上线后，Delivery 写回路径彻底关闭。
- Phase flag 与逃生 flag 的组合矩阵在排障时优先生效逃生 flag（细粒度优先）。

## Risks and Mitigations

| 风险 | 影响 | Mitigation |
|---|---|---|
| LLM 模型仍输出漏洞类型语言 | Reason 路径污染 | Prompt 显式禁止 + sanitizer 剥离 + audit |
| 旧任务读图断裂 | 用户在跑的任务挂掉 | NodeType / IntentType 全部走映射，不改 DB schema；映射函数有 unit test 兜底 |
| ClueChain 闭合判定过严，没有 Capability 产出 | 没有 Finding | Phase 1 上线时附 `clue_chain_relaxed` flag，允许只要 origin+evidence+impact 就闭合；同时 audit 警告 missing-link |
| Delivery Layer 写回路径被遗漏 | Reason 仍被反向污染 | grep 所有调用方写白名单；Phase 4 加 CI lint 检查 |
| Deterministic fallback 仍生成 vuln-type intent | 模型不可用时回到旧路径 | Phase 3 改写 fallback；测试覆盖"task without modelConfig"场景 |
| 模型 prompt 压缩超额（>6000 字符） | 524 超时复发 | 沿用 `truncateGraphFacts` 等现有截断；新 GraphDelta clue 字段也加 cap 限制 |

## Resolved Decisions

> 来自 design review 反馈第 6/7/8/9 条。

1. **Capability Strength 保留三档**，语义改为 ClueChain role coverage 完整度：
   - `suspected` = 有线索但 ClueChain role coverage 不全或 evidence 缺失。
   - `observed`  = 有工具/代码/运行观察支撑，但仍缺关键 relation /
     control_state / verification。
   - `verified`  = required clue roles 全部覆盖，每 role 有 evidence 支撑，
     且无 active NegativeFact 反驳。
2. **NodeType 兼容策略**：不做 DB 一次性迁移。采用 read-time normalization
   + new-write `clue_*`。
3. **Contract incomplete 反向生成补证据 Intent 路径移除**：Contract 仅在
   Delivery Layer 内部记录 diagnostic / audit；真正的补证据需求由 Evidence
   Gate 在判定 ClueChain role 缺失时 spawn Intent。
4. **Feature flag 同时使用阶段 flag 与逃生 flag**：
   - 阶段 flag：`RABBIT_CLUE_DRIVEN_PHASE=0|1|2|3|4`。
   - 逃生 flag：`RABBIT_PROMOTION_GATE` / `RABBIT_FINALIZE_FALLBACK` /
     `RABBIT_DELIVERY_WRITEBACK`。
   - 排障时逃生 flag 优先生效。

## 现有代码影响清单

> Tasks 阶段会把每条转成一个具体任务。

- `backend/internal/model/constants.go` — 加 NodeType / EdgeType / IntentType / ClueRole 常量。
- `backend/internal/model/intent_alias.go`（新增）— `NormalizeIntentType`。
- `backend/internal/service/cairn_loop.go` — `BuildCoverageGoalState` / `GraphRecentProgress` / `GraphDelta` / `CapabilityPromotionGate` / `PromoteCapabilitiesToFindings` / GraphSummary 构建。
- `backend/internal/service/agent_orchestrator.go` — `runLoopIterations` / `runReasonPhase` / `ingestPlannerNextIntents` / `supportingEvidenceForIntent` / `deliveryProofSummaryForCapability`（迁出 Promotion 路径） / `outcomeSupportsCapability`（降级为 hint） / `intentExpectedCapability`（降级） / `isPentestRuntimeIntent`（降级） / `isCodeAuditRuntimeIntent`（降级）。
- `backend/internal/service/blackboard_service.go` — UpsertNode 接受新 NodeType；Edge 接受新 EdgeType。
- `backend/internal/service/clue_chain_service.go`（新增）。
- `backend/internal/service/llm_sanitizer.go`（新增）。
- `backend/internal/service/model_runtime_service.go` — `buildPlannerPrompt` / `buildSecurityGraphPrompt` / `deterministicIterationPlan` / `deterministicEvidenceIntent` / output sanitizer 调用。
- `backend/internal/service/contract_service.go` — 移除"Contract incomplete → 反向 Intent"分支。
- `backend/internal/service/finding_service.go` / `report_service.go` — 调用 `deliveryProofSummaryForCapability` 的合法位置（Delivery 内部）。
- `backend/internal/service/dynamic_intent_expander_service.go` / `state_expansion_planner_service.go` — Intent 类型走 NormalizeIntentType。
- `backend/internal/tools/*` — 不动实现，只校验 ToolResult metadata 是否仍含漏洞分类字段；如有，加 deprecation note。
- 测试文件：`cairn_loop_test.go`、`coverage_goalstate_test.go`、`hypothesis_lifecycle_service_test.go`、`recentering_regression_test.go`、`graph_search_fixture_e2e_test.go`、`graph_search_worker_test.go`、`dynamic_intent_expander_service_test.go`、`state_expansion_planner_service_test.go`、`exploration_budget_manager_service_test.go`、`worker_driver_service_test.go`。

## 下一步

design.md 落地完成（含 design review 反馈第 1–14 条修正）。**等待你确认**进入：

1. `requirements.md`：按 EARS 风格写硬性要求，至少覆盖：
   Layer separation / Clue model / Clue roles / GraphDelta structured clue
   preservation / Legacy intent normalization / Evidence Gate role coverage /
   Delivery writeback isolation / ShouldFinalize clue-based stop condition /
   Tool observation contract / Prompt-output sanitizer / Deterministic fallback /
   Property-based correctness / Backward compatibility / Feature flag
   controllability。
2. `tasks.md`：按 Phase 0–4 拆解，每个任务必须能落到具体文件 + 测试。

我不会未经确认就动代码，也不会未经确认就写 requirements/tasks。
