# Worker Graph Search Diagnosis

## 1. 当前执行链路

当前链路已经不是单纯报告生成器。`TaskService` 创建任务与初始黑板节点，`AgentOrchestrator.Run` 创建 `AIAgentLoop`，随后 `runLoopIterations` 以 Cairn-style 循环运行：选择 pending `AIIntent`，构造 `AgentContext`，调用模型规划或外部 Worker，执行 Runner/Tool，写入 `AIEvidence`、`AIBlackboardNode`、`AINegativeFact`、`AICapability`，最后由 `CairnLoop.PromoteCapabilitiesToFindings` 将合格能力提升为 `AIFinding`。

主要代码入口：

- `backend/internal/service/agent_orchestrator.go`
- `backend/internal/service/cairn_loop.go`
- `backend/internal/service/worker_driver_service.go`
- `backend/internal/service/blackboard_service.go`
- `backend/internal/service/evidence_service.go`
- `backend/internal/service/finding_service.go`

## 2. 当前核心概念覆盖情况

项目已有多数相近概念：

- Goal：`AISecurityTask.Objective` 和 `AIGoalProfile`
- Fact：`AIBlackboardNode`，其中 `node_type` 覆盖 `code_fact`、`behavior_fact`、`surface_fact` 等
- Intent：`AIIntent`
- Hint：目前主要以 `AIBlackboardNode{node_type: "hint"}` 表达
- Evidence：`AIEvidence`
- NegativeFact：`AINegativeFact` 和黑板 `negative_fact` 节点
- Capability：`AICapability`
- Finding：`AIFinding`

现有结构可以复用，不需要新建一套孤立模型。

## 3. 当前 Worker 输入

外部 Worker 输入来自 `writePiWorkerRuntimeSnapshot` 和 `buildPiContainerWorkerPrompt`。输入包含任务、当前 Intent、`AgentContext`、安全策略、Worker 配置、运行时工具和阶段边界。

问题是输入仍偏混合：`AgentContext` 包含 `OpenFindings`，而提示词要求 Worker 不能以 Finding 作为探索入口；图状态摘要也不够接近 `Goal / confirmed_facts / open_intents / recent_evidence / negative_facts / capabilities / unknowns / hints / budget_state` 这种结构化 GraphSummary。

## 4. 当前 Worker 输出

外部 Worker 输出已经要求 JSON，不是纯自然语言。当前结构是：

```json
{
  "accepted": true,
  "data": {
    "summary": "",
    "facts": [],
    "evidence": [],
    "capability_candidates": [],
    "negative_facts": [],
    "unverified_risks": [],
    "next_intent_suggestions": []
  }
}
```

这与 GraphDelta 接近，但命名上还不是明确的 `GraphDelta`，也缺少 `completed_intents`、`verified_capabilities`、`diagnostics`、`errors` 等统一字段。

## 5. GraphSummary / Blackboard

项目已有 Blackboard：`AIBlackboardNode`、`AIBlackboardEdge`、`BlackboardService`。`CairnLoop.BuildGraphSummary` 已经能给 Reason 阶段生成压缩摘要，但当前摘要偏字符串列表，缺少事实、证据、能力、负面事实、预算状态之间的结构化关系。

## 6. Intent 是否动态生成

Intent 已经可以动态生成：

- `runReasonPhase` 通过 `reasonOverSecurityGraph` 生成下一批 intent
- `ingestPlannerNextIntents` 将模型 planner 输出转成 intent
- `ingestWorkerGraphOutput` 将 Worker 的 `next_intent_suggestions` 转成 intent
- `HypothesisLifecycleService` 从 Evidence 和 Capability 扩展验证 intent

问题是 `intent_types.go` 仍保留大量以漏洞类型命名的 intent，例如 `sqli_probe`、`idor_probe`、`path_traversal_probe`。这些可以保留兼容，但核心探索入口应优先使用通用 intent kind，例如 `inspect_dataflow`、`inspect_guard`、`validate_hypothesis`、`resolve_unknown`。

## 7. 失败路径

失败路径已有沉淀能力：`AINegativeFact`、`AIUnverifiedRisk`、`writeTestedPathFact` 和 `supportingEvidenceForIntent` 会将无效验证、阻塞和不可观测结果写回图。

不足是 GraphSummary 对 NegativeFact 的结构化暴露不足，Worker 和 Reason 阶段容易只看到字符串摘要，不容易基于 `effect / tested_path / evidence_refs` 避免重复探索。

## 8. Evidence 状态推动

Evidence 当前会进入 `AIEvidence`，并被写成黑板 `evidence` 节点，再通过 `supports_fact` 等边关联到事实。`WriteCapability` 和 `PromoteCapabilitiesToFindings` 也要求 capability 带 evidence refs。

不足是 promotion gate 分散在多个函数中：`WriteCapability`、`workerCapabilityCandidateIsVerified`、`deliveryDetailsForCapability`、`deliveryDetailsComplete`。需要一个显式的 Evidence-first gate，防止 Worker 或漏洞标签直接触发 Finding。

## 9. Finding 是否可能早于 Verified Capability

主链路中 `PromoteCapabilitiesToFindings` 只查询 `strength = verified` 且 `can_advance_goal = true` 的 capability，这一点是正确的。`FindingService.CreateCandidate` 仍是公开 service 方法，测试和其他代码可以直接调用；需要明确将它视为 delivery 层 API，主循环只允许通过 verified capability promotion 调用。

## 10. 简单漏洞发现失败的直接原因

主要原因不是没有表，而是搜索策略和 Worker 契约仍不够“事实图优先”：

- Worker 输入缺少强结构化 GraphSummary。
- Worker 输出虽然结构化，但没有统一命名为 GraphDelta。
- Reason / Planner 仍容易受漏洞类型 intent 牵引。
- 部分验证逻辑仍存在 SQLi 特化判断。
- NegativeFact 暴露不够结构化，可能导致重复走死路。
- Evidence-first promotion 条件没有集中表达，难以审计。

## 11. 最小改造路径

1. 保留现有数据库模型，补齐 GraphSummary 结构化字段。
2. 增加 GraphDelta 类型，并让 Worker 输出兼容 `graph_delta`。
3. 增加通用 Cairn-style intent kind，保留旧漏洞类型 intent 作为兼容标签。
4. 将 Worker snapshot 和 prompt 明确改为 GraphSummary + GraphDelta。
5. 增加 Evidence-first promotion gate，并在 Finding promotion 前调用。
6. 让 NegativeFact 在 GraphSummary 中带 tested path、effect、evidence refs。
7. 增加针对 Bootstrap、Reason、Explore、NegativeFact、Capability promotion、Finding promotion 的单元测试。
