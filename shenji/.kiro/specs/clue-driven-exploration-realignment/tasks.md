# Clue-Driven Exploration Realignment — Tasks

> 按 Phase 0–4 拆解。每个任务包含：修改文件、修改目标、不允许做什么、对应测试、回滚/runtime toggle 影响。
> 所有任务完成后系统从 vulnerability/finding/report-driven 回正为 clue-driven。
> 不要在未经用户确认前开始代码实现。

---

## Task Dependency Graph

```
Phase 0: T0.1 → T0.2 → T0.3 → T0.4
Phase 1: T0.4 → T1.1 → T1.2 → T1.3
Phase 2: T1.3 → T2.1 → T2.2
Phase 3: T2.2 → T3.1 → T3.2 → T3.3 → T3.4
Phase 4: T3.4 → T4.1 → T4.2 → T4.3
```

---

## Phase 0 · 类型扩展（仅常量与映射，不改行为）

### Task 0.1: 新增 NodeType / EdgeType / IntentType / ClueRole 常量

- [ ] **修改文件**: `backend/internal/model/constants.go`
- **修改目标**:
  - 新增 NodeType 常量: `NodeClueOrigin`, `NodeClueObservation`, `NodeClueLink`, `NodeClueRefuted`, `NodeClueImpact`, `NodeToolErrorClue`
  - 新增 EdgeType 常量: `EdgeClueSupports`, `EdgeClueRefutes`, `EdgeClueChainsTo`
  - 新增 IntentType 常量: `IntentClueCollect`, `IntentClueValidate`, `IntentClueRefute`, `IntentClueChainExtend`, `IntentScopeObservation`
  - 新增 ClueRole 常量: `RoleOriginOrEntry`, `RoleTriggerOrControl`, `RoleReachabilityOrRelation`, `RoleSecurityEffectOrImpact`, `RoleControlStateOrMissingControl`, `RoleVerificationOrObservation`
  - 新增 `RequiredClueRoles []string` 变量（包含全部 6 个 role）
- **不允许做什么**: 不修改任何现有常量值；不删除任何现有常量；不改变任何运行时行为
- **对应测试**: 编译通过即可；新增 `constants_test.go` 断言 `RequiredClueRoles` 长度为 6
- **回滚/toggle**: 直接 revert commit，无 DB 变更，无 toggle 依赖

### Task 0.2: 新增 NormalizeIntentType 映射函数

- [ ] **修改文件**: `backend/internal/model/intent_alias.go`（新增文件）
- **修改目标**:
  - 实现 `NormalizeIntentType(legacy string) (modern string, hint string)` 纯函数
  - 包含 design.md 中定义的完整映射表（sql_injection_validation → clue_validate 等）
  - 未知 IntentType 映射到 `clue_collect`，hint 为原值
  - 函数必须幂等
- **不允许做什么**: 不在本任务中启用（不修改任何写入路径调用此函数）；不引入 DB 变更
- **对应测试**: `backend/internal/model/intent_alias_test.go`（新增）
  - 全表映射正确性
  - 幂等性: `NormalizeIntentType(NormalizeIntentType(x)) == NormalizeIntentType(x)`
  - 未知值兜底
  - Property-based: 随机字符串输入不 panic
- **回滚/toggle**: 直接 revert，函数未被调用无副作用

### Task 0.3: GraphDelta 结构化 clue 字段扩展

- [ ] **修改文件**: `backend/internal/service/cairn_loop.go`
- **修改目标**:
  - 在 `GraphDelta` struct 中新增字段: `NewClueFacts []ClueFact`, `ClueChainLinks []ClueChainLink`, `RefutedClues []ClueRefutation`
  - 新增 `ClueFact` / `ClueChainLink` / `ClueRefutation` struct 定义（含 `Roles []string` 字段）
  - 在 `GraphRecentProgress` 中新增 `NewClueFactsLastN int` 字段
  - 在 `IntentSuggestion` struct 中新增 `Operation string` / `IntentGoal string` / `ExpectedClueRoles []string`
- **不允许做什么**: 不修改任何现有字段的语义；不修改合并逻辑（Phase 2 做）；不删除旧字段
- **对应测试**: 编译通过；新增 `cairn_loop_clue_types_test.go` 断言 JSON 序列化/反序列化 round-trip
- **回滚/toggle**: 直接 revert，新字段为空数组时行为不变

### Task 0.4: Runtime Toggle 基础设施

- [ ] **修改文件**: `backend/internal/config/config.go`
- **修改目标**:
  - 新增 Config 字段: `ClueDrivenPhase int`（env `RABBIT_CLUE_DRIVEN_PHASE`，默认 0）
  - 新增 Config 字段: `PromotionGate string`（env `RABBIT_PROMOTION_GATE`，默认 `"clue_chain"`）
  - 新增 Config 字段: `FinalizeMode string`（env `RABBIT_FINALIZE_FALLBACK`，默认 `"clue"`）
  - 新增 Config 字段: `DeliveryWriteback string`（env `RABBIT_DELIVERY_WRITEBACK`，默认 `"off"`）
  - 启动时 log 输出当前 toggle 配置
- **不允许做什么**: 不在本任务中使用这些 toggle 做分支判断（Phase 1+ 做）
- **对应测试**: `backend/internal/config/config_test.go` 新增用例验证 env 解析与默认值
- **回滚/toggle**: 直接 revert

---

## Phase 1 · ClueChainService + Capability Gate 切换（修复 P4）

### Task 1.1: 新增 ClueChainService

- [ ] **修改文件**: `backend/internal/service/clue_chain_service.go`（新增文件）
- **修改目标**:
  - 实现 `EvidenceGate` 接口（design.md Components 章节定义）
  - 核心方法: `EvaluateChain(ctx, chainID) ClueChainEval`
    - 加载 chain 上所有 clue 节点
    - 计算 RoleCoverage（含 legacy NodeType 映射）
    - 计算 RoleEvidence
    - 检查 ActiveRefutationsAgainst
    - 返回 Allowed / Strength / Missing
  - 辅助方法: `PromoteObservation`, `LinkClues`, `Refute`, `PromoteCapability`
  - 内部复用 `BlackboardService` / `EvidenceService`，不引入新表
- **不允许做什么**: 不修改现有 `CapabilityPromotionGate` 逻辑（Task 1.2 做）；不调用 FindingService / ReportService
- **对应测试**: `backend/internal/service/clue_chain_service_test.go`（新增）
  - 全 role 覆盖 → verified
  - 缺 1 role → observed 或 suspected
  - 有 NegativeFact 反驳 → 不 promote
  - 单调性 property: 加 evidence 后 Strength 不降
  - Legacy NodeType 映射正确
- **回滚/toggle**: `RABBIT_PROMOTION_GATE=legacy` 时不调用此 service

### Task 1.2: Capability Gate 切换

- [ ] **修改文件**: `backend/internal/service/agent_orchestrator.go`, `backend/internal/service/cairn_loop.go`
- **修改目标**:
  - 在 `PromoteCapabilitiesToFindings` / Promotion 路径中：
    - 当 `cfg.PromotionGate == "clue_chain"` 时，调用 `ClueChainService.EvaluateChain`
    - 当 `cfg.PromotionGate == "legacy"` 时，保留旧逻辑
  - 移除 Promotion 路径对 `deliveryProofSummaryForCapability` 的调用（该函数保留，但只在 Delivery 调用）
  - `outcomeSupportsCapability` / `intentExpectedCapability` 降级为 hint（不再作为 gate 条件）
- **不允许做什么**: 不删除 `deliveryProofSummaryForCapability` 函数本身；不修改 Delivery Layer 的调用路径
- **对应测试**:
  - 修改 `cairn_loop_test.go` / `coverage_goalstate_test.go` 验证新 gate
  - 新增测试: toggle=legacy 时旧行为不变
  - 回归: `recentering_regression_test.go` / `hypothesis_lifecycle_service_test.go` 仍绿
- **回滚/toggle**: `RABBIT_PROMOTION_GATE=legacy` 即回滚

### Task 1.3: Delivery Layer 调用 deliveryProofSummary 迁移

- [ ] **修改文件**: `backend/internal/service/finding_service.go`, `backend/internal/service/report_service.go`, `backend/internal/service/agent_orchestrator.go`
- **修改目标**:
  - 最终目标：`agent_orchestrator.go` / `cairn_loop.go` 不直接依赖 `deliveryProofSummaryForCapability`
  - 确保 `deliveryProofSummaryForCapability` 仅在 `FindingService.BuildFindingFromCapability` 和 `ReportService.Generate` 中被调用
  - 在 `agent_orchestrator.go` 中 Promotion 路径的调用点：
    - 当 `cfg.PromotionGate == "clue_chain"` 时，完全跳过（不调用）
    - 当 `cfg.PromotionGate == "legacy"` 时，短期保留并加 `// TODO(phase4): remove legacy promotion proof path` 注释
  - legacy 分支仅作为逃生通道，不作为长期设计
- **不允许做什么**: 不改变 Finding / Report 的最终输出格式（Delivery 内部仍可用 delivery proof 字段）；不删除函数本身
- **对应测试**: 集成测试验证 Report 仍能正常生成（含 rich detail）；验证 toggle=clue_chain 时 Promotion 路径不调用 deliveryProofSummary
- **回滚/toggle**: `RABBIT_PROMOTION_GATE=legacy` 恢复旧调用路径

---

## Phase 2 · ShouldFinalize plateau fallback（修复 P1）+ GraphDelta 结构化合并（修复 P2）

### Task 2.1: ShouldFinalize clue-plateau fallback

- [ ] **修改文件**: `backend/internal/service/cairn_loop.go`
- **修改目标**:
  - 修改 `BuildCoverageGoalState` / `ShouldFinalizeWithNoProgressLimit`：
    - 当 `cfg.FinalizeMode == "clue"` 时，使用新判定式（design.md Architecture §ShouldFinalize）
    - 新增 `NewClueFactsLastN` 计算逻辑（在 `recentCoverageProgress` 中）
    - 三类终止: budget-exhausted / clue-coverage-sufficient / clue-plateau
    - `SurfaceCount == 0` 不再直接判 plateau，改用 clue-progress 综合判定
    - 终止时 emit audit `agent.shouldfinalize_reason`
  - 当 `cfg.FinalizeMode == "legacy"` 时，保留旧逻辑
- **不允许做什么**: 不读 finding 数量 / contract 状态作为终止输入；不修改 Promotion 逻辑
- **对应测试**:
  - 修改 `coverage_goalstate_test.go`: 新增 SurfaceCount=0 + 有 clue progress → 不终止
  - 新增 SurfaceCount=0 + 无 progress + 无 pending → clue-plateau 终止
  - 可重入性 property: 同输入多次调用结果一致
  - 回归: `graph_search_worker_test.go` 仍绿
- **回滚/toggle**: `RABBIT_FINALIZE_FALLBACK=legacy` 即回滚

### Task 2.2: GraphDelta 结构化 clue 合并

- [ ] **修改文件**: `backend/internal/service/cairn_loop.go`, `backend/internal/service/agent_orchestrator.go`, `backend/internal/service/worker_driver_service.go`
- **修改目标**:
  - 在 GraphDelta 合并路径（`ingestPlannerNextIntents` / worker delta ingest）中：
    - 优先使用 `NewClueFacts` → upsert `AIBlackboardNode`（NodeType = ClueFact.NodeKind，ContentJSON 含 roles）
    - 优先使用 `ClueChainLinks` → upsert `AIBlackboardEdge`（EdgeType 从 link_kind 映射）
    - 优先使用 `RefutedClues` → 写 `clue_refuted` 节点 + `clue_refutes` Edge + suppress 目标节点
    - 旧字段（`NewFacts` / `NewNegativeFacts`）仅作 observation-only 入图
  - Emit audit `agent.clue_delta_ingested` with counts
- **不允许做什么**: 不删除旧字段处理逻辑（保留兼容）；不在本任务中修改 prompt（Phase 3 做）
- **对应测试**:
  - 新增 `cairn_loop_clue_merge_test.go`:
    - 结构化字段优先级验证
    - 旧字段 observation-only 验证
    - RefutedClues suppress 目标节点验证
  - 回归: `graph_search_fixture_e2e_test.go` 仍绿
- **回滚/toggle**: Phase toggle ≤1 时跳过结构化合并，走旧路径

---

## Phase 3 · Legacy vuln intent 降级（修复 P3）+ Prompt 改造（修复 P5、P6）+ Sanitizer

### Task 3.1: 启用 NormalizeIntentType

- [ ] **修改文件**: `backend/internal/service/intent_service.go`, `backend/internal/service/agent_orchestrator.go`, `backend/internal/service/dynamic_intent_expander_service.go`, `backend/internal/service/state_expansion_planner_service.go`
- **修改目标**:
  - 在所有 `AIIntent` 创建路径（`db.Create(&intent)`）前调用 `NormalizeIntentType`
  - 原 IntentType 存入 `ConstraintsJSON.legacy_hint`
  - Emit audit `agent.legacy_intent_normalized`
  - `isPentestRuntimeIntent` / `isCodeAuditRuntimeIntent` 改为读 `legacy_hint` 做 worker 路由（不再硬编码 vuln-type）
- **不允许做什么**: 不修改已持久化的旧 Intent 记录（read-time 映射在 Task 0.2 已覆盖）；不修改 prompt（Task 3.2 做）
- **对应测试**:
  - 修改 `dynamic_intent_expander_service_test.go` / `state_expansion_planner_service_test.go`: 验证输出 IntentType 全部在 5 个通用动词内
  - 新增集成测试: 创建 pentest 任务 → 启动 → 验证所有 Intent.IntentType ∈ {clue_collect, clue_validate, clue_refute, clue_chain_extend, scope_observation}
- **回滚/toggle**: Phase toggle ≤2 时不调用 NormalizeIntentType

### Task 3.2: Prompt 改造

- [ ] **修改文件**: `backend/internal/service/model_runtime_service.go`
- **修改目标**:
  - 重写 `buildPlannerPrompt`: 使用 design.md Components §"Planner system prompt" 骨架
  - 重写 `buildSecurityGraphPrompt`: 要求模型返回结构化 clue 字段，禁止漏洞类型词汇
  - 新增 `buildEvidenceIntentPrompt` 的 clue-driven 版本
  - IntentSuggestion 解析支持 `operation` / `intent_goal` / `expected_clue_roles` 字段
- **不允许做什么**: 不修改 `callResponsesAPI` / `callChatCompletionsAPI` 的 HTTP 调用逻辑；不修改 `GenerateReportNarrative`（Delivery 内部，允许保留漏洞类型语言）
- **对应测试**:
  - 修改 `model_runtime_service_test.go`: mock 模型返回新 schema → 验证解析正确
  - 新增测试: mock 模型返回旧 schema（缺 operation/intent_goal）→ 验证兜底 + audit
  - 新增测试: mock 模型返回 vuln_type 字段 → 验证被 sanitizer 剥离
- **回滚/toggle**: Phase toggle ≤2 时使用旧 prompt 函数

### Task 3.3: Deterministic Fallback 改造

- [ ] **修改文件**: `backend/internal/service/model_runtime_service.go`
- **修改目标**:
  - 重写 `deterministicIterationPlan`:
    - 无 clue 候选 → `scope_observation` + operation=`expand_surface`
    - 有未链接 clue_observation → `clue_chain_extend` + operation=`correlate_clues`
    - 有强信号缺 verification → `clue_validate` + operation=`recheck_inconclusive`
  - 重写 `deterministicEvidenceIntent`: 不再引用 vuln-type
  - 所有输出 IntentType 必须在 5 个通用动词内
- **不允许做什么**: 不修改 `deterministicReportNarrative`（Delivery 内部，允许保留漏洞类型语言）
- **对应测试**:
  - 新增 `model_runtime_deterministic_test.go`:
    - 无 modelConfig 的 task → 验证 Intent 全部 clue-driven
    - 验证不含 vuln-type 词汇
    - 验证 operation / intent_goal 字段非空
- **回滚/toggle**: Phase toggle ≤2 时使用旧 deterministic 函数

### Task 3.4: LLM Output Sanitizer

- [ ] **修改文件**: `backend/internal/service/llm_sanitizer.go`（新增文件）, `backend/internal/service/model_runtime_service.go`
- **修改目标**:
  - 新增 `SanitizeLLMOutput(raw parsedOutput) (sanitized parsedOutput, auditEvents []AuditEvent)` 函数
  - 规则实现（design.md Components §"Prompt / Output Sanitizer"）:
    1. 剥离 vuln-type 字段
    2. Legacy intent normalize
    3. Report-style 段落降级
    4. 缺字段兜底
    5. 过载截断
  - 在 `parsePlannerOutput` / `parseSecurityGraphDecisionOutput` / `parseEvidenceIntentOutput` 调用方插入 sanitizer
  - Sanitizer 失败时 fallback deterministic，不阻塞
- **不允许做什么**: 不修改 `parseReportNarrativeOutput`（Delivery 内部，允许漏洞类型语言）；不丢弃有效 clue 字段
- **对应测试**: `backend/internal/service/llm_sanitizer_test.go`（新增）
  - vuln_type 字段被剥离
  - legacy intent 被 normalize
  - report-style 被降级
  - 有效 clue 字段保留
  - 异常输入不 panic
  - Property-based: 随机 JSON 输入不丢有效 new_clue_facts
- **回滚/toggle**: Phase toggle ≤2 时不调用 sanitizer

---

## Phase 4 · Delivery Layer 完全隔离

### Task 4.1: 移除 Contract incomplete 反向生成 Intent

- [ ] **修改文件**: `backend/internal/service/contract_service.go`
- **修改目标**:
  - 找到 Contract incomplete → 生成补证据 Intent 的分支
  - 当 `cfg.DeliveryWriteback == "off"` 时：
    - 不创建 Intent
    - 只 emit audit event `agent.contract_incomplete_diagnostic`
    - 记录 missing fields 到 Delivery 内部 diagnostic
  - 当 `cfg.DeliveryWriteback == "on"` 时：保留旧行为（逃生）
- **不允许做什么**: 不删除 Contract 检查逻辑本身；不修改 Finding 状态机
- **对应测试**:
  - 修改 `contract_service` 相关测试: flag=off 时验证不产生 Intent
  - 新增测试: toggle=on 时旧行为保留
  - 回归: smoke test 仍通过
- **回滚/toggle**: `RABBIT_DELIVERY_WRITEBACK=on` 即回滚

### Task 4.2: DeliveryLayer 接口引入

- [ ] **修改文件**: `backend/internal/service/types.go`, `backend/internal/service/agent_orchestrator.go`
- **修改目标**:
  - 在 `Services` struct 中新增 `Delivery DeliveryLayer` 字段
  - 实现 `DeliveryLayer` 接口（包装现有 FindingService + ReportService）
  - `AgentOrchestrator` 在 finalize 阶段只调一次 `Delivery.GenerateArtifacts`
  - 移除 `agent_orchestrator.go` 中直接调用 `FindingService` / `ReportService` 的 Reason 路径引用
- **不允许做什么**: 不修改 Finding / Report 的最终输出内容；不修改前端 API 响应格式
- **对应测试**:
  - 集成测试: 完整跑一个 task → 验证 Finding + Report 仍正常生成
  - 验证 Reason 路径中无 FindingService / ReportService 调用（可用 grep guard 或 mock 验证）
- **回滚/toggle**: `RABBIT_DELIVERY_WRITEBACK=on` + Phase toggle ≤3 恢复旧路径

### Task 4.3: CI Lint Guard + README 更新

- [ ] **修改文件**: `scripts/` 或 CI config（新增 lint script）, `README.md`
- **修改目标**:
  - 新增 `scripts/lint-layer-isolation.sh`: grep `agent_orchestrator.go` / `cairn_loop.go` 中不允许出现 `FindingService` / `ContractService` / `ReportService` 的直接调用（白名单: Delivery 接口内部）
  - Phase 4 初期：lint 失败为 **warning**（不阻塞 CI），便于渐进清理
  - Phase 4 验收后：lint 失败必须升级为 **blocking check**（exit 1），防止 Delivery 再次反向污染 Kernel
  - 更新 README.md: 移除"Contract incomplete 会生成补证据 Intent"的话术，改为"Contract incomplete 仅记录 diagnostic"
- **不允许做什么**: 不修改后端代码逻辑
- **对应测试**: lint script 在 CI 中执行通过；Phase 4 验收后 blocking 模式下无违规
- **回滚/toggle**: 无需 toggle，lint 可直接 revert script

---

## 验收检查清单

完成全部 Phase 后，以下条件必须同时满足：

- [ ] `go test ./...` 全绿
- [ ] `scripts/smoke-first-stage.sh` 通过
- [ ] 新建 code_audit 任务 → 无 vuln-type IntentType 出现
- [ ] 新建 pentest 任务 → 无 vuln-type IntentType 出现
- [ ] 模型不可用 → deterministic fallback 只产 clue-driven Intent
- [ ] Capability 仅在 ClueChain role coverage 闭合时 verified
- [ ] Report 仍正常生成（Delivery Layer 内部可用 delivery proof）
- [ ] 旧任务（DB 中已有 legacy NodeType/IntentType）能继续读出并完成
- [ ] Runtime toggle 组合测试: 各 escape hatch 能独立回滚对应功能
