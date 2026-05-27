# Rabbit Re-Centering Modification Summary

## 1. 背景

本次修改的目标是把 Rabbit AI Security Validation Platform 从 Phase 7 引入的外部 ProofPacket / GitHub POC repository / SafeProbe side-probe 路线中彻底拉回主线。

Rabbit 当前主线被重新明确为：

```text
Fact / Observation / Evidence
→ Hypothesis / Intent
→ Runner / Explore
→ Evidence / New Fact
→ Capability / NegativeFact / UnverifiedRisk
→ DynamicIntentExpander
→ StateExpansionPlanner
→ ExplorationBudgetManager
→ Next Intent
```

核心原则：

```text
Rabbit is not a scanner.
Rabbit is not a CVE/PoC search engine.
Rabbit is not a report-first vulnerability formatter.
Rabbit is a Cairn-style state-space exploration system.

Tools only observe or validate.
Findings are delivery artifacts.
Contracts are report quality gates.
Reports are outputs.
The graph exploration loop is the product.
```

中文原则：

```text
Rabbit 不是扫描器。
Rabbit 不是 CVE/PoC 搜索器。
Rabbit 不是报告优先的漏洞格式化系统。
Rabbit 是 Cairn-style 状态空间探索系统。

工具只负责观察和验证。
Finding 是交付产物，不是探索驱动力。
Contract 是报告质量闸门，不是主规划器。
Report 是最终输出，不是主循环。
图探索闭环才是产品核心。
```

## 2. Phase 7 删除结果

本次确认并清理了 Phase 7 相关运行时路径、配置、测试和文档残留。

已移除或确认不存在：

- ProofPacket runtime feature
- ProofPacket repository / index runtime dependency
- GitHub ProofPacket / POC repository sync path
- RepoSourceManager
- ProofPacket-derived SafeProbe path
- `proof_packet_search`
- `proof_packet_normalize`
- `safe_packet_validate`
- ProofPacket / repository side-probe audit events
- ProofPacket config and environment parsing
- Fingerprint-triggered external repository lookup
- Pheromone / clue layer tied to external ProofPacket logic

明确禁止保留的形态：

- default disabled
- feature flag disabled
- future plugin placeholder
- empty interface for later reuse
- dormant config

当前代码中不再让 ProofPacket / GitHub POC repository 影响主循环。

## 3. 主线纠偏

### 3.1 Agent Loop

`AgentOrchestrator` 已重新围绕状态空间探索闭环表达职责：

- 调度 Intent
- 调用 Runner / ToolRun
- 写入 Evidence
- 写入 Blackboard Fact / Evidence node
- 推动 Hypothesis lifecycle
- 调用 DynamicIntentExpander
- 调用 StateExpansionPlanner
- 由 ExplorationBudgetManager 控制分支增长
- 在预算或探索终止条件满足时生成交付结果

同时移除或停止主循环中的旧倾向：

- 不再让 Contract repair 替代 DynamicIntentExpander
- 不再因为“补报告字段”重置 no-progress
- 不再在每轮 evidence 后急切 promotion Finding
- 不再根据 Finding 数量作为主要终止依据

### 3.2 Model Runtime

移除了旧的 Finding-first 深度代码审计死路径：

- `DeepCodeAudit`
- `deepCodeAuditWithOpenAI`
- DeepCodeAudit prompt
- code-audit finding schema
- model finding suggestion merge path
- graph reasoner finding hint handling

保留并强化的方向：

- `AnalyzeSecurityGraph`
- 图状态输入
- 输出 facts
- 输出 next intents
- 不直接输出 Finding

Graph Reasoner schema 现在只服务：

```text
graph state → facts / next_intents
```

不再鼓励：

```text
code snippets → model finding suggestions → Finding
```

### 3.3 Finding / Contract / Report 定位

Finding 被重新定位为交付产物：

```text
Evidence-backed validated Hypothesis
+ Capability where applicable
+ reproducible validation path
+ impact explanation
→ Finding
```

禁止路径：

```text
pattern hit → confirmed Finding
fingerprint → Finding
model guess → confirmed Finding
CVE match → Finding
PoC reference → Finding
Contract need → Finding
```

ContractService 被重新定位为报告质量闸门：

- 可以检查字段完整性
- 可以降级 incomplete finding
- 可以请求补证据 intent
- 不参与主 planner 替代
- 不控制主 loop

Report 只作为最终输出层，不参与探索控制。

## 4. 代码审计流程改写

旧倾向：

```text
全量索引
→ 逐文件分析
→ Finding Candidate
→ Contract Check
→ Report
```

已改写为：

```text
创建任务 → 上传 ZIP → 安全解压
  ↓
Bootstrap Observation
  - 创建 origin / goal
  - code_search / code_slice / source index 产生 Observation
  - Source / Sink / EntryPoint / AuthBoundary 写入 Blackboard Fact
  ↓
Hypothesis Formation
  - Source+Sink 共现只能形成 Hypothesis / ValidationIntent
  - pattern hit 不能直接形成 confirmed Finding
  ↓
ValidationIntent
  - code_trace
  - dataflow_trace
  - inspect_auth_boundary
  - inspect_owner_check
  - validate_candidate_path
  ↓
Runner / ToolRun
  - code_search
  - code_slice
  - dataflow_trace
  - sandbox_exec if allowed
  ↓
Evidence / New Fact
  ↓
Capability / NegativeFact / UnverifiedRisk
  ↓
DynamicIntentExpander
  ↓
StateExpansionPlanner + ExplorationBudgetManager
  ↓
Finding / Contract / Report
```

硬性规则：

- `code_search` 是 Observation 工具
- `code_slice` 是 Evidence 工具
- Source/Sink/pattern hit 不是漏洞结论
- Finding 只能在 Evidence / Capability 足够后生成

## 5. 渗透测试流程改写

旧倾向：

```text
Recon
→ CVE Search
→ PoC Validate
→ Finding
```

已改写为：

```text
创建任务 → 输入授权目标
  ↓
Bootstrap Observation
  - 创建 origin / goal
  - 写入 target / scope / safe policy
  ↓
Recon / Fingerprint
  - http_surface
  - http_request
  - fingerprint
  - response_diff
  - 只写入 EnvironmentModel / Blackboard Fact / Evidence
  - 不触发外部漏洞数据库或公开验证包查询
  ↓
Hypothesis Formation
  - 根据页面、接口、参数、身份、响应差异、环境信息形成 Hypothesis
  ↓
ValidationIntent
  - http_request
  - response_diff
  - auth_boundary_test
  - idor_test
  - state_transition_test
  - business_logic_test
  ↓
Runner
  - 非破坏性验证
  - 授权范围检查
  - 安全策略检查
  ↓
Evidence / Capability / NegativeFact / UnverifiedRisk
  ↓
DynamicIntentExpander
  ↓
StateExpansionPlanner + ExplorationBudgetManager
  ↓
Finding / Contract / Report
```

硬性规则：

- fingerprint 只是 Observation / EnvironmentModel signal
- fingerprint 不触发外部 PoC
- fingerprint 不直接生成 Finding
- fingerprint 不直接生成 Capability

## 6. 终止条件纠偏

删除或改写了报告导向终止倾向。

不再以如下条件作为主要终止依据：

```text
N 个 contract_passed Finding
```

现在终止条件围绕状态探索：

```text
no meaningful graph expansion in N rounds
no new high-value Hypothesis / Intent
no new Capability
no pending high-value Intent
budget exhausted
explicit terminal goal completed
safety policy requires stop
```

## 7. 逻辑漏洞状态空间支持

新增或确认了逻辑漏洞能力表达，不作为 checklist 控制流，而作为状态空间探索中的 Capability。

新增 Capability 类型：

- `cross_user_object_access`
- `unauthorized_state_transition`
- `workflow_step_bypass`
- `business_value_tampering`
- `replay_success`

逻辑漏洞探索方式：

```text
Observation:
  接口、对象、身份、状态变化

Hypothesis:
  对象归属可能缺失
  状态转换可能绕过
  金额/数量可能篡改
  流程步骤可能跳过
  操作可能重放

ValidationIntent:
  多账号对比
  状态前后对比
  异常顺序请求
  异常参数提交
  重复提交

Runner:
  非破坏性多步骤验证

Evidence:
  请求/响应
  前后状态差异
  对象归属差异
  权限边界变化

Capability:
  cross_user_object_access
  unauthorized_state_transition
  workflow_step_bypass
  business_value_tampering
  replay_success
```

## 8. 新增 / 更新测试

新增或更新的核心回归测试集中在：

- Phase 7 删除验证
- external repository side-probe 不再出现
- removed intent type 不再进入 NextPending
- fingerprint 不触发外部 repository side-probe
- task creation 仍创建 GoalProfile / Hypothesis / Intent
- Evidence lifecycle 仍创建 Capability / NegativeFact / UnverifiedRisk
- Finding 仅作为 delivery artifact
- Contract incomplete 降级而不是确认
- 逻辑漏洞状态探索 smoke test

主要测试文件：

- `backend/internal/service/recentering_regression_test.go`
- `backend/internal/config/removed_feature_config_test.go`

关键测试：

- `TestFingerprintEvidenceDoesNotTriggerExternalRepositorySideProbe`
- `TestDynamicIntentExpanderCreatesOnlyMainLoopValidationIntent`
- `TestNextPendingSkipsRemovedExternalRepositoryIntentRows`
- `TestTaskCreationStillBootstrapsGoalHypothesisAndIntent`
- `TestEvidenceLifecycleStillProducesCapabilityNegativeFactAndUnverifiedRisk`
- `TestFindingIsDeliveryArtifactOnlyAfterValidatedCapability`
- `TestContractDowngradesIncompleteFindingWithoutConfirmingIt`
- `TestLogicVulnerabilityStateExplorationSmoke`
- `TestExternalRepositorySideProbeConfigIsRemoved`
- `TestExternalRepositorySideProbeEnvDoesNotAffectLoadedConfig`

## 9. 文档更新

更新了以下文档，使系统方向统一为 Cairn-style state-space exploration：

- `README.md`
- `SYSTEM_ARCHITECTURE.md`
- `docs/hypothesis-driven-autonomous-security-exploration.md`
- `docs/项目详细分析报告.html`
- `.kiro/specs/goal-profile-coverage-expansion/requirements.md`
- `.kiro/specs/goal-profile-coverage-expansion/design.md`
- `.kiro/specs/security-audit-platform-overhaul/requirements.md`
- `.kiro/specs/security-audit-platform-overhaul/design.md`
- `.kiro/specs/security-audit-platform-overhaul/tasks.md`

文档中已重写：

- CVE / PoC search mainline
- fingerprint side-probe wording
- deterministic finding generator wording
- Contract repair as planner wording
- Finding-first code audit flow
- report-first termination condition

## 10. 核心文件改动

后端核心改动：

- `backend/internal/service/agent_orchestrator.go`
- `backend/internal/service/model_runtime_service.go`
- `backend/internal/service/cairn_loop.go`
- `backend/internal/service/intent_service.go`
- `backend/internal/service/finding_service.go`
- `backend/internal/service/contract_service.go`
- `backend/internal/service/hypothesis_lifecycle_service.go`
- `backend/internal/service/state_expansion_planner_service.go`
- `backend/internal/model/capability.go`

测试改动：

- `backend/internal/service/recentering_regression_test.go`
- `backend/internal/config/removed_feature_config_test.go`
- `backend/internal/service/exploration_budget_manager_service_test.go`

配置 / 模型确认：

- `backend/internal/database/database.go`
- `backend/internal/model/hypothesis.go`
- `backend/internal/model/intent_types.go`

依赖：

- `backend/go.mod`

## 11. 验证结果

后端测试：

```bash
cd backend
go test ./...
```

结果：

```text
PASS
```

前端类型检查与构建：

```bash
cd frontend
npm run build
```

结果：

```text
PASS
```

说明：

- `npm run build` 包含 `vue-tsc -b` 和 `vite build`
- 构建过程中仅出现 Rollup 对第三方依赖 PURE 注释的提示，不影响构建结果

## 12. Remaining References

Phase 7 关键词检查结果：

```text
ProofPacket / proof_packet / RepoSourceManager / SafeProbe / safe_probe
proof_packet_search / proof_packet_normalize / safe_packet_validate
PROOF_PACKET_REPOSITORIES / PROOF_PACKET_SIDE_PROBE_ENABLED
AIPheromoneHint / proof_packet_hint / known_vuln_clue / safe_probe_candidate
```

结果：

```text
none in runtime code and current docs
```

仍存在的广义 PoC 字段：

- `curl_poc`
- `bash_poc`
- `python_poc`

保留原因：

这些字段位于报告交付层或普通验证证据展示层，用于呈现 evidence-backed validation path。它们不是 ProofPacket、GitHub repository sync、fingerprint side-probe 或外部 PoC 搜索主线。

## 13. 当前系统定位

当前 Rabbit 的产品核心重新统一为：

```text
自主探索能力
```

而不是：

```text
漏洞列表
扫描模板
CVE/PoC 搜索
报告字段填充
```

当前执行核心重新统一为：

```text
Fact → Intent → Explore → Fact
```

当前结果原则：

```text
Rabbit 的结果不是模型猜测。
Rabbit 的结果必须来自 Evidence。

Rabbit 的 Finding 不是起点。
Rabbit 的 Finding 是 Evidence-backed exploration 的交付产物。

Rabbit 的 Contract 不是主循环。
Rabbit 的 Contract 是报告质量闸门。

Rabbit 的工具不是主控流程。
Rabbit 的工具只是观察和验证手段。
```

## 14. Final Decision

```text
ACCEPTED
```

原因：

```text
Phase 7 ProofPacket / GitHub POC repository / SafeProbe side-probe 已从运行时移除；
旧的 Finding-first / DeepCodeAudit 死路径已清理；
文档和 specs 已重新统一到 Cairn-style 状态空间探索；
后端 go test ./... 通过；
前端 npm run build 通过。
```
