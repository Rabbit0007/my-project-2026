# AI Security Validation Platform 漏洞识别失败根因分析报告

## 1. 分析结论摘要

经过对 `backend/internal/service/` 核心链路的代码级排查，系统识别不出漏洞的根因如下：

1. **Reason 阶段预算过低（reasonPasses >= 2 即终止）**：模型连续两次没有产生新 Intent 就直接结束整个任务，不会继续探索。
2. **代码审计 Finding 完全依赖模型**：如果 `ModelConfigID == nil` 或模型调用失败，`buildModelCodeAuditFindingCandidates` 返回 nil，系统不会生成任何 Finding——即使 code_search 已经找到了 `move_uploaded_file` 等高价值 Sink。
3. **Contract 补证据 Intent 被创建但可能不被消费**：Contract 失败后确实创建了 `collect_evidence` Intent，但主循环 `runLoopIterations` 在 `reasonPasses >= 2` 时已经退出，新创建的 Intent 永远不会被执行。
4. **Context Builder 过于简单**：只喂 30 条 Blackboard Node + 20 条 Evidence + 20 条 Finding，没有注入 missing_fields、失败 ToolRun 原因、代码调用链上下文。模型拿不到足够信息做深度推理。
5. **code_search 只做 regex grep，没有项目级理解**：找到 `move_uploaded_file` 后只记录单行 snippet，不追踪 Source→Propagation→Sink 完整数据流。
6. **code_slice 只取固定半径窗口**：无法跨文件追踪调用链，无法理解上传后缀检查逻辑的完整上下文。
7. **没有 Bootstrap 直接尝试机制**：系统不会在第一轮就尝试"直接到达 Goal"，而是机械地跑 code_search → code_slice → 等模型判断。
8. **ToolRun 失败静默丢弃**：`runCodeAuditIntent` 中 `code_slice` 失败只是 `continue`，不写入 negative_fact 或 hint。
9. **报告只展示有 Finding 的内容**：如果整个流程没有产生 Finding（因为模型不可用或 reason 预算耗尽），报告显示"无漏洞"。
10. **单 Worker 串行执行**：没有多 Worker 并行探索，一条路径卡住就全卡住。

---

## 2. 当前系统实际执行链路

```text
TaskService.Create()
  → 创建 Workspace / Origin / Goal / 初始 Intent(code_trace 或 recon)
  → 状态 pending

AgentOrchestrator.Run(taskID)
  → 设置 task running
  → 创建 AIAgentLoop
  → runLoopIterations()
      → NextPending() 取第一个 pending Intent
      → Claim() 标记 running
      → runSingleIteration()
          → ContextBuilder.Build() 构建上下文
          → ModelRuntimeService.PlanIteration() 或 FallbackIterationPlan()
          → 根据 IntentType 分发：
              code_trace/collect_evidence → runCodeAuditIntent()
                  → code_search (ripgrep regex)
                  → code_slice (固定半径窗口)
                  → 返回 ToolRunOutcome[]
              recon/validate → runPentestIntent()
                  → http_surface / http_request / response_diff
                  → 返回 ToolRunOutcome[]
          → 写入 Blackboard (ToolRun fact + Evidence node + Fact nodes)
          → createOrUpdateFindings()
              → 代码审计：buildModelCodeAuditFindingCandidates()
                  → 如果模型可用：deepCodeAudit() 或 reasonOverSecurityGraph()
                  → 如果模型不可用：返回 nil → 不创建 Finding
              → 渗透测试：buildModelPentestFindingCandidates()
              → UpsertCandidate() → ContractService.CheckFinding()
                  → 如果 missing fields → 降级 + 创建补证据 Intent
      → 回到循环顶部
      → NextPending() 取下一个 pending Intent（包括 Contract 创建的）
      → 如果没有 pending Intent → runReasonPhase()
          → 如果 reasonPasses >= 2 → 返回 false → 循环结束
          → 否则调用 AnalyzeSecurityGraph() 让模型推理
          → 模型可能产生新 Intent / Finding
          → 如果产生了新 Intent → continue 循环
          → 如果没产生 → reasonPasses++ → 再试一次
  → Compactor.Compact()
  → ReportService.Generate()
  → 任务 completed
```

---

## 3. 与 Cairn 机制的差距

| Cairn 机制 | 当前系统状态 | 差距 |
|---|---|---|
| Bootstrap：一开始就尝试直接到达 Goal | ❌ 没有。第一轮只是机械跑 code_search | 缺少"直接尝试解决"的初始阶段 |
| Reason：读取完整图，判断是否继续 | ⚠️ 有，但 reasonPasses >= 2 就终止 | 预算太低，2 次 no-op 就放弃 |
| Explore：领取 Intent 执行 | ✅ 有，runSingleIteration 执行 Intent | 基本对齐 |
| Fact → Intent → Fact 循环 | ⚠️ 有框架，但循环容易被截断 | Contract Intent 可能来不及被消费 |
| 失败事实回写 | ❌ code_slice 失败只 continue，不写 fact | 失败信息丢失 |
| 动态 Intent 生成 | ⚠️ 模型可以生成，但依赖模型可用 | 模型不可用时完全没有动态 Intent |
| Worker 调度 | ❌ 单 goroutine 串行 | 没有并行探索 |
| Stigmergy 间接协同 | ❌ 只有一个 Worker | 无法涌现 |

---

## 4. 根因分类

### 4.1 Agent Loop 过早终止（P0 最高优先级）

**问题描述**：`reasonPasses >= 2` 时整个循环结束。如果模型第一次 reason 没产生 Intent（比如模型返回格式错误、或者判断信息不够），第二次也没产生，任务就直接结束了。

**代码位置**：`backend/internal/service/agent_orchestrator.go:147`
```go
if reasonPasses >= 2 {
    return false, nil  // 直接结束循环
}
```

**触发条件**：
- 模型不可用（ModelConfigID == nil）
- 模型返回解析失败
- 模型判断当前信息不足以产生新 Intent（但实际上 Contract 已经创建了补证据 Intent）

**影响**：任务在还有 pending Intent（Contract 创建的补证据 Intent）的情况下就结束了。

**关键矛盾**：`runReasonPhase` 只在 `NextPending() == nil` 时才被调用。但 Contract 在 `createOrUpdateFindings` 中创建的 Intent 是在同一轮 iteration 的末尾创建的。下一轮循环回到顶部时 `NextPending()` 应该能取到这个 Intent。

**真正的断点**：如果 `createOrUpdateFindings` 没有创建 Finding（因为模型不可用），那 Contract 也不会被调用，补证据 Intent 也不会被创建。这才是真正的死路。

**修复建议**：
1. 当模型不可用时，基于 code_search 结果的 pattern 匹配生成确定性 Finding Candidate（不依赖模型）
2. 将 reasonPasses 上限提高到 4-5
3. 在 reason 阶段检查是否有 contract_incomplete 的 Finding，如果有则强制生成补证据 Intent

---

### 4.2 代码审计 Finding 完全依赖模型（P0）

**问题描述**：`createOrUpdateFindings` 中，代码审计路径调用 `buildModelCodeAuditFindingCandidates`，如果模型不可用或返回空，直接 return nil，不创建任何 Finding。

**代码位置**：`backend/internal/service/agent_orchestrator.go:1082-1097`
```go
if task.TaskType == model.TaskTypeCodeAudit {
    items := o.loadEvidenceItems(ctx, evidenceIDs)
    candidates := o.buildModelCodeAuditFindingCandidates(ctx, task, intent, items, details)
    if len(candidates) == 0 {
        // 只记录审计事件，不创建 Finding
        appendAuditEvent(...)
        return nil  // ← 这里直接返回，不创建任何 Finding
    }
    ...
}
```

**触发条件**：
- `o.models == nil`（ModelRuntimeService 未初始化）
- `task.ModelConfigID == nil`（任务没绑定模型配置）
- 模型调用失败（网络超时、API 错误、JSON 解析失败）
- 模型返回空 findings 列表

**影响**：即使 code_search 找到了 `move_uploaded_file`、`$_FILES`、`in_array` 等高价值 pattern，如果模型不可用，系统不会生成任何 Finding。这是最致命的断点。

**修复建议**：
1. 实现确定性 Finding 生成器：当模型不可用时，基于 code_search 的 pattern 组合（Source + Sink 同文件/同目录）自动生成 hypothesis Finding
2. 确定性生成器不需要完整的数据流分析，只需要把"同一文件中同时出现 `$_FILES` 和 `move_uploaded_file`"这种组合标记为 candidate
3. 后续由 Contract 驱动补证据循环来完善

---

### 4.3 Context Builder 信息不足（P1）

**问题描述**：`ContextBuilder.Build()` 只提供 30 条 Blackboard Node + 20 条 Evidence + 20 条 Finding + 一句 recommended next。没有：
- missing_fields 列表
- 失败的 ToolRun 及其原因
- 代码文件结构概览
- Source/Sink 关联关系
- 已尝试但失败的探索方向

**代码位置**：`backend/internal/service/context_builder.go:34-67`

**影响**：模型在 PlanIteration 和 AnalyzeSecurityGraph 时拿不到足够上下文，无法做出有价值的推理决策。

**修复建议**：
1. 注入 Contract missing_fields（从 hint 类型的 Blackboard Node 中提取）
2. 注入最近失败的 ToolRun 摘要
3. 注入文件结构树（至少是 code_search 命中的文件列表）
4. 注入 Source/Sink 配对关系

---

### 4.4 code_search 只做 regex 没有项目级理解（P1）

**问题描述**：code_search 用 ripgrep 跑一组固定 regex pattern，找到匹配行后每行生成一条 Evidence。但它不理解：
- 哪些文件是入口点（路由/控制器）
- 哪些参数是用户可控的
- Source 和 Sink 之间的数据流关系
- 安全检查（黑名单/白名单）的完整逻辑

**代码位置**：`backend/internal/tools/code_search.go`

**影响**：对于 Pass-07 这种漏洞，code_search 能找到 `move_uploaded_file`、`$_FILES`、`in_array`、`strrchr` 等单行匹配，但无法理解"末尾点绕过黑名单"这种需要理解完整逻辑的漏洞。

**修复建议**：
1. 短期：在 code_slice 阶段增大 radius（当前对高价值 pattern 已经有 `codeSliceRadiusForEvidence` 但可能不够大）
2. 中期：实现"同文件 Source+Sink 关联"——当同一文件中同时出现 Source pattern 和 Sink pattern 时，自动做全文件 slice
3. 长期：实现 AST 级别的数据流分析（需要语言特定的 parser）

---

### 4.5 code_slice 失败静默丢弃（P2）

**问题描述**：`runCodeAuditIntent` 中 code_slice 失败只是 continue，不写入任何 fact 或 hint。

**代码位置**：`backend/internal/service/agent_orchestrator.go:430-440`
```go
sliceOutcome, sliceErr := o.toolRuns.Execute(ctx, ToolRunRequest{...})
if sliceErr == nil {
    outcomes = append(outcomes, sliceOutcome)
}
// sliceErr != nil 时直接跳过，不记录失败原因
```

**影响**：如果某个关键文件的 slice 失败（比如文件太大、路径错误），系统不知道这个失败，下一轮也不会重试。

**修复建议**：失败时写入 negative_fact 到 Blackboard，包含失败原因和目标文件路径。

---

### 4.6 模型不可用时没有确定性降级路径（P0）

**问题描述**：当模型不可用时：
- `PlanIteration` 返回确定性 plan（✅ 这个有）
- `buildModelCodeAuditFindingCandidates` 返回 nil（❌ 不创建 Finding）
- `reasonOverSecurityGraph` 不会被调用（❌ 没有确定性 reason）
- `SuggestEvidenceIntent` 返回确定性建议（✅ 这个有，但前提是 Finding 已存在）

**关键断点**：模型不可用 → 不创建 Finding → Contract 不被调用 → 补证据 Intent 不被创建 → 任务结束 → 报告无漏洞。

**修复建议**：实现确定性 Finding 生成器，基于 pattern 组合规则（不是固定漏洞规则，而是 Source+Sink 共现规则）。

---

### 4.7 Report 准入逻辑（P2）

**问题描述**：`renderMarkdownReport` 中 `view.Findings` 来自 `buildFindingViews`，需要确认它是否过滤了 candidate/contract_incomplete 状态的 Finding。

**代码位置**：`backend/internal/service/report_service.go:206`

**实际情况**：经过代码阅读，`buildFindingViews` 读取所有 Finding（不按状态过滤），所以如果 Finding 存在，报告会展示。问题不在报告过滤，而在 Finding 根本没有被创建。

---

## 5. 为什么 Pass-07 漏洞没有识别出来

以 Pass-07（文件名末尾点绕过黑名单）为例，逐步追踪断点：

| 步骤 | 是否执行 | 断点分析 |
|---|---|---|
| 1. 上传 ZIP 并解压 | ✅ | workspace 正常创建 |
| 2. code_search 扫描 | ✅ | 能找到 `move_uploaded_file`、`$_FILES`、`in_array`、`strrchr` |
| 3. code_slice 取上下文 | ✅ | 能取到 index.php 的部分代码 |
| 4. 生成 Evidence | ✅ | 每个 hit 生成一条 code_snippet Evidence |
| 5. 写入 Blackboard Fact | ✅ | Evidence 和 ToolRun 都写入了 |
| 6. createOrUpdateFindings | ⚠️ **这里断了** | 调用 `buildModelCodeAuditFindingCandidates` |
| 7. 模型分析代码 | ❓ 取决于模型是否可用 | 如果模型可用且返回正确 JSON → 创建 Finding |
| 8. 如果模型不可用 | ❌ **死路** | 返回 nil，不创建 Finding，任务继续但无漏洞 |
| 9. Contract Check | ❌ 不会执行 | 因为没有 Finding |
| 10. 补证据 Intent | ❌ 不会创建 | 因为 Contract 没被调用 |
| 11. Report | ❌ 显示无漏洞 | 因为没有 Finding |

**结论**：如果模型可用且正确返回，系统**能够**识别漏洞。问题出在：
1. 模型不可用时完全没有降级路径
2. 模型可用但返回格式不对时静默失败
3. 模型可用但 reasoning effort 设置为 "low"（见 `codeAuditReasoningEffort` 函数，默认返回 "low"）导致分析不够深入

---

## 6. 关键发现：codeAuditReasoningEffort 默认为 "low"

**代码位置**：`backend/internal/service/model_runtime_service.go`
```go
func codeAuditReasoningEffort(value string) string {
    switch strings.ToLower(strings.TrimSpace(value)) {
    case "none", "minimal", "low":
        return strings.ToLower(strings.TrimSpace(value))
    default:
        return "low"  // ← 即使用户配置了 "high" 或 "xhigh"，这里也返回 "low"
    }
}
```

**影响**：即使用户在模型配置中设置了 `modelReasoningEffort: "xhigh"`，代码审计和图推理的 reasoning effort 都被强制降为 "low"。这直接导致模型在分析复杂漏洞时深度不够。

**修复建议**：移除这个强制降级，或者至少改为 `return value`（保持用户配置的值）。

---

## 7. 最小修复方案（不破坏现有功能）

### P0-1：修复 codeAuditReasoningEffort 强制降级

```go
// 修改前
func codeAuditReasoningEffort(value string) string {
    switch strings.ToLower(strings.TrimSpace(value)) {
    case "none", "minimal", "low":
        return strings.ToLower(strings.TrimSpace(value))
    default:
        return "low"
    }
}

// 修改后
func codeAuditReasoningEffort(value string) string {
    v := strings.ToLower(strings.TrimSpace(value))
    if v == "" {
        return "medium"
    }
    return v
}
```

### P0-2：实现确定性 Finding 生成器

当模型不可用时，基于 Evidence 中的 pattern 组合自动生成 hypothesis Finding：
- 同一文件中同时出现 `file_upload_sink` + `file_upload_source` → 生成"文件上传候选风险"
- 同一文件中同时出现 `dynamic_code_execution` + `input_source` → 生成"代码执行候选风险"
- 同一文件中同时出现 `database_query_sink` + `input_source` → 生成"SQL 注入候选风险"

### P0-3：提高 reason 预算

```go
// 修改前
if reasonPasses >= 2 {

// 修改后
if reasonPasses >= 5 {
```

并且在 reason 阶段增加检查：如果存在 contract_incomplete 的 Finding，强制生成补证据 Intent。

### P1-1：增强 Context Builder

在 `AgentContext` 中增加：
- `MissingFields []string`：从 hint 类型 Blackboard Node 中提取
- `FailedToolRuns []model.AIToolRun`：最近失败的 ToolRun
- `FileStructure []string`：code_search 命中的文件列表

### P1-2：code_slice 失败写入 negative_fact

```go
if sliceErr != nil {
    o.blackboard.UpsertNode(ctx, BlackboardNodeDraft{
        TaskID:   task.ID,
        NodeType: "negative_fact",
        Title:    "Code slice failed for " + item.FilePath,
        Summary:  sliceErr.Error(),
        ...
    })
}
```

---

## 8. 推荐实施顺序

| 优先级 | 修复项 | 预计工作量 | 风险 |
|---|---|---|---|
| P0 | 修复 codeAuditReasoningEffort 强制降级 | 5 分钟 | 极低 |
| P0 | 实现确定性 Finding 生成器 | 2-3 小时 | 低 |
| P0 | 提高 reason 预算到 5 | 5 分钟 | 极低 |
| P1 | 增强 Context Builder | 1-2 小时 | 低 |
| P1 | code_slice 失败写入 negative_fact | 30 分钟 | 极低 |
| P2 | 实现同文件 Source+Sink 关联全文件 slice | 2-3 小时 | 低 |
| P2 | 多 Worker 并行探索 | 1-2 天 | 中 |

---

## 9. 不建议做的事情

1. ❌ 不要加固定漏洞规则库（如"检测 SQL 注入的 10 条规则"）
2. ❌ 不要加"测试强度"或"报告级别"选择
3. ❌ 不要用置信度代替证据
4. ❌ 不要把系统改成传统扫描器
5. ❌ 不要在客户报告中加入 Agent/Blackboard/ToolRun 等内部术语
6. ❌ 不要因为模型不可用就放弃整个 Finding 生成——应该有确定性降级
7. ❌ 不要把 reasoning effort 强制降为 low——这直接削弱了模型的分析深度

---

## 10. 验证方法

修复后使用 Pass-07 样例重跑：

1. 创建代码审计任务
2. 上传包含 Pass-07 index.php 的 ZIP
3. 启动任务
4. 预期数据库状态：
   - `ai_intents`：至少 3 条（初始 code_trace + 补证据 collect_evidence + 可能的 reason 产生的 Intent）
   - `ai_tool_runs`：至少 2 条（code_search + code_slice）
   - `ai_evidence`：至少 5 条（move_uploaded_file / $_FILES / in_array / strrchr / 完整文件 slice）
   - `ai_findings`：至少 1 条（文件上传候选风险，状态 candidate 或 contract_incomplete）
   - `ai_contract_check_results`：至少 1 条
5. 预期报告：包含文件上传漏洞的 Finding 章节（即使是 candidate 状态也应展示，但措辞受约束）
