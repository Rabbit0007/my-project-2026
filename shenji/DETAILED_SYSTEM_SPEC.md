# Rabbit AI Security Validation Platform — 详细系统规格说明书

> 本文档精确描述系统每个数据表、每个字段的含义、每个 API 接口的参数和返回值、每个服务的职责和调用关系。

---

## 第一部分：数据模型详细说明

### 1.1 AIUser — 用户表

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 用户唯一标识 |
| Username | string(80) | 是 | 登录用户名，全局唯一 |
| PasswordHash | string(260) | 是 | bcrypt 加密后的密码哈希，不返回给前端 |
| DisplayName | string(120) | 否 | 用户显示名称，用于前端展示 |
| Role | string(40) | 是 | 角色：admin（管理员）/ viewer（查看者），默认 admin |
| Enabled | bool | 是 | 是否启用，禁用后无法登录，默认 true |
| LastLoginAt | *time.Time | 否 | 最后一次成功登录的时间，首次登录前为 null |
| CreatedAt | time.Time | 自动 | 创建时间 |
| UpdatedAt | time.Time | 自动 | 最后更新时间 |

---

### 1.2 AIWorkspace — 工作区表

每个任务对应一个隔离的工作区，用于存放上传的代码、执行产物和证据文件。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 工作区唯一标识 |
| Name | string(180) | 是 | 工作区名称，通常为"任务名 + Workspace" |
| Description | text | 否 | 工作区描述 |
| RootPath | string(800) | 是 | 工作区在文件系统中的绝对路径，如 `/app/workspace/task-54` |
| StorageRef | string(800) | 否 | MinIO 存储引用前缀 |
| CreatedBy | uint | 否 | 创建者用户 ID |
| CreatedAt | time.Time | 自动 | 创建时间 |
| UpdatedAt | time.Time | 自动 | 更新时间 |

**目录结构：**
```
workspace/task-{id}/
  input/           # 用户上传的原始文件
    source.zip     # 上传的 ZIP 文件
    extracted/     # 解压后的源代码（只读）
  work/            # 工作临时目录（可写）
  artifacts/       # 产出物（可写）
  evidence/        # 证据文件（可写）
  logs/            # 执行日志（可写）
```

---

### 1.3 AISecurityTask — 安全验证任务表

系统的核心实体，代表一次完整的安全验证任务（代码审计或渗透测试）。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 任务唯一标识 |
| WorkspaceID | uint | 是 | 关联的工作区 ID |
| Name | string(220) | 是 | 任务名称，用户自定义 |
| TaskType | string(40) | 是 | 任务类型：`code_audit`（代码审计）/ `pentest`（渗透测试）/ `hybrid`（混合） |
| Status | string(40) | 是 | 任务状态：`pending`（等待启动）/ `running`（执行中）/ `completed`（已完成）/ `failed`（失败）/ `cancelled`（已取消） |
| Objective | text | 否 | 任务目标描述，如"发现代码中的高危漏洞" |
| ScopeJSON | jsonb | 否 | 授权范围 JSON，包含 targets/includePaths/excludePaths/level |
| AuthorizationJSON | jsonb | 否 | 授权策略 JSON，包含 level/allowChainExploration/allowReadOnlyCommands |
| SafePolicyJSON | jsonb | 否 | 安全策略 JSON，定义允许和禁止的操作 |
| ModelConfigID | *uint | 否 | 绑定的模型配置 ID，null 时使用确定性运行时 |
| IsTestTask | bool | 是 | 是否为测试任务（smoke test 用），默认 false |
| Archived | bool | 是 | 是否已归档，归档后不在默认列表显示，默认 false |
| ProgressStage | string(180) | 否 | 当前执行阶段的中文描述，如"正在执行代码智能检索" |
| ProgressPercent | int | 否 | 执行进度百分比 0-100 |
| StartedAt | *time.Time | 否 | 任务开始执行的时间 |
| FinishedAt | *time.Time | 否 | 任务完成/失败的时间 |
| CreatedBy | uint | 否 | 创建者用户 ID |
| CreatedAt | time.Time | 自动 | 创建时间 |
| UpdatedAt | time.Time | 自动 | 更新时间 |

**TaskType 枚举值：**
- `code_audit`：代码审计，需要上传 ZIP 源代码
- `pentest`：渗透测试，需要输入授权目标 URL/IP
- `hybrid`：混合模式，同时支持代码审计和渗透测试

**Status 状态机：**
```
pending → running → completed
pending → running → failed
pending → cancelled
```

---

### 1.4 AITaskTarget — 任务目标表

记录任务的授权测试目标（URL/域名/IP/代码仓库等）。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 目标唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| TargetType | string(40) | 是 | 目标类型：`url` / `domain` / `ip` / `cidr` / `repo` / `zip` / `api_spec` |
| Value | string(1200) | 是 | 目标值，如 `http://10.0.13.145:8080` 或 `192.168.1.0/24` |
| ScopeStatus | string(40) | 是 | 范围状态：`in_scope`（授权范围内）/ `out_of_scope`（范围外）/ `unknown`（未确定） |
| Metadata | jsonb | 否 | 附加元数据 JSON |
| CreatedAt | time.Time | 自动 | 创建时间 |


---

### 1.5 AIAgentLoop — Agent 执行循环表

记录一次完整的 Agent 执行循环（从启动到结束）。每个任务通常只有一个 Loop。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 循环唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| Status | string(40) | 是 | 循环状态：`running` / `completed` / `failed` / `stopped` |
| Goal | text | 否 | 循环目标，通常等于任务的 Objective |
| StartedAt | time.Time | 是 | 循环开始时间 |
| FinishedAt | *time.Time | 否 | 循环结束时间 |
| StopReason | text | 否 | 停止原因，如"first-stage bootstrap loop completed"或错误信息 |
| CreatedAt | time.Time | 自动 | 创建时间 |

---

### 1.6 AIAgentLoopIteration — Agent 迭代表

记录 Agent Loop 中的每一轮迭代。每轮迭代对应一个 Intent 的执行。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 迭代唯一标识 |
| LoopID | uint | 是 | 所属 Loop ID |
| TaskID | uint | 是 | 所属任务 ID |
| IterationNo | int | 是 | 迭代序号（从 1 开始） |
| CurrentIntentID | *uint | 否 | 当前执行的 Intent ID |
| InputContextRef | string(900) | 否 | 输入上下文的存储引用路径 |
| ModelProvider | string(120) | 否 | 本轮使用的模型提供商名称 |
| ModelName | string(180) | 否 | 本轮使用的模型名称 |
| ThoughtSummary | text | 否 | 模型的思考摘要（不保存完整推理链） |
| PlannedAction | text | 否 | 模型规划的下一步动作 |
| ToolRunIDs | jsonb | 否 | 本轮执行的 ToolRun ID 列表，如 [359, 360, 361] |
| EvidenceRefs | jsonb | 否 | 本轮产生的 Evidence ID 列表 |
| BlackboardDelta | jsonb | 否 | 本轮黑板变化摘要 JSON |
| Status | string(40) | 是 | 迭代状态：`running` / `completed` / `failed` |
| ErrorMessage | text | 否 | 失败时的错误信息 |
| StartedAt | time.Time | 是 | 迭代开始时间 |
| FinishedAt | *time.Time | 否 | 迭代结束时间 |

---

### 1.7 AIBlackboardNode — 黑板节点表

黑板图的核心节点，记录系统在探索过程中发现的所有事实、意图、证据和发现。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 节点唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| NodeType | string(50) | 是 | 节点类型：`origin`（起点）/ `goal`（目标）/ `fact`（事实）/ `intent`（意图）/ `hint`（提示）/ `finding`（发现）/ `evidence`（证据）/ `summary`（摘要）/ `negative_fact`（否定事实） |
| Title | string(260) | 是 | 节点标题 |
| Summary | text | 否 | 节点摘要描述 |
| ContentJSON | jsonb | 否 | 节点完整内容 JSON（结构化数据） |
| DedupKey | string(160) | 是 | 去重键，相同 DedupKey 的节点会被合并而非重复创建 |
| ImportanceScore | float64 | 否 | 重要性评分 0.0-1.0，用于 Context Builder 选择最重要的节点 |
| Status | string(40) | 是 | 节点状态：`active`（活跃）/ `merged`（已合并）/ `archived`（已归档）/ `suppressed`（已抑制） |
| SourceType | string(50) | 是 | 来源类型：`agent`（Agent 生成）/ `tool`（工具产出）/ `human`（人工输入）/ `contract`（Contract 生成）/ `system`（系统生成） |
| SourceID | string(160) | 否 | 来源标识，如 ToolRun ID 或 Intent ID |
| EvidenceRefs | jsonb | 否 | 关联的 Evidence ID 列表 |
| FirstSeenAt | time.Time | 是 | 首次出现时间 |
| LastSeenAt | time.Time | 是 | 最后一次被更新的时间 |
| SeenCount | int | 是 | 被观察到的次数（去重合并时递增） |
| CreatedAt | time.Time | 自动 | 创建时间 |
| UpdatedAt | time.Time | 自动 | 更新时间 |

**DedupKey 生成规则：**
- 格式：`hash(taskID + dedupSeed)`
- 相同 DedupKey 的节点不会重复创建，而是更新 LastSeenAt 和 SeenCount

---

### 1.8 AIBlackboardEdge — 黑板边表

黑板图中节点之间的关系边。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 边唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| FromID | uint | 是 | 起始节点 ID |
| ToID | uint | 是 | 目标节点 ID |
| EdgeType | string(60) | 是 | 边类型：`supports`（支持）/ `leads_to`（导向）/ `derived_from`（派生自）/ `contradicts`（矛盾）/ `missing_evidence_for`（缺少证据）/ `executed_tool`（执行了工具）/ `produced_evidence`（产出了证据）/ `supports_fact`（支持事实）/ `spawned_intent`（生成了意图）/ `supports_finding`（支持发现）/ `reasoned_fact`（推理出的事实） |
| Weight | float64 | 否 | 边权重 0.0-1.0，表示关系强度 |
| Metadata | jsonb | 否 | 附加元数据 |
| CreatedAt | time.Time | 自动 | 创建时间 |

---

### 1.9 AIIntent — 探索意图表

记录系统的每一个探索方向。Intent 是 Cairn 式状态空间搜索的核心驱动力。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | Intent 唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| ParentNodeID | *uint | 否 | 父黑板节点 ID（表示由哪个节点派生） |
| IntentType | string(80) | 是 | 意图类型：`code_trace`（代码追踪）/ `collect_evidence`（收集证据）/ `recon`（信息收集）/ `validate`（验证）/ `fingerprint`（指纹识别）/ `reason`（推理）/ `report`（报告生成） |
| Title | string(260) | 是 | 意图标题，如"深度审计: index.php" |
| Objective | text | 否 | 意图目标的详细描述 |
| ConstraintsJSON | jsonb | 否 | 约束条件 JSON，如 `{"filePath": "index.php", "safe": true}` |
| RequiredEvidence | jsonb | 否 | 需要收集的证据类型列表 |
| PriorityScore | float64 | 是 | 优先级评分 0.0-1.0，越高越优先被执行 |
| Status | string(40) | 是 | 状态：`pending`（等待执行）/ `claimed`（已认领）/ `running`（执行中）/ `completed`（已完成）/ `failed`（失败）/ `cancelled`（已取消）/ `suppressed`（已抑制）/ `archived`（已归档） |
| ClaimedBy | string(160) | 否 | 认领该 Intent 的 Worker 标识 |
| ClaimExpiresAt | *time.Time | 否 | 认领过期时间（Worker Lease） |
| CreatedBy | string(50) | 是 | 创建者：`system`（系统初始化）/ `agent`（Agent 推理生成）/ `contract`（Contract 补证据生成）/ `human`（人工创建） |
| CreatedReason | text | 否 | 创建原因说明 |
| StartedAt | *time.Time | 否 | 开始执行时间 |
| FinishedAt | *time.Time | 否 | 执行完成时间 |
| CreatedAt | time.Time | 自动 | 创建时间 |
| UpdatedAt | time.Time | 自动 | 更新时间 |

---

### 1.10 AIToolRun — 工具执行记录表

记录每一次工具调用的完整信息，包括输入、输出、容器信息和安全策略。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | ToolRun 唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| IterationID | *uint | 否 | 所属迭代 ID |
| IntentID | *uint | 否 | 触发该 ToolRun 的 Intent ID |
| RunnerType | string(80) | 是 | Runner 类型：`code_audit` / `pentest` / `http` / `sandbox` / `report` |
| ToolName | string(120) | 是 | 工具名称：`code_search` / `code_slice` / `http_request` / `fingerprint` / `pentest_probe` / `sandbox_exec` / `response_diff` |
| InputJSON | jsonb | 否 | 工具输入参数 JSON |
| CommandPreview | text | 否 | 实际执行的命令预览（脱敏后） |
| ContainerID | string(160) | 否 | Docker 容器 ID |
| ImageName | string(240) | 否 | 使用的 Docker 镜像名称 |
| WorkspacePath | string(800) | 否 | 挂载的工作区路径 |
| NetworkPolicy | string(120) | 否 | 网络策略：`none`（无网络）/ `bridge`（桥接，可访问外网）/ `host`（主机网络） |
| ResourceLimits | jsonb | 否 | 资源限制 JSON（CPU/Memory/Pids/Timeout） |
| Status | string(40) | 是 | 执行状态：`pending` / `running` / `success` / `failed` / `timeout` / `blocked` |
| ExitCode | *int | 否 | 容器退出码 |
| StdoutRef | string(900) | 否 | 标准输出的 MinIO 存储引用 |
| StderrRef | string(900) | 否 | 标准错误的 MinIO 存储引用 |
| ArtifactRefs | jsonb | 否 | 产出物的存储引用列表 |
| SafePolicySnapshot | jsonb | 否 | 执行时的安全策略快照 |
| BlockReason | text | 否 | 被安全策略阻断的原因（Status=blocked 时） |
| StartedAt | time.Time | 是 | 开始执行时间 |
| FinishedAt | *time.Time | 否 | 执行完成时间 |
| CreatedAt | time.Time | 自动 | 创建时间 |

---

### 1.11 AIEvidence — 证据表

记录所有安全验证过程中收集到的证据。每条证据必须有 hash 和来源 ToolRun。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 证据唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| ToolRunID | *uint | 否 | 产生该证据的 ToolRun ID |
| EvidenceType | string(80) | 是 | 证据类型：`code_snippet`（代码片段）/ `http_exchange`（HTTP 交互）/ `tool_output`（工具输出）/ `response_diff`（响应差异）/ `marker_poc`（Marker PoC 结果）/ `screenshot`（截图）/ `runtime_log`（运行日志）/ `command_output`（命令输出）/ `chain_proof`（链路证明） |
| Title | string(260) | 是 | 证据标题 |
| Summary | text | 否 | 证据摘要 |
| RawRef | string(900) | 否 | 原始数据的 MinIO 存储引用 |
| Hash | string(128) | 是 | 证据内容的 SHA-256 哈希，用于去重和完整性验证 |
| Target | string(1200) | 否 | 证据关联的目标（URL/文件路径） |
| FilePath | string(900) | 否 | 代码证据的文件路径 |
| LineStart | *int | 否 | 代码证据的起始行号 |
| LineEnd | *int | 否 | 代码证据的结束行号 |
| RequestSnapshot | jsonb | 否 | HTTP 请求快照 JSON |
| ResponseSnapshot | jsonb | 否 | HTTP 响应快照 JSON |
| ArtifactURL | string(900) | 否 | 产出物的访问 URL |
| RelationType | string(80) | 否 | 关系类型：`baseline`（基线）/ `code_sink`（代码 Sink）/ `code_source`（代码 Source）/ `poc_result`（PoC 结果）/ `fingerprint`（指纹）/ `cve_match`（CVE 匹配）/ `poc_reference`（PoC 引用） |
| Redacted | bool | 否 | 是否已脱敏 |
| CreatedAt | time.Time | 自动 | 创建时间 |

---

### 1.12 AIFinding — 漏洞发现表

记录系统发现的每一个安全漏洞/风险。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | Finding 唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| Title | string(280) | 是 | 漏洞标题，如"黑名单扩展名校验可绕过导致任意文件上传/RCE" |
| VulnerabilityType | string(160) | 是 | 漏洞类型：`command_execution` / `arbitrary_file_upload` / `sql_injection` / `path_traversal` / `ssrf` / `xxe` / `insecure_deserialization` / `weak_cryptography` 等 |
| AffectedTarget | string(1200) | 否 | 受影响的目标 |
| AffectedComponent | string(900) | 否 | 受影响的组件/文件路径 |
| Severity | string(40) | 是 | 严重程度：`critical`（严重）/ `high`（高危）/ `medium`（中危）/ `low`（低危）/ `info`（信息） |
| Status | string(60) | 是 | Finding 状态：`hypothesis`（假设）/ `candidate`（候选）/ `candidate_incomplete`（候选不完整）/ `contract_incomplete`（Contract 不完整）/ `dynamically_validated`（已动态验证）/ `human_confirmed`（人工确认）/ `false_positive`（误报）/ `accepted_risk`（接受风险）/ `fixed`（已修复）/ `retested`（已复测） |
| ValidationStatus | string(60) | 是 | 验证状态：`not_attempted`（未尝试）/ `tool_observed`（工具已观察）/ `contract_incomplete`（Contract 不完整）/ `dynamically_validated`（已动态验证）/ `human_confirmed`（人工确认） |
| ContractType | string(120) | 否 | Contract 类型，通常为 `generic_security_finding` |
| ContractStatus | string(60) | 是 | Contract 状态：`not_checked`（未检查）/ `passed`（通过）/ `incomplete`（不完整）/ `failed`（失败） |
| RichDetails | jsonb | 否 | 漏洞详细信息 JSON，包含 entrypoint/controlled_input/propagation_path/sensitive_sink_or_behavior/impact_explanation/remediation/bash_poc/python_poc/mermaid_graph 等所有报告字段 |
| EvidenceRefs | jsonb | 否 | 关联的 Evidence ID 列表 |
| Remediation | text | 否 | 修复建议 |
| RetestSteps | text | 否 | 复测方法 |
| HumanReviewStatus | string(60) | 是 | 人工复核状态：`pending`（待复核）/ `confirmed`（已确认）/ `false_positive`（误报）/ `accepted_risk`（接受风险） |
| HumanReviewNote | text | 否 | 人工复核备注 |
| CreatedAt | time.Time | 自动 | 创建时间 |
| UpdatedAt | time.Time | 自动 | 更新时间 |


---

### 1.13 AIContractCheckResult — Contract 检查结果表

记录每次 Finding Contract 检查的结果，包括缺失字段和生成的补证据 Intent。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 检查结果唯一标识 |
| FindingID | uint | 是 | 被检查的 Finding ID |
| TaskID | uint | 是 | 所属任务 ID |
| ContractType | string(120) | 是 | Contract 类型 |
| Status | string(60) | 是 | 检查状态：`passed`（通过）/ `incomplete`（不完整）/ `failed`（失败） |
| MissingFields | jsonb | 否 | 缺失的字段列表，如 `["bash_poc", "python_poc", "request_packet"]` |
| SatisfiedFields | jsonb | 否 | 已满足的字段列表 |
| EvidenceMapping | jsonb | 否 | 证据映射关系 |
| DowngradeReason | text | 否 | 降级原因说明 |
| NextIntentIDs | jsonb | 否 | 因缺失字段而创建的补证据 Intent ID 列表 |
| CheckedAt | time.Time | 是 | 检查执行时间 |

**Contract 通用字段（全部需要满足才能 passed）：**
- entrypoint / controlled_input / propagation_path / sensitive_sink_or_behavior
- trigger_payload_or_action / baseline_evidence / validation_evidence
- observed_result / impact_explanation / scope_statement / safety_statement
- remediation / retest_steps / evidence_mapping
- request_packet / bash_poc / python_poc / success_criteria / root_cause

---

### 1.14 AIReport — 报告表

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 报告唯一标识 |
| TaskID | uint | 是 | 所属任务 ID |
| Title | string(260) | 是 | 报告标题 |
| Status | string(40) | 是 | 报告状态：`generating` / `ready` / `failed` |
| Format | string(40) | 是 | 报告格式：`markdown_html`（同时生成 MD 和 HTML） |
| MarkdownRef | string(900) | 否 | Markdown 文件的 MinIO 存储引用 |
| HTMLRef | string(900) | 否 | HTML 文件的 MinIO 存储引用 |
| EvidencePack | string(900) | 否 | 证据包的存储引用 |
| Summary | text | 否 | 报告摘要 |
| GeneratedAt | *time.Time | 否 | 报告生成完成时间 |
| CreatedAt | time.Time | 自动 | 创建时间 |
| UpdatedAt | time.Time | 自动 | 更新时间 |

---

### 1.15 AIModelConfig — 模型配置表

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 配置唯一标识 |
| Name | string(160) | 是 | 配置名称，如"Claude Opus 4.7" |
| Provider | string(80) | 是 | 模型提供商：`OpenAI` / `openai-compatible` / `anthropic-compatible` |
| BaseURL | string(900) | 否 | API 基础地址，如 `https://key.simpleai.com.cn/v1` |
| Model | string(180) | 是 | 模型名称，如 `claude-opus-4-7` |
| APIKeyRef | string(260) | 否 | API 密钥（直接值或 `env://ENV_VAR` 格式） |
| OptionsJSON | jsonb | 否 | 高级选项 JSON：wireApi/modelReasoningEffort/networkAccess/requiresOpenAIAuth 等 |
| Enabled | bool | 是 | 是否启用，系统只使用 enabled=true 的第一个配置 |
| CreatedAt | time.Time | 自动 | 创建时间 |
| UpdatedAt | time.Time | 自动 | 更新时间 |

---

### 1.16 AIModelCallLog — 模型调用日志表

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 日志唯一标识 |
| TaskID | *uint | 否 | 关联的任务 ID（对话类调用可能为 null） |
| ModelName | string(180) | 是 | 调用的模型名称 |
| Provider | string(80) | 否 | 模型提供商 |
| Purpose | string(120) | 是 | 调用目的：`plan`（迭代规划）/ `code_audit`（代码审计）/ `graph_reasoning`（图推理）/ `chat`（对话）/ `evidence_intent`（补证据建议）/ `report_narrative`（报告生成） |
| Status | string(40) | 是 | 调用状态：`success` / `failed` / `timeout` |
| LatencyMs | int64 | 否 | 调用耗时（毫秒） |
| PromptTokens | int | 否 | 提示 tokens 数（估算） |
| CompTokens | int | 否 | 补全 tokens 数（估算） |
| ErrorMessage | text | 否 | 失败时的错误信息 |
| CalledAt | time.Time | 是 | 调用时间 |

---

### 1.17 AIAuditEvent — 审计事件表

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| ID | uint | 自增主键 | 事件唯一标识 |
| TaskID | *uint | 否 | 关联的任务 ID |
| EventType | string(100) | 是 | 事件类型，如 `agent.started` / `agent.completed` / `agent.failed` / `agent.model_plan` / `toolrun.completed` / `task.created` 等 |
| Actor | string(160) | 是 | 执行者：`user` / `agent-runtime` / `model-runtime` / `system` / `runner` |
| Summary | text | 否 | 事件摘要描述 |
| Metadata | jsonb | 否 | 事件附加数据 JSON |
| OccurredAt | time.Time | 是 | 事件发生时间 |

---

## 第二部分：API 接口详细说明

### 2.1 认证接口

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| POST | /api/v1/auth/login | 否 | 登录，返回 JWT token |
| GET | /api/v1/auth/me | 是 | 获取当前用户信息 |
| POST | /api/v1/auth/change-password | 是 | 修改密码 |

**POST /api/v1/auth/login**
- 请求体：`{"username": "admin", "password": "admin123"}`
- 成功响应：`{"token": "xxx.yyy", "expiresAt": 1234567890}`
- 失败响应：`{"error": "用户名或密码错误"}`

### 2.2 任务接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/v1/tasks | 任务列表 |
| POST | /api/v1/tasks | 创建任务 |
| GET | /api/v1/tasks/:id | 任务详情（含 findings/evidence/reports/timeline） |
| POST | /api/v1/tasks/:id/start | 启动任务 |
| POST | /api/v1/tasks/:id/upload | 上传 ZIP |
| POST | /api/v1/tasks/:id/archive | 归档/取消归档 |
| DELETE | /api/v1/tasks/:id | 删除任务（级联删除所有关联数据） |
| POST | /api/v1/tasks/:id/restart | 重新执行任务 |
| GET | /api/v1/tasks/:id/timeline | 任务时间线 |
| GET | /api/v1/tasks/:id/tool-runs | 任务的 ToolRun 列表 |
| GET | /api/v1/tasks/:id/evidence | 任务的 Evidence 列表 |
| GET | /api/v1/tasks/:id/findings | 任务的 Finding 列表 |
| GET | /api/v1/tasks/:id/reports | 任务的报告列表 |
| POST | /api/v1/tasks/:id/reports/regenerate | 重新生成报告 |
| GET | /api/v1/tasks/:id/export/findings?format=csv | 导出漏洞为 CSV/JSON |
| GET | /api/v1/tasks/:id/export/evidence?format=csv | 导出证据为 CSV/JSON |

### 2.3 其他接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/v1/overview | 工作台概览数据 |
| GET | /api/v1/tools | 已注册工具列表 |
| POST | /api/v1/chat | AI 对话 |
| GET | /api/v1/model-configs | 模型配置列表 |
| POST | /api/v1/model-configs | 创建模型配置 |
| PATCH | /api/v1/model-configs/:id | 更新模型配置 |
| POST | /api/v1/model-configs/:id/test | 测试模型连接 |
| GET | /api/v1/users | 用户列表 |
| POST | /api/v1/users | 创建用户 |
| PATCH | /api/v1/users/:id | 更新用户 |
| GET | /api/v1/audit-events | 审计事件列表 |
| GET | /api/v1/model-call-logs | 模型调用日志 |
| POST | /api/v1/findings/:id/review | 人工复核 Finding |

---

## 第三部分：后端服务职责

| 服务 | 文件 | 职责 |
|---|---|---|
| AuthService | auth_service.go | 用户认证、JWT 签发验证、默认用户创建 |
| ChatService | chat_service.go | AI 对话、模型连接测试 |
| TaskService | task_service.go | 任务 CRUD、ZIP 上传、安全解压 |
| AgentOrchestrator | agent_orchestrator.go | Agent 执行循环、Intent 调度、Finding 生成 |
| ModelRuntimeService | model_runtime_service.go | 模型调用抽象、多 Provider 支持 |
| BlackboardService | blackboard_service.go | 黑板节点/边的 CRUD、去重 |
| IntentService | intent_service.go | Intent 查询、认领、完成 |
| ToolRunService | toolrun_service.go | 工具执行、Evidence 提取 |
| EvidenceService | evidence_service.go | 证据存储、MinIO 写入 |
| FindingService | finding_service.go | Finding 创建/更新/复核 |
| ContractService | contract_service.go | Contract 检查、缺失字段反馈、补证据 Intent 生成 |
| ContextBuilder | context_builder.go | 构建 Agent 上下文（L3 摘要 + 相关 L2） |
| BlackboardCompactor | blackboard_compactor.go | 黑板压缩、合并重复、归档低价值节点 |
| ReportService | report_service.go | 报告生成（Markdown + HTML） |
| ModelConfigService | model_config_service.go | 模型配置 CRUD |

---

## 第四部分：工具详细说明

### 4.1 code_search
- **用途**：用 ripgrep 在源代码中搜索安全相关 pattern
- **Runner**：runner-code-audit（Docker 容器）
- **输入**：root（源码根目录）、patterns（正则列表，默认内置 17 个安全 pattern）、maxHits（最大命中数）
- **输出**：按优先级排序的命中列表（文件/行号/pattern/代码片段）
- **Evidence**：每个命中生成一条 code_snippet 类型的 Evidence

### 4.2 code_slice
- **用途**：提取指定文件指定行号周围的代码上下文
- **Runner**：runner-code-audit
- **输入**：root、filePath、line（中心行号）、radius（上下文半径，默认 36-80 行）
- **输出**：代码片段文本
- **Evidence**：生成 code_source 类型的 Evidence

### 4.3 fingerprint
- **用途**：识别目标的组件、框架、版本
- **Runner**：runner-pentest
- **输入**：target（URL）、mode（http_headers/dependency_scan/full）
- **输出**：组件列表（name/version/category/confidence/source）
- **后续**：进入 EnvironmentModel 和普通 Hypothesis formation；不触发外部 PoC 仓库查询。

---

## 第五部分：环境变量完整说明

| 变量 | 默认值 | 说明 |
|---|---|---|
| APP_ENV | development | 运行环境 |
| FRONTEND_PORT | 13110 | 前端端口 |
| BACKEND_PORT | 18080 | 后端内部端口 |
| HOST_BACKEND_PORT | 18190 | 后端对外映射端口 |
| DATABASE_DSN | - | PostgreSQL 连接串 |
| REDIS_ADDR | redis:6379 | Redis 地址 |
| WORKSPACE_ROOT | /app/workspace | 工作区根目录（容器内） |
| HOST_WORKSPACE_ROOT | - | 工作区根目录（宿主机） |
| MINIO_ENDPOINT | minio:9000 | MinIO 地址 |
| MINIO_ACCESS_KEY | minioadmin | MinIO 访问密钥 |
| MINIO_SECRET_KEY | minioadmin | MinIO 秘密密钥 |
| MINIO_BUCKET | rabbit-artifacts | MinIO 存储桶名 |
| MODEL_TIMEOUT_SECONDS | 90 | 模型调用超时（秒） |
| TOOL_TIMEOUT_SECONDS | 180 | 工具执行超时（秒） |
| SANDBOX_TIMEOUT_SECONDS | 300 | 沙箱执行超时（秒） |
| MAX_ITERATIONS | 30 | Agent 最大迭代次数 |
| MAX_RUNTIME_MINUTES | 60 | Agent 最大运行时间（分钟） |
| MAX_TOOL_RUNS | 60 | 单任务最大 ToolRun 数 |
| MAX_PENDING_INTENTS | 40 | 最大待执行 Intent 数 |
| JWT_SECRET | - | JWT 签名密钥 |
| CORS_ORIGINS | - | 允许的跨域来源 |
