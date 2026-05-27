# Rabbit AI Security Validation Platform 项目详细分析报告

生成时间：2026-05-12  
项目路径：`/Users/rabbit/Desktop/shenji`  
分析对象：后端、前端、Runner 镜像、Docker 编排、脚本、workspace 历史产物  
分析方式：静态代码阅读 + 配置审查 + 本地构建与测试验证

---

## 1. 执行摘要

这个项目不是一个普通的任务管理后台，而是一个围绕“AI 原生安全验证闭环”搭建的第一阶段平台。它的核心目标是让安全审计任务从创建、授权范围定义、工具执行、证据沉淀、漏洞发现、Contract 检查到报告导出形成真实可运行链路。项目 README 中称其为 Rabbit AI Security Validation Platform，当前实现已经具备可演示、可验收、可导出报告的最小闭环。

从代码实现看，项目的主干设计非常明确：

- 后端使用 Go + Gin + GORM + PostgreSQL。
- 前端使用 Vue 3 + Vite + TypeScript + Element Plus。
- 运行环境通过 Docker Compose 编排 PostgreSQL、Redis、MinIO、Backend、Agent Worker、Frontend。
- 安全工具执行通过 Docker Runner 动态容器隔离，包括 code-audit、pentest、sandbox 三类核心 Runner。
- 平台以 Task 为入口，以 Intent 作为 Agent 的阶段目标，以 ToolRun 记录工具执行，以 Evidence 记录证据，以 Blackboard 维护事实图，以 Finding/Contract 判断是否达到交付门槛，以 Report 输出 Markdown/HTML 报告。
- 模型能力已接入 OpenAI / OpenAI-compatible 风格接口，支持 Responses API 与 Chat Completions API，并提供 deterministic fallback。

本次验证结果：

- `cd backend && go test ./...` 通过。
- `cd frontend && npm run build` 通过。
- `docker compose ps` 显示核心服务正在运行，backend healthy。
- 当前 workspace 约 949 MB，包含 53 个历史 task 目录与 89 个 artifact 文件，可视为本地演示与调试痕迹。

整体判断：

项目已经达到“第一阶段可运行闭环”的状态，工程分层、领域模型、审计链路和报告产物都比较完整。最强的部分是 Agent 执行链路、证据模型、工具运行记录、安全策略与报告生成的端到端设计。最大短板是生产化能力：认证授权缺失、Agent Worker 仍是心跳占位、Docker socket 权限边界偏大、数据库迁移和任务调度还不够生产级、前端聚合页存在取样限制、测试覆盖集中在基础安全和模型解析，尚未覆盖大部分业务闭环。

---

## 2. 项目定位与产品目标

### 2.1 产品定位

项目定位是一个 AI 原生安全验证平台，核心不是传统“规则扫描器”，而是一个可观察、可追溯、可交付的安全验证工作台。它强调以下几个产品动作：

1. 创建安全验证任务。
2. 对代码包或授权目标进行安全分析。
3. 用工具产生真实证据。
4. 用模型或 deterministic runtime 进行推理。
5. 用 Contract 判断 Finding 是否满足交付条件。
6. 自动生成正式报告。

这类系统的价值不在于单点工具，而在于“证据闭环”。代码里多次体现了这个理念：工具只是 sensor，模型/图推理才是 brain；漏洞结论不能由置信度代替，必须由证据、验证状态和 Contract 完整度驱动。

### 2.2 当前阶段边界

README 和源码都表明当前属于第一阶段。第一阶段重点包括：

- 代码审计闭环：创建任务 -> 上传 ZIP -> 安全解压 -> code_search/code_slice -> Evidence -> Finding -> Contract -> Report。
- 渗透验证闭环：创建任务 -> 授权目标 -> recon/http_request/http_surface/response_diff -> Evidence -> Finding -> Contract -> Report。
- 模型配置 CRUD。
- 模型不可用时 fallback。
- 报告 Markdown/HTML 导出。

当前未完全进入真实主链路或仍在计划中的能力：

- Browser runner。
- PDF / Word / evidence package 导出。
- 多 Worker 分布式调度。
- 更成熟的开放式状态空间搜索。
- Human review 治理闭环。
- 固定漏洞模板化扫描能力。

---

## 3. 仓库结构总览

项目根目录关键结构如下：

```text
/Users/rabbit/Desktop/shenji
├── README.md
├── .env.example
├── docker-compose.yml
├── backend/
│   ├── cmd/api/main.go
│   ├── cmd/worker/main.go
│   ├── internal/api/
│   ├── internal/config/
│   ├── internal/database/
│   ├── internal/middleware/
│   ├── internal/model/
│   ├── internal/runner/
│   ├── internal/safety/
│   ├── internal/service/
│   ├── internal/storage/
│   └── internal/tools/
├── frontend/
│   ├── src/api/
│   ├── src/router/
│   ├── src/stores/
│   ├── src/views/
│   ├── src/assets/
│   ├── Dockerfile
│   └── nginx.conf
├── runner-images/
│   ├── browser/
│   ├── code-audit/
│   ├── pentest/
│   ├── report/
│   └── sandbox/
├── scripts/
│   ├── smoke-first-stage.sh
│   └── archive-smoke-tasks.sh
└── workspace/
    ├── task-*/
    └── artifacts/
```

规模统计：

- 项目源码与脚本约 69 个文件。
- 后端 Go 代码约 12k 行级别，其中 Agent Orchestrator、Model Runtime、Report Service 是最大模块。
- 前端源码约 2k 行级别。
- 当前 workspace 占用约 949 MB，主要是历史任务输入、解压内容和报告/证据产物。
- `frontend/node_modules` 与 `frontend/dist` 已存在，属于依赖与构建产物，不应作为核心源码分析对象。

---

## 4. 技术栈分析

### 4.1 后端技术栈

后端位于 `backend/`，模块名为 `shenji/backend`，Go 版本声明为 1.25.0。

主要依赖：

- `github.com/gin-gonic/gin`：HTTP API 路由。
- `gorm.io/gorm`：ORM。
- `gorm.io/driver/postgres`：PostgreSQL 驱动。
- `gorm.io/datatypes`：JSONB 字段。
- `github.com/minio/minio-go/v7`：MinIO 对象存储。
- `github.com/docker/docker`：Docker SDK，用于动态构建和运行 Runner 容器。
- `github.com/rs/zerolog`：结构化日志。

后端整体是单体服务架构，内部按领域拆分为：

- API 层：`internal/api`
- Service 层：`internal/service`
- Tool 层：`internal/tools`
- Runner 层：`internal/runner`
- Storage 层：`internal/storage`
- Safety 层：`internal/safety`
- Model 层：`internal/model`

### 4.2 前端技术栈

前端位于 `frontend/`，技术栈为：

- Vue 3
- Vite 6
- TypeScript
- Vue Router
- Pinia
- Element Plus
- Axios
- Dayjs

前端构建命令：

```bash
cd frontend
npm run build
```

构建结果本次验证通过。构建产物中 Element Plus chunk 较大，`element-Cid9jWIB.js` gzip 后约 296.72 KB，属于正常但需要关注的体积点。

### 4.3 基础设施

`docker-compose.yml` 编排以下服务：

- PostgreSQL 16 Alpine
- Redis 7 Alpine
- MinIO
- Backend
- Agent Worker
- Frontend Nginx

默认本机端口：

- 前端：`http://localhost:13110`
- 后端：`http://localhost:18190`
- MinIO API：`http://localhost:19110`
- MinIO Console：`http://localhost:19111`
- PostgreSQL：`localhost:25440`
- Redis：`localhost:16400`

---

## 5. 后端架构详解

### 5.1 启动入口

后端 API 入口是 `backend/cmd/api/main.go`。

启动流程：

1. 加载配置。
2. 初始化 zerolog。
3. 连接数据库。
4. 执行 GORM AutoMigrate。
5. 根据配置初始化 Artifact Store：local 或 MinIO。
6. 初始化 WorkspaceManager。
7. 初始化 RunnerManager。
8. 注册默认工具。
9. 构建 Services。
10. 恢复中断任务。
11. 启动 Gin Router。

这说明 API 进程当前承担了几乎全部业务能力，包括任务调度和 Agent 异步执行。

`backend/cmd/worker/main.go` 当前只是连接数据库并输出心跳日志，代码中明确写着：

```text
agent worker ready; API process currently dispatches first-stage runs asynchronously
```

因此，当前 Agent Worker 不是实际任务消费者。它更像是为第二阶段分布式调度预留的进程壳。

### 5.2 配置系统

配置定义在 `backend/internal/config/config.go`，由环境变量驱动，提供默认值。

关键配置：

- `DATABASE_DSN`
- `REDIS_ADDR`
- `WORKSPACE_ROOT`
- `HOST_WORKSPACE_ROOT`
- `ARTIFACT_ROOT`
- `ARTIFACT_STORE_TYPE`
- `RUNNER_IMAGES_ROOT`
- `MINIO_*`
- `PUBLIC_BASE_URL`
- `CORS_ORIGINS`
- `MODEL_TIMEOUT_SECONDS`
- `TOOL_TIMEOUT_SECONDS`
- `SANDBOX_TIMEOUT_SECONDS`
- `WORKER_LEASE_TIMEOUT_SECONDS`
- `MAX_ITERATIONS`
- `MAX_RUNTIME_MINUTES`
- `MAX_TOOL_RUNS`
- `MAX_PENDING_INTENTS`
- `CODE_AUDIT_MAX_HITS`
- `CODE_AUDIT_MAX_SNIPPETS`
- `CODE_AUDIT_BATCH_SIZE`
- `CODE_AUDIT_MAX_BATCHES`

配置优点：

- 大部分运行参数可通过环境变量调节。
- 支持 Runner 镜像名称切换。
- 支持 MinIO 与 Local artifact store 两种模式。
- 对模型、工具、任务最大运行时长都有预算控制。

配置风险：

- 默认数据库密码、MinIO 用户名密码在 `.env.example` 和 compose 中是固定弱口令，只适合本地开发。
- 当前没有配置层面的必填校验，例如生产环境下是否必须设置强密码、认证密钥、MinIO 凭据等。
- Redis 配置存在，但当前未看到真实队列消费逻辑使用 Redis。

### 5.3 API 路由

API 路由定义在 `backend/internal/api/router.go`。

基础路由：

- `GET /healthz`
- `GET /artifacts/*filepath`

API v1：

- `GET /api/v1/overview`
- `GET /api/v1/tools`
- `GET /api/v1/model-configs`
- `POST /api/v1/model-configs`
- `PATCH /api/v1/model-configs/:id`
- `GET /api/v1/tasks`
- `POST /api/v1/tasks`
- `GET /api/v1/tasks/:id`
- `POST /api/v1/tasks/:id/start`
- `POST /api/v1/tasks/:id/upload`
- `GET /api/v1/tasks/:id/timeline`
- `GET /api/v1/tasks/:id/tool-runs`
- `GET /api/v1/tasks/:id/evidence`
- `GET /api/v1/tasks/:id/findings`
- `GET /api/v1/tasks/:id/reports`
- `POST /api/v1/tasks/:id/reports/regenerate`
- `POST /api/v1/tasks/:id/archive`
- `POST /api/v1/findings/:id/review`

API 设计特点：

- 任务详情接口聚合了 task、toolRuns、evidence、findings、reports、intents、contractChecks、timeline、blackboard、toolCatalog。
- artifact 读取由后端统一代理，可支持 local/minio 两种引用形式。
- 下载由 `?download=1` 或 `?download=true` 控制。

主要缺口：

- 没有认证中间件。
- 没有基于用户/工作区的访问控制。
- Artifact 读取只要知道 ref 路径就能访问，生产环境需要鉴权和权限校验。
- Handler 中 `GetTask` 对多个子查询忽略错误，例如 `toolRuns, _ := ...`，这会降低故障可观测性。

### 5.4 中间件

中间件位于 `backend/internal/middleware/middleware.go`。

包括：

- RequestLogger
- Recovery
- CORS

CORS 只允许配置中的 Origin，但允许 credentials。当前没有认证，所以 credentials 的意义有限。若后续加入 Cookie/JWT，需要严格审计 CORS 与 CSRF 方案。

---

## 6. 数据模型详解

数据模型定义在 `backend/internal/model/models.go`，由 GORM AutoMigrate 自动建表。

核心实体：

### 6.1 AIWorkspace

代表任务隔离工作区。

关键字段：

- `Name`
- `Description`
- `RootPath`
- `StorageRef`
- `CreatedBy`

当前每个任务创建时都会创建一个 workspace，并在本地 workspace 目录准备任务文件夹。

### 6.2 AISecurityTask

任务主表，是平台最核心实体。

关键字段：

- `WorkspaceID`
- `Name`
- `TaskType`
- `Status`
- `Objective`
- `ScopeJSON`
- `AuthorizationJSON`
- `SafePolicyJSON`
- `ModelConfigID`
- `IsTestTask`
- `Archived`
- `ProgressStage`
- `ProgressPercent`
- `StartedAt`
- `FinishedAt`

TaskType 支持：

- `code_audit`
- `pentest`
- `hybrid`

Status 支持：

- `pending`
- `running`
- `paused`
- `completed`
- `failed`
- `cancelled`

### 6.3 AITaskTarget

任务目标表，用于记录授权范围内的 URL、domain、CIDR、repo 等。

关键字段：

- `TaskID`
- `TargetType`
- `Value`
- `ScopeStatus`
- `Metadata`

### 6.4 AIAgentLoop 与 AIAgentLoopIteration

表示 Agent 执行循环和每次迭代。

Iteration 记录：

- 当前 Intent
- 输入上下文引用
- 模型 provider/name
- ThoughtSummary
- PlannedAction
- ToolRunIDs
- EvidenceRefs
- BlackboardDelta
- 状态与错误

这是平台可观测性的核心之一。

### 6.5 AIBlackboardNode 与 AIBlackboardEdge

黑板图是项目的关键架构抽象。

Node 用于记录：

- origin
- goal
- intent
- fact
- evidence
- finding
- hint
- summary
- negative_fact

Edge 用于表达：

- spawned_intent
- executed_tool
- produced_evidence
- supports_fact
- supports_finding
- reasoned_fact

通过黑板图，平台把工具输出从“日志堆叠”变成可被模型读取和继续推理的事实图。

### 6.6 AIIntent

Intent 是 Agent 的待执行目标。

关键字段：

- `IntentType`
- `Title`
- `Objective`
- `ConstraintsJSON`
- `RequiredEvidence`
- `PriorityScore`
- `Status`
- `ClaimedBy`
- `ClaimExpiresAt`
- `CreatedBy`
- `CreatedReason`

当前主要 intent 类型：

- `code_trace`
- `collect_evidence`
- `recon`
- `validate`
- `reason`

### 6.7 AIToolRun

ToolRun 记录每次工具执行。

关键字段：

- `RunnerType`
- `ToolName`
- `InputJSON`
- `CommandPreview`
- `ContainerID`
- `ImageName`
- `WorkspacePath`
- `NetworkPolicy`
- `ResourceLimits`
- `Status`
- `ExitCode`
- `StdoutRef`
- `StderrRef`
- `ArtifactRefs`
- `SafePolicySnapshot`
- `BlockReason`

这张表提供了完整审计链路：谁执行了什么工具、输入是什么、容器是什么、输出在哪里、是否被 SafePolicy 阻断。

### 6.8 AIEvidence

Evidence 是报告和 Finding 的证据基础。

关键字段：

- `EvidenceType`
- `Title`
- `Summary`
- `RawRef`
- `Hash`
- `Target`
- `FilePath`
- `LineStart`
- `LineEnd`
- `RequestSnapshot`
- `ResponseSnapshot`
- `ArtifactURL`
- `RelationType`
- `Redacted`

证据类型包括：

- `code_snippet`
- `tool_output`
- `http_exchange`
- `response_diff`
- `command_output`
- `marker_poc`

### 6.9 AIFinding

Finding 表示漏洞或候选风险。

关键字段：

- `Title`
- `VulnerabilityType`
- `AffectedTarget`
- `AffectedComponent`
- `Severity`
- `Status`
- `ValidationStatus`
- `ContractType`
- `ContractStatus`
- `RichDetails`
- `EvidenceRefs`
- `Remediation`
- `RetestSteps`
- `HumanReviewStatus`
- `HumanReviewNote`

Finding 的状态设计比较细：

- hypothesis
- candidate
- candidate_incomplete
- contract_incomplete
- dynamically_validated
- human_confirmed
- false_positive
- accepted_risk
- fixed
- retested

这说明项目有意区分“候选风险”“证据合同未闭环”“动态验证通过”“人工确认”等不同交付语义。

### 6.10 AIContractCheckResult

Contract 检查结果表，用于判断 Finding 是否满足报告交付门槛。

检查字段包括：

- entrypoint
- controlled_input
- propagation_path
- sensitive_sink_or_behavior
- trigger_payload_or_action
- baseline_evidence
- validation_evidence
- observed_result
- impact_explanation
- scope_statement
- safety_statement
- remediation
- retest_steps
- evidence_mapping
- request_packet
- bash_poc
- python_poc
- success_criteria
- root_cause

如果缺字段，Contract 会将 Finding 降级为 incomplete，并生成补证据 Intent。

### 6.11 AIReport

报告表，记录 Markdown 与 HTML 报告引用。

关键字段：

- `Title`
- `Status`
- `Format`
- `MarkdownRef`
- `HTMLRef`
- `EvidencePack`
- `Summary`
- `GeneratedAt`

当前已经支持 Markdown + HTML，EvidencePack 字段尚未真实形成完整证据包。

### 6.12 AIModelConfig

模型配置表。

关键字段：

- `Name`
- `Provider`
- `BaseURL`
- `Model`
- `APIKeyRef`
- `OptionsJSON`
- `Enabled`

API Key 推荐用 `env://OPENAI_API_KEY` 形式引用，避免直接明文写入数据库。但当前前端仍允许输入明文引用，生产环境应加入密钥管理策略。

### 6.13 AIAuditEvent

审计事件表，用于时间线。

事件包括：

- task.created
- workspace.zip_extracted
- agent.started
- agent.model_plan
- agent.model_fallback
- agent.graph_reasoning
- toolrun.completed
- toolrun.blocked
- agent.completed
- agent.failed

---

## 7. 核心业务流程分析

### 7.1 任务创建流程

实现位置：`backend/internal/service/task_service.go`

创建任务时执行以下动作：

1. 校验 taskType。
2. 如果是 pentest/hybrid，要求至少一个 target。
3. 校验 authorizationLevel 为 0-3。
4. 如果没有显式选择模型配置，则选择第一个 enabled 且名称不含 fallback 的配置作为默认模型。
5. 生成 scope/auth/policy JSON。
6. 创建 AIWorkspace。
7. 创建 AISecurityTask。
8. 准备本地 workspace 目录。
9. 保存 workspace.RootPath。
10. 为每个目标创建 AITaskTarget。
11. 写入黑板 origin 节点。
12. 写入黑板 goal 节点。
13. 创建初始 AIIntent。
14. 写入 task.created 审计事件。

设计优点：

- 任务创建阶段就把授权范围、目标、策略、黑板起点和初始 Intent 建好。
- 不把 Agent 的所有状态塞进 Task，而是用多张表记录演进过程。
- 授权等级与 SafePolicy 在任务开始前就固化为快照。

风险与改进：

- 任务创建不是显式事务，workspace、task、target、blackboard、intent 中任一步失败可能留下部分数据。
- `CreatedBy` 目前固定为 0，说明用户体系尚未接入。
- code_audit 任务 targets 可以为空，前端会把仓库说明写在 targetText 里但后端不保存为 target；这在产品语义上略有断裂。

### 7.2 ZIP 上传与安全解压

实现位置：

- `backend/internal/service/task_service.go`
- `backend/internal/runner/workspace.go`

上传流程：

1. 校验任务存在。
2. 校验只有 code_audit 或 hybrid 可上传 ZIP。
3. 将上传文件保存到 `workspace/task-{id}/input/`。
4. 解压到 `workspace/task-{id}/input/extracted/`。
5. 生成 ExtractManifest。
6. 写入黑板 fact：Source archive extracted safely。
7. 更新任务进度为“代码已上传，等待审计”。
8. 写入 workspace.zip_extracted 审计事件。

安全解压控制：

- 文件数量最大 12000。
- 单文件最大 16 MB。
- 总解压大小最大 256 MB。
- 上传读取最多 512 MB。
- 阻断 `../` 路径穿越。
- 阻断绝对路径。
- 阻断 symlink 和 device 文件。
- 目标路径二次校验必须位于 extracted 目录下。

测试覆盖：

- 已有测试验证 Zip Slip 阻断。
- 已有测试验证总大小限制。

改进建议：

- 上传文件扩展名和 MIME 校验目前主要在前端，后端只依赖 `zip.OpenReader`；可以明确返回更友好的 ZIP 格式错误。
- 解压前可以清理旧 extracted 内容，避免重复上传导致旧文件残留混入分析。
- 可以记录原始 ZIP 哈希，增强报告追溯。

### 7.3 任务启动与 Agent 执行

实现位置：`backend/internal/service/agent_orchestrator.go`

启动入口：

- API 调用 `StartTask`
- 读取任务
- code_audit/hybrid 要求 extracted 非空
- 调用 `Orchestrator.StartAsync(id)`
- API 进程启动 goroutine 执行任务

Agent Run 主流程：

1. 加载任务。
2. 如果已 running，返回错误。
3. 标记任务 running。
4. 创建 AIAgentLoop。
5. 进入 `runLoopIterations`。
6. 完成后执行黑板压缩。
7. 生成报告。
8. 标记任务 completed。

失败处理：

- `failTask` 会标记任务 failed。
- 服务启动时 `RecoverInterrupted` 会将 running task fail-closed，避免无限 running。

设计优点：

- 有最大运行时 `MaxRuntime`。
- 有最大迭代数 `MaxIterations`。
- 有 fail-closed 恢复机制。
- Agent 每次迭代都有 AIAgentLoopIteration 记录。

关键短板：

- 当前异步执行在 API 进程内，服务重启会中断任务。
- `agent-worker` 还没有真实消费任务。
- 没有分布式锁，多个 API 实例并发启动同一任务存在竞态风险。
- Redis 配置未实际承载任务队列。

### 7.4 Intent 执行逻辑

`runLoopIterations` 的逻辑：

1. 查找最高优先级 pending intent。
2. 如果不存在，进入 reason phase。
3. 如果 reason phase 创建新 intent，继续循环。
4. 如果没有新 intent，结束循环。
5. 如果存在 intent，claim 后执行单次迭代。

支持的 intent 类型：

- `code_trace`
- `collect_evidence`
- `recon`
- `validate`

未知 intent 会导致迭代失败。

Reason phase：

- 需要模型配置。
- 读取黑板图、证据、代码片段。
- 调用模型进行安全图推理。
- 可能产生新 fact、finding、next intent。
- 最多连续 2 次 no-op 后停止。

设计优点：

- 不是固定扫描流水线，而是保留了“图推理 -> 生成下一步 intent”的架构。
- Contract 缺字段也会生成补证据 intent。

现实边界：

- 当没有模型配置时，reason phase 无法继续，只能依赖 deterministic first-stage。
- collect_evidence 在代码审计中主要扩大代码 slice，在渗透中主要继续 validate。

---

## 8. 工具与 Runner 体系分析

### 8.1 ToolRegistry

默认注册工具：

- `http_request`
- `http_surface`
- `pentest_probe`
- `response_diff`
- `code_search`
- `code_slice`
- `sandbox_exec`
- `report_assembler`

每个工具实现统一接口：

- Name
- Kind
- Schema
- Validate
- Run
- ExtractEvidence

统一接口的好处是 ToolRunService 可以无差别处理校验、执行、持久化、证据抽取。

### 8.2 ToolRunService

实现位置：`backend/internal/service/toolrun_service.go`

执行流程：

1. 从 registry 获取工具。
2. 将输入序列化为 JSON。
3. 从任务生成 SafePolicy。
4. 创建 ToolRun pending。
5. 调用工具 Validate。
6. 如果被阻断，保存 blocked ToolRun 和 block reason。
7. 如果允许，保存 running ToolRun。
8. 调用工具 Run。
9. 保存 stdout/stderr 到 Artifact Store。
10. 更新 ToolRun 状态、容器 ID、镜像名、命令预览等。
11. 调用 ExtractEvidence。
12. 对每个 EvidenceDraft 创建 Evidence。
13. 写入 toolrun.completed 审计事件。

这是非常重要的“可追溯执行封装”。所有工具无论是否跑 Docker，都会沉淀为统一 ToolRun/Evidence。

### 8.3 RunnerManager

实现位置：

- `backend/internal/runner/manager.go`
- `backend/internal/runner/docker_client.go`

Runner 类型：

- sandbox
- code_audit
- pentest
- fallback local exec

Docker Runner 关键设计：

- 如果镜像不存在，则从 `runner-images/{runnerDir}` 动态构建。
- 每次工具执行创建独立容器。
- 挂载任务 workspace：
  - `/workspace/input` 只读
  - `/workspace/work` 可写
  - `/workspace/artifacts` 可写
  - `/workspace/evidence` 可写
  - `/workspace/logs` 可写
- code-audit 容器网络为 none。
- pentest 容器网络为 bridge。
- sandbox 容器按 SafePolicy 的 networkPolicy 传入，当前常用 none。
- 容器资源限制：
  - Memory 256 MB
  - CPU 0.5
  - PidsLimit 64
- 容器执行后停止并移除。

优点：

- 每次执行独立容器，隔离清晰。
- code audit 无网络，符合代码审计场景。
- 输入目录只读，降低工具改写源码风险。
- 容器 ID、镜像名、命令预览写入 ToolRun。

风险：

- backend 与 agent-worker 都挂载了 `/var/run/docker.sock`，这等价于高权限主机控制能力。生产环境必须将后端所在主机视为高信任边界，或引入更受限的 Runner 执行平面。
- Runner 容器网络策略仍比较粗粒度，pentest 使用 bridge 后依赖 SafePolicy 做目标校验，但容器运行时本身没有 egress allowlist。
- fallback local exec 仍存在，如果 Docker runtime 初始化失败，部分工具可能退回本地执行。这对生产安全边界不理想，应在生产环境 fail-closed。

### 8.4 code_search

实现位置：`backend/internal/tools/code_search.go`

作用：在解压源码中使用 ripgrep 搜索安全相关 source/sink 模式。

默认搜索模式覆盖：

- 命令执行/代码执行 sink
- 文件上传 sink/source
- PHP superglobal 输入
- Web 框架 request input
- 文件扩展名/MIME 校验函数
- 反序列化
- 动态 SQL 与 query 执行
- 文件读取/包含
- SSRF/outbound request
- open redirect
- XXE parser
- weak crypto

增强逻辑：

- 对不同 pattern 做 priority。
- 对 ERP、API、controller、service 等路径加权。
- 排除 node_modules、vendor、dist、build、libs、min.js、图片、二进制等低价值路径。
- 每类、每文件有限流。
- 输出按优先级排序。

输出 Evidence：

- 类型：`code_snippet`
- RelationType：`code_sink`
- Raw：脱敏后的命中行。

评价：

这是第一阶段很实用的传感器。它不直接宣称漏洞，而是给模型/图推理提供候选 source/sink 点，设计是正确的。

### 8.5 code_slice

实现位置：`backend/internal/tools/code_slice.go`

作用：围绕 code_search 命中行抽取上下文代码片段。

特点：

- radius 默认 12，最大 60。
- 通过 `nl -ba` + `sed` 抽取。
- 命中行以 `>>` 标记。
- 输出脱敏。
- Evidence 类型：`code_snippet`
- RelationType：`code_source`

风险与改进：

- 虽然 filePath 来自 code_search，工具自身没有强校验 filePath 是否位于 root 内部；当前命令使用 shellQuote 降低命令注入风险，但建议仍在 Validate 或 Run 中做路径规范化和 root containment 校验。

### 8.6 pentest_probe

实现位置：`backend/internal/tools/pentest_probe.go`

支持模式：

- `quick_http`
- `service_fingerprint`
- `dns`
- `web_crawl`

使用工具：

- curl
- whatweb
- nuclei
- nmap
- httpx
- katana
- sqlmap
- dig

注意：这些工具依赖 `runner-images/pentest/Dockerfile` 的基础镜像 `ai-security/kali-tools:latest`。这不是 Docker Hub 官方通用镜像，构建与供应链可用性需要单独确认。

输出会被 normalize 为 facts：

- http_status
- http_header
- service
- fingerprint
- tool_signal
- endpoint
- dns

Evidence 类型：`tool_output`。

评价：

这个工具把复杂外部工具输出收敛成结构化 facts，很符合黑板图架构。但 web_crawl 里使用 sqlmap 作为低级别表单探测，虽然参数较保守，仍应在生产中明确授权级别与速率限制。

### 8.7 http_request

实现位置：`backend/internal/tools/http_request.go`

作用：执行授权 HTTP 请求，记录请求/响应证据。

安全校验：

- SafePolicy ValidateTarget。
- SafePolicy ValidatePayload。

执行方式：

- Runner pentest 容器中执行 curl。
- `curl -sS -i -X {method}`。
- 通过 `__RABBIT_STATUS__` marker 提取状态码。

Evidence 类型：

- `http_exchange`
- RequestSnapshot：method/url。
- ResponseSnapshot：status/header summary。
- Raw：脱敏响应 body。

风险：

- Headers 会拼入 curl 命令，当前 header key/value 由上层控制，若未来开放用户输入，需要更严格校验。
- 仅记录 response body，完整 headers 只在 snapshot；需要报告级别的原始 HTTP 包时还不够完整。

### 8.8 http_surface

实现位置：`backend/internal/tools/http_surface.go`

作用：解析 HTML body 中的 link、form、参数，生成 HTTP 输入面。

特点：

- 不运行外部命令，在平台内解析。
- 使用正则解析 HTML。
- 最多处理 512 KB body。
- Links 最多 60。
- Forms 最多 24。
- Params 最多 80。

局限：

- 正则解析 HTML 在复杂页面、JS 渲染页面、动态路由方面能力有限。
- Browser runner 尚未接入，所以 SPA 输入面发现会受限。

### 8.9 response_diff

实现位置：`backend/internal/tools/response_diff.go`

作用：对 baseline 与 validation 响应做差异判断。

判断项：

- 状态码变化。
- Body 是否变化。
- marker 是否反射。

Evidence 类型：

- `response_diff`
- RelationType：`poc_result`

评价：

适合作为第一阶段“非破坏性 marker 验证”。但当前 diff 仍偏粗糙，后续可以增加结构化 diff、DOM diff、语义 diff、错误模式识别、时间差判断等。

### 8.10 sandbox_exec

实现位置：`backend/internal/tools/sandbox_exec.go`

作用：执行只读 proof command，例如 whoami/id/hostname/pwd/echo marker。

安全校验：

- SafePolicy ValidateCommand。
- 默认阻断破坏、持久化、反弹 shell 等命令。
- Level 1+ 才允许只读命令证明。

Evidence 类型：

- 普通只读命令：`command_output` / `command_output`
- PoC proof context：`command_output` / `poc_result`

评价：

用于命令执行类漏洞的非破坏性证明很合适。但当前 Orchestrator 里对 sandbox_exec 的使用从 smoke 脚本期待看似存在动态验证路径，不过在读到的主流程中没有看到大量显式 sandbox_exec 调用路径，需要结合历史运行数据继续验证。

---

## 9. SafePolicy 安全策略分析

实现位置：`backend/internal/safety/policy.go`

### 9.1 授权等级

DefaultPolicy：

- Level 0：只读信息收集，不允许只读命令证明。
- Level 1：允许 sandbox verification 与只读命令证明。
- Level 2：允许 chain exploration。
- Level 3：更高授权，命令策略更宽。

### 9.2 Target 校验

ValidateTarget：

- 从 URL 或 host 中提取 hostname。
- 如果有 AllowedScopes，则必须匹配。
- 如果没有 AllowedScopes，默认阻断敏感地址。

默认阻断：

- `169.254.169.254`
- `127.0.0.1`
- `localhost`
- `0.0.0.0`
- `::1`
- 私有 IPv4 网段
- 私有/链路本地 IPv6 网段

支持 scope 类型：

- 精确 host。
- 子域名后缀。
- CIDR。

优点：

- 防 SSRF 基础策略存在。
- 显式授权 loopback 可通过测试覆盖。

改进建议：

- URL 重定向后的目标也需要校验，否则 curl 跟随跳转可能访问出范围目标。当前 http_request 未加 `-L`，pentest_probe 中部分 curl 使用 `-L`，需要关注。
- DNS rebinding 未处理。
- IDN/punycode、IPv6 zone、混合编码 URL 可进一步加强。

### 9.3 Payload 与 Command 校验

危险片段包括：

- rm/del/format/mkfs/shutdown/reboot/halt/poweroff
- rm -rf
- dd if/of
- crontab/systemctl/launchctl/schtasks
- useradd/adduser/net user
- authorized_keys/passwd/shadow
- nc/ncat shell
- curl|wget pipe shell
- eval/assert/Runtime/ProcessBuilder 与命令执行相关片段

只读命令白名单：

- whoami
- id
- hostname
- pwd
- echo AI_VALIDATION_MARKER*
- printf AI_VALIDATION_MARKER*

测试覆盖：

- 允许只读 proof。
- 阻断破坏/持久化行为。
- 默认阻断 metadata 地址。
- 显式授权 loopback 允许访问。

---

## 10. 模型运行时分析

实现位置：`backend/internal/service/model_runtime_service.go`

### 10.1 支持能力

ModelRuntimeService 支持：

- PlanIteration：为当前 Intent 生成迭代计划。
- SuggestEvidenceIntent：为 Contract 缺字段生成补证据 Intent。
- GenerateReportNarrative：为报告生成更自然的摘要与 Finding 叙述。
- DeepCodeAudit：对代码片段做深度审计。
- AnalyzeSecurityGraph：读取黑板图做安全图推理。
- FallbackIterationPlan：模型失败时回退 deterministic plan。
- IterationCallMetadata：记录模型 provider/model/intentType。

### 10.2 Provider 支持

当前真实支持：

- `openai`
- `openai-compatible`

前端 Settings 页面虽然提供 Anthropic Compatible、Local Gateway 等选项，但后端会返回 unsupported model provider。这是一个前后端能力不一致点。

### 10.3 Wire API

支持：

- Responses API：`/responses`
- Chat Completions API：`/chat/completions`

Responses API 请求结构：

- model
- input system/user
- store false 可选
- reasoning effort 可选

Chat Completions 请求结构：

- model
- messages
- response_format json_object

### 10.4 Prompt 设计

模型 Prompt 分为几类：

- Planner Prompt：返回 thought_summary/planned_action，禁止泄露 chain-of-thought。
- Evidence Intent Prompt：返回 title/objective/intent_type。
- Deep Code Audit Prompt：要求从 source -> propagation -> sink 建图，输出完整 finding schema。
- Security Graph Prompt：读取黑板节点、边、代码片段，输出 facts/findings/next_intents/stop_reason。
- Report Narrative Prompt：生成中文专业报告叙述，并根据 Finding 状态避免强确认措辞。

Prompt 设计亮点：

- 明确“工具只是 sensors，模型才是 brain”。
- 强制 JSON 输出。
- 要求证据 ID 必须来自 packet。
- 对代码审计要求 entrypoint、controlled_input、propagation_path、sink、proof plan。
- 对报告叙述有 guardrail，不允许未验证时写“已确认/成功利用/getshell”等强措辞。

### 10.5 解析与容错

解析函数支持：

- 直接 JSON。
- 从包含 Markdown fence 或前后文本的响应中截取 `{...}`。

测试覆盖：

- parsePlannerOutput。
- joinAPIURL。
- parseEvidenceIntentOutput。
- enforceFindingNarrativeGuardrail。
- delivery evidence 判断。

改进建议：

- 使用 JSON schema / structured output 能提升稳定性。
- DeepCodeAudit 和 AnalyzeSecurityGraph 超时硬编码 140s，与全局 ModelTimeout 的关系略复杂。
- `codeAuditReasoningEffort` 会把 high/xhigh 降为 low，这可能是为了速度，但与配置期望可能不一致，应在文档或前端提示。
- Prompt 中中文/英文混合，长期可维护性可通过模板文件或版本号管理。

---

## 11. Agent Orchestrator 深度分析

实现位置：`backend/internal/service/agent_orchestrator.go`

这是项目最大、最复杂、最关键的模块。

### 11.1 主要职责

AgentOrchestrator 负责：

- 启动任务执行。
- 控制 Agent loop。
- Claim intent。
- 构建上下文。
- 调用模型规划。
- 根据 intent 类型调工具。
- 将 ToolRun/Evidence 写入黑板图。
- 从 Evidence 生成 Finding。
- 调用 Contract 检查。
- 在需要时触发 graph reasoning。
- 生成最终报告。
- 更新任务进度与状态。

### 11.2 代码审计路径

`runCodeAuditIntent`：

1. 检查 extracted source 是否存在。
2. 更新任务进度为“正在执行代码智能检索”。
3. 执行 `code_search`。
4. 基于 code_search Evidence 选择优先级最高的 slice target。
5. 对每个 target 执行 `code_slice`。
6. 返回所有 ToolRunOutcome。

优先级策略：

- 高优先级：eval/system/exec、SQL、unique check、file upload、unserialize 等。
- 路径加权：ERP/API/controller/service 等。
- 低价值路径降权：public/static/assets/jsutil/bundle/echarts/jspdf/mui 等。

随后 `createOrUpdateFindings` 对代码审计任务：

1. 加载 evidence items。
2. 调用模型构建代码审计 Finding candidates。
3. 如果模型没有返回 candidates，不创建 Finding，只记录 no model finding 事件。
4. 对候选 Finding 做 Upsert。
5. 执行 Contract Check。

这说明代码审计结论强依赖模型 source/sink reasoning，而不是直接由 regex 命中生成漏洞。

### 11.3 渗透验证路径

`runPentestIntent`：

1. 找出 URL/domain target。
2. 对每个 target，根据 intent 类型执行 recon 或 validate。

Recon：

1. 执行 pentest_probe quick_http。
2. 执行 pentest_probe service_fingerprint。
3. 执行 pentest_probe web_crawl。
4. 执行 http_request baseline。
5. 用 baseline body 执行 http_surface。
6. 从 surface 中生成 validation candidates。
7. 对 candidates 执行 marker validation。

Validation：

1. 构造 marker。
2. 对 baseline URL 做 baseline request。
3. 将 marker 放到 query 或 form 参数。
4. 执行 validation request。
5. 执行 response_diff。

Finding 生成：

- 优先使用模型对 pentest facts 进行图推理。
- 如果模型没有返回，但存在 response_diff 信号，则生成 pentest_candidate。
- 当 response_diff 显示 marker reflected/status changed/body length changed，validationStatus 可变为 dynamically_validated。

### 11.4 Graph Reasoning

`reasonOverSecurityGraph`：

1. 从黑板加载最多 80 个高重要性 active nodes。
2. 加载最多 120 条边。
3. 对代码审计附带最多 36 个 snippets。
4. 构造 SecurityGraphAuditPacket。
5. 调用模型 AnalyzeSecurityGraph。
6. 将模型输出 facts 写入黑板。
7. 将模型输出 next intents 写入 AIIntent。
8. 将 findings 转换为候选 Finding。

这个设计是项目未来扩展的核心：固定工具链只是第一层，真正持续探索依赖黑板图和模型。

### 11.5 关键风险

- 模块过大：AgentOrchestrator 约 2300 行，职责过多，后续维护压力较高。
- 一些路径特化明显，例如 ERP、SatRDA、upload-labs 相关优先级和排除逻辑，说明项目已针对特定样本调优，但泛化能力需要继续验证。
- 没有事务边界：一次迭代中 ToolRun、Evidence、Blackboard、Finding、Contract 多步写入，失败后可能部分落库。
- 任务并发控制较弱：API goroutine 执行，缺少真实 worker lease/队列/锁。

---

## 12. Contract 与报告交付分析

### 12.1 Contract 检查

实现位置：`backend/internal/service/contract_service.go`

Contract 的作用是确保 Finding 不只是“猜测”，而是包含报告交付所需字段。

如果缺字段：

- Finding.Status = `contract_incomplete`
- Finding.ValidationStatus = `contract_incomplete`
- Finding.ContractStatus = `incomplete`
- 写入 ContractCheckResult
- 写入黑板 hint
- 生成补证据 intent

如果字段完整且动态验证通过：

- Finding.Status = `dynamically_validated`

这套机制是项目的亮点。它避免了安全工具常见问题：发现大量疑似结果但无法交付。

### 12.2 报告生成

实现位置：`backend/internal/service/report_service.go`

Generate 流程：

1. 加载 task/findings/evidence/toolRuns/contractChecks snapshot。
2. 生成 deterministic narrative。
3. 如果模型可用，生成 enriched narrative。
4. 构建 reportView。
5. 渲染 Markdown。
6. 渲染 HTML。
7. 写入 Artifact Store。
8. 创建 AIReport。

报告内容包括：

- 执行摘要。
- 测试范围与授权边界。
- 漏洞发现。
- 漏洞定性与风险评估。
- 漏洞描述。
- 攻击向量。
- 代码证据。
- 数据流分析。
- 实际可利用性分析。
- 技术框架分析。
- 调用栈与 Mermaid 图。
- 漏洞利用证明。
- 根源分析与修复建议。
- 复测方法。
- Contract 检查摘要。
- 限制说明。

报告证据筛选：

- 过滤 runtime_log/tool_output 等不适合正文堆叠的内容。
- 代码证据优先 focused code slice。
- 过滤 upload-labs-env、Apache、PHP、min.js、jquery 等低价值环境文件。
- command_output 只有 PoC context 才进入交付证据。

评价：

报告生成非常完整，已经明显超过“demo 报告”的程度。它特别注意报告措辞，不会在 Contract 不完整时使用强确认语言。

改进建议：

- PDF/Word 导出尚未完成。
- EvidencePack 字段还未生成完整证据包。
- 报告 CSS 与 HTML 渲染在 Go 文件中硬编码，长期可以拆模板。
- 报告中大量字段依赖模型输出质量，建议为关键字段设置更严格的 schema 校验。

---

## 13. 前端架构分析

### 13.1 前端整体结构

前端入口：

- `frontend/src/main.ts`
- `frontend/src/App.vue`
- `frontend/src/router/index.ts`

路由：

- `/` 工作台
- `/tasks/new` 创建任务
- `/tasks` 任务中心
- `/tasks/:id` 任务详情
- `/findings` 漏洞中心
- `/reports` 报告中心
- `/settings` 系统设置

API client：

- `frontend/src/api/client.ts`

状态管理：

- `frontend/src/stores/platform.ts`

### 13.2 API Client

前端 API baseURL：

```ts
import.meta.env.VITE_API_BASE_URL || '/api/v1'
```

封装能力：

- overview
- list/create/update model configs
- list/create/get/start/archive task
- upload zip
- review finding

类型定义基本覆盖后端返回结构。

风险：

- `TaskDetail` interface 缺少 `toolCatalog` 字段，后端实际返回了该字段。
- 前端没有统一 axios error interceptor。
- API 超时 30 秒，对启动任务没问题，但对直接等待长请求不适合；目前长任务是异步启动，所以还可以。

### 13.3 Dashboard

展示：

- 任务总数。
- 正在执行。
- 合同未闭环。
- 高风险发现。
- 最近任务。
- Runner health。

Backend Overview 的 runnerHealth 是静态值：

- codeAudit ready
- browser planned
- pentest ready
- sandbox ready

这不是实时健康检测。生产化应改为真实 Runner 镜像/Docker/MinIO/DB 连通性检测。

### 13.4 Task Wizard

支持创建：

- code_audit
- pentest

UI 虽然后端支持 hybrid，但前端卡片只提供 code_audit/pentest，没有 hybrid 入口。

代码审计任务：

- 创建时不上传 ZIP。
- 创建后跳到任务详情页上传。

渗透任务：

- 要求至少一个 target。
- 创建后跳到详情页启动。

支持配置：

- Authorization Level 0-3。
- allowReadOnlyCommands。
- allowChainExploration。
- ModelConfig。

改进建议：

- code_audit 的“代码包说明/仓库信息”当前被拆成 targetText，但后端 targets 对 code_audit 不强制，这些信息可能丢失。建议写入 objective 或新增 repo metadata 字段。
- hybrid 没有 UI 入口。

### 13.5 Task List

功能：

- 状态筛选。
- 类型筛选。
- 关键词筛选。
- 显示测试任务。
- 显示已归档。
- 批量开始。
- 批量归档。
- 单任务归档。
- 每 5 秒刷新。

限制：

- 终止按钮 disabled，取消任务能力未实现。
- 过滤在前端完成，任务多时需要后端分页/过滤。
- 开始 failed 任务时，对 code_audit 如果 ZIP 缺失会返回后端错误。

### 13.6 Task Detail

这是前端最核心页面。

展示：

- 任务标题/目标。
- next step hint。
- ZIP 上传。
- 开始执行。
- 当前阶段。
- 关键证据数。
- Finding 数。
- ToolRun 数。
- 执行进度。
- 漏洞结果卡片。
- 报告产物。
- 复现交付说明。
- 执行时间线。
- Intent 队列。
- Contract 检查。
- 高级观察：ToolRun/Evidence/Blackboard。

优点：

- 把用户视角和审计链路区分得比较好。
- 默认突出 Finding 与报告，内部证据放在高级观察。
- running 状态会自动轮询。

风险与问题：

- `keyEvidenceForFinding` 与 `evidenceTypeLabel` 当前定义后未被模板使用，可能是历史遗留。
- `artifactUrl(ref)` 对 `minio://` 的 replace 实际不会移除 `minio://`，生成 `/artifacts/minio://bucket/key`。这与后端 artifact 路由的兼容逻辑匹配，但 URL 里包含 scheme 字符串，不够优雅。
- Evidence 原始链接直接使用 `item.artifactUrl`，这依赖后端 PublicURL 配置正确。

### 13.7 Finding Center

功能：

- 聚合近期任务 Finding。
- 按验证状态、Contract 状态、关键词过滤。
- 指标：总数、动态验证、合同未闭环、高风险。

限制：

- 只加载 `store.tasks.slice(0, 12)` 的任务详情。
- 没有独立后端 Finding 聚合接口。
- 没有跳转回任务详情或报告的操作。

### 13.8 Report Center

功能：

- 聚合近期任务报告。
- 打开 HTML/Markdown。
- 下载 HTML/Markdown。

限制：

- 只加载 `store.tasks.slice(0, 8)` 的任务详情。
- 没有全局报告分页接口。

### 13.9 Settings

功能：

- 模型配置 CRUD。
- 配置 Provider、Base URL、Model、API Key Ref。
- 配置 reviewModel、reasoning effort、wireApi、networkAccess、context window、auto compact token limit。
- 配置 disable response storage、requires OpenAI auth 等开关。

前后端不一致：

- 前端展示 Anthropic Compatible、Local Gateway。
- 后端当前只支持 OpenAI/OpenAI Compatible。

---

## 14. 部署与运行分析

### 14.1 Docker Compose

Compose 服务：

- postgres
- redis
- minio
- backend
- agent-worker
- frontend

backend volumes：

- `./workspace:/app/workspace`
- `./runner-images:/app/runner-images:ro`
- `/var/run/docker.sock:/var/run/docker.sock`

agent-worker volumes 同 backend。

frontend 使用 Nginx：

- `/` 静态文件。
- `/api/` 代理 backend。
- `/artifacts/` 代理 backend。
- `client_max_body_size 512m`，支持大 ZIP 上传。

### 14.2 当前运行状态

本次 `docker compose ps` 显示：

- backend 正在运行且 healthy。
- frontend 正在运行。
- postgres 正在运行且 healthy。
- redis 正在运行。
- minio 正在运行。
- agent-worker 正在运行。

端口映射符合 `.env.example` 的预期：

- frontend 13110
- backend 18190
- minio 19110/19111
- postgres 25440
- redis 16400

### 14.3 Runner 镜像

Runner Dockerfile：

- browser：Playwright noble 基础镜像，仅预留。
- code-audit：Alpine + git/ripgrep/python3/node/npm/go/php/jq/tree/ctags。
- pentest：`ai-security/kali-tools:latest`。
- report：Alpine + pandoc/python3。
- sandbox：Alpine + bash/python3/nodejs/go/php/openjdk17-jre。

注意：

- report runner 镜像存在，但报告生成当前在 Go 服务内完成，未走 report runner。
- browser runner 镜像存在，但未接入主链路。

---

## 15. Artifact 与 workspace 分析

### 15.1 Artifact Store

抽象接口：

- PutText
- PutBytes
- ReadText
- PublicURL

支持：

- LocalStore
- MinIOStore

MinIO ref 格式：

```text
minio://bucket/objectKey
```

Local ref 格式：

```text
local://relative/path
```

Artifact API 会根据 ref 读取对象，并按扩展名设置 content-type。

### 15.2 当前 workspace 状态

当前 workspace：

- 约 949 MB。
- 包含 53 个 task 目录。
- `workspace/artifacts` 下有 89 个文件。
- 历史产物包括 evidence、toolruns stdout/stderr、report md/html。

这表明项目已经被多次运行验证过，而且报告产物真实落盘。

建议：

- workspace 历史输入可能包含客户代码或敏感样本，不建议纳入版本控制。
- 增加清理策略，例如按任务归档后清理 input，保留 evidence/report。
- 增加 artifact retention 配置。
- 增加 workspace 空间使用监控。

---

## 16. 测试与验收分析

### 16.1 单元测试

当前测试文件：

- `backend/internal/runner/workspace_test.go`
- `backend/internal/safety/policy_test.go`
- `backend/internal/service/model_runtime_service_test.go`

覆盖内容：

- ZIP 解压阻断 traversal。
- ZIP 总大小限制。
- SafePolicy 允许只读 proof。
- SafePolicy 阻断破坏和持久化命令。
- SafePolicy 默认阻断 metadata。
- SafePolicy 显式授权 loopback。
- 模型 JSON 解析。
- API URL 拼接。
- Finding narrative guardrail。
- 报告 evidence 筛选。

本次执行：

```bash
cd backend && go test ./...
```

结果通过。

### 16.2 前端构建验证

本次执行：

```bash
cd frontend && npm run build
```

结果通过。

唯一警告：

- Rollup 对 `@vueuse/core` 中某些 `/* #__PURE__ */` 注释位置无法解释，会移除注释。该警告来自第三方依赖，不影响构建成功。

### 16.3 Smoke 脚本

脚本：`scripts/smoke-first-stage.sh`

验证内容：

代码审计：

- 创建测试任务。
- 创建并上传 smoke ZIP。
- 启动任务。
- 等待 completed。
- 断言多个 ToolRun。
- 断言 Evidence。
- 断言 Contract passed。
- 断言 dynamically_validated finding。
- 断言 code_search/sandbox_exec 有真实 containerId。
- 断言 Evidence/Report 存入 MinIO。

渗透验证：

- 创建 pentest 测试任务。
- 目标为 `http://host.docker.internal:18190/healthz`。
- 启动任务。
- 断言 http_request、response_diff、Evidence、Contract、Finding、MinIO。

注意：

- Smoke 脚本假设 backend 已运行。
- Smoke 脚本使用 jq、curl、zip。
- 默认执行结束会归档测试任务。

本次没有运行 smoke 脚本，因为它会创建新任务并触发 Runner 容器执行；但已有服务正在运行，脚本本身逻辑完整。

---

## 17. 安全性评估

### 17.1 已有安全设计

项目已经具备较多安全意识：

- 授权范围 SafePolicy。
- Target 默认阻断内网、metadata、loopback，除非显式授权。
- Payload/Command 阻断破坏、持久化、反弹 shell。
- 只读命令 proof 需 Level 1+。
- ZIP 解压防 Zip Slip。
- ZIP 文件数/大小限制。
- Runner 容器隔离执行。
- code-audit Runner 无网络。
- 输入源码只读挂载。
- Evidence 脱敏。
- Finding 报告措辞 guardrail。
- Contract 不完整时不强确认。
- 服务启动时 running task fail-closed。

### 17.2 高优先级安全风险

#### 风险 1：缺少认证与授权

当前所有 API 都没有认证。任何能访问后端的人都可以：

- 创建任务。
- 上传 ZIP。
- 启动 Runner。
- 访问 artifact。
- 查看 evidence。
- 修改模型配置。
- 归档任务。
- 审核 Finding。

这是生产上线前必须补齐的能力。

建议：

- 加入登录认证。
- API 加 JWT/session 中间件。
- Artifact API 做任务级授权校验。
- 引入用户、角色、工作区权限。
- 区分管理员、审计员、只读查看者。

#### 风险 2：Docker socket 挂载权限过大

backend 和 agent-worker 都挂载 `/var/run/docker.sock`。拥有 Docker socket 基本等于拥有宿主机 root 等级能力。

建议：

- 生产环境将 Runner 平面隔离到专用机器。
- API 服务不直接挂 Docker socket，通过受限 Runner service 调度。
- 使用 rootless Docker、gVisor、Kata、Firecracker 或 Kubernetes Job + PSP/PSA 策略。
- 禁止 fallback local exec。
- 对 Runner 镜像做签名与固定 digest。

#### 风险 3：Artifact 访问缺少权限校验

`GET /artifacts/*filepath` 可读取 MinIO/local 产物。虽然需要知道 ref，但 ref 会出现在 API 返回里，缺少鉴权时风险很大。

建议：

- Artifact 下载走授权校验。
- 对 report 可生成短期签名 URL。
- Evidence 原始材料默认只允许管理员/任务拥有者访问。

#### 风险 4：默认弱凭据

Compose 中存在默认：

- PostgreSQL 用户密码：shenji/shenji。
- MinIO 用户密码：minioadmin/minioadmin。

建议：

- 生产环境启动时强制校验默认密码不可用。
- `.env.example` 明确标注仅开发使用。
- 密钥通过 secret manager 注入。

### 17.3 中优先级安全风险

- SafePolicy 不能处理所有 DNS rebinding 与跳转场景。
- pentest runner bridge 网络没有容器级 egress allowlist。
- 前端 Settings 允许保存 API key ref，若用户填明文会进数据库。
- Model Base URL 可配置，存在服务端主动请求外部地址的 SSRF/数据外发风险，需要管理员权限与 allowlist。
- Report HTML 直接展示由模型生成的内容，虽然使用 html.EscapeString 较多，但需要持续审计所有插入点。

---

## 18. 工程质量评估

### 18.1 优点

1. 领域模型完整  
   Task、Intent、ToolRun、Evidence、Finding、Contract、Report、AuditEvent 都有独立表，结构清晰。

2. 执行链路可追溯  
   每个工具执行都有输入、输出、容器、状态、stdout/stderr、证据引用。

3. 安全意识强  
   SafePolicy、ZIP 安全解压、Runner 隔离、证据脱敏、报告措辞 guardrail 都已实现。

4. 模型失败可回退  
   不会因为模型不可用就打断第一阶段闭环。

5. 报告能力超出 MVP  
   Markdown/HTML 报告结构完整，且强调可复现材料。

6. 前端产品闭环完整  
   从任务创建、上传、启动、查看详情、报告下载到模型设置都有界面。

### 18.2 主要工程问题

1. Orchestrator 过大  
   单文件约 2300 行，包含流程控制、代码审计、渗透验证、模型推理、Finding 生成、Evidence 选择等大量职责。

2. 缺少事务  
   多步落库操作失败可能留下部分状态。

3. Worker 未真正工作  
   当前 Agent 执行在 API goroutine 中。

4. 缺少认证授权  
   生产不可接受。

5. 测试覆盖不足  
   现有测试偏基础设施，缺少 API/service/tool/report 主要路径测试。

6. 前后端能力不一致  
   后端支持 hybrid，前端没有入口；前端 provider 选项多于后端支持。

7. 聚合页不具备分页  
   Findings/Reports 只聚合前 12/8 个任务。

8. 部分配置与代码硬编码  
   例如 runner health 静态、特定项目路径优先级、报告模板硬编码在 Go 文件中。

---

## 19. 性能与可扩展性评估

### 19.1 当前性能特点

- 任务是异步 goroutine 执行。
- 每个工具调用创建一个容器。
- code_search 可限制 maxHits。
- code_slice 可限制 snippet 数。
- 模型深度审计按 batch 执行。
- 黑板图输入限制 nodes/edges/snippets 数量，避免 prompt 过大。

### 19.2 潜在瓶颈

- 每个工具执行构建/启动容器，冷启动较重。
- 如果 Runner 镜像不存在，执行时动态构建，首次任务耗时长。
- Agent 在 API 进程内执行，任务多时影响 API 服务稳定。
- Findings/Reports 前端聚合通过逐个拉任务详情，任务多时会产生 N+1 请求。
- ReportService 每次生成重新读取所有 evidence/toolRuns，数据量大时会变慢。
- GORM AutoMigrate 每次启动执行，生产环境不推荐。

### 19.3 扩展建议

- 引入任务队列：Redis Stream、PostgreSQL advisory lock、NATS 或 RabbitMQ。
- Agent Worker 真正消费任务。
- Runner service 独立部署。
- 为 list findings/reports 提供后端分页接口。
- Artifact 元数据分页。
- 黑板图查询增加索引与分页。
- Runner 镜像预构建，不在请求路径构建。
- 对大型 ZIP 做异步上传/解压进度。

---

## 20. 生产化差距清单

上线前必须补：

1. 用户认证与权限控制。
2. Artifact 权限校验。
3. Docker socket 风险隔离。
4. Secret 管理和默认弱密码治理。
5. 真实 worker/队列/锁。
6. 数据库迁移工具替代 AutoMigrate。
7. API 输入校验和错误规范化。
8. 审计日志不可抵赖与操作人记录。
9. Runner 网络 egress allowlist。
10. 任务取消/超时/清理机制。

上线前强烈建议补：

1. 后端分页与过滤接口。
2. Findings/Reports 全局查询接口。
3. Browser runner 接入。
4. PDF/Word/evidence pack 导出。
5. 更完整的端到端测试。
6. 模型输出 schema 校验。
7. OpenAPI 文档。
8. 观测指标：任务耗时、Runner 成功率、模型延迟、artifact 大小。
9. workspace retention。
10. 代码审计策略配置化。

---

## 21. 推荐迭代路线图

### 21.1 第一优先级：生产安全底座

目标：让平台从本地演示变成可控内网服务。

任务：

- 增加认证中间件。
- 增加用户/角色/工作区模型。
- Artifact API 增加任务权限校验。
- 禁止未认证访问模型配置。
- 默认弱口令启动校验。
- 生产环境禁用 fallback local exec。
- 记录 CreatedBy/Actor 为真实用户。

### 21.2 第二优先级：任务调度架构

目标：把 API 与 Agent 执行解耦。

任务：

- 引入任务队列。
- Agent Worker 消费 pending/running task。
- 使用 lease/lock 防止重复执行。
- 支持取消任务。
- 支持任务重试策略。
- 支持 Worker 心跳与真实健康检查。

### 21.3 第三优先级：Runner 安全与能力

目标：让工具执行平面安全可扩展。

任务：

- Runner service 独立部署。
- 镜像固定 digest 与签名。
- 网络 egress allowlist。
- Browser runner 接入。
- Report runner 接入 PDF/Word。
- Runner 资源限制配置化。

### 21.4 第四优先级：报告交付增强

目标：提高客户交付质量。

任务：

- PDF 导出。
- Word 导出。
- Evidence pack zip。
- 报告编号、目录、页眉页脚。
- 报告模板拆分。
- 支持多语言模板。
- 支持人工 review 后再出正式版。

### 21.5 第五优先级：体验与运营

目标：让团队长期使用顺手。

任务：

- Findings 全局分页接口。
- Reports 全局分页接口。
- 任务详情中 Evidence/ToolRun 分页与搜索。
- 模型调用成本/耗时统计。
- Runner health 真实探测。
- workspace 清理 UI。
- smoke 任务独立视图。

---

## 22. 重点文件速查

后端入口：

- `backend/cmd/api/main.go`
- `backend/cmd/worker/main.go`

API：

- `backend/internal/api/router.go`
- `backend/internal/api/handler.go`

配置与数据库：

- `backend/internal/config/config.go`
- `backend/internal/database/database.go`
- `backend/internal/model/models.go`
- `backend/internal/model/constants.go`

核心服务：

- `backend/internal/service/task_service.go`
- `backend/internal/service/agent_orchestrator.go`
- `backend/internal/service/model_runtime_service.go`
- `backend/internal/service/contract_service.go`
- `backend/internal/service/report_service.go`
- `backend/internal/service/toolrun_service.go`
- `backend/internal/service/evidence_service.go`
- `backend/internal/service/blackboard_service.go`
- `backend/internal/service/context_builder.go`

Runner 与安全：

- `backend/internal/runner/manager.go`
- `backend/internal/runner/docker_client.go`
- `backend/internal/runner/workspace.go`
- `backend/internal/safety/policy.go`
- `backend/internal/safety/redactor.go`

工具：

- `backend/internal/tools/code_search.go`
- `backend/internal/tools/code_slice.go`
- `backend/internal/tools/pentest_probe.go`
- `backend/internal/tools/http_request.go`
- `backend/internal/tools/http_surface.go`
- `backend/internal/tools/response_diff.go`
- `backend/internal/tools/sandbox_exec.go`

前端：

- `frontend/src/api/client.ts`
- `frontend/src/router/index.ts`
- `frontend/src/stores/platform.ts`
- `frontend/src/views/DashboardView.vue`
- `frontend/src/views/TaskWizardView.vue`
- `frontend/src/views/TaskListView.vue`
- `frontend/src/views/TaskDetailView.vue`
- `frontend/src/views/FindingCenterView.vue`
- `frontend/src/views/ReportCenterView.vue`
- `frontend/src/views/SettingsView.vue`

部署：

- `docker-compose.yml`
- `.env.example`
- `backend/Dockerfile`
- `frontend/Dockerfile`
- `frontend/nginx.conf`
- `runner-images/*/Dockerfile`

验收：

- `scripts/smoke-first-stage.sh`
- `scripts/archive-smoke-tasks.sh`

---

## 23. 本次验证记录

已执行：

```bash
cd backend && go test ./...
```

结果：通过。

已执行：

```bash
cd frontend && npm run build
```

结果：通过。

构建警告：

- `@vueuse/core` 中 PURE 注释位置 Rollup 无法解释，构建会移除注释。这是第三方依赖警告，不影响构建产物生成。

已执行：

```bash
docker compose ps
```

结果：

- backend up 且 healthy。
- frontend up。
- postgres up 且 healthy。
- redis up。
- minio up。
- agent-worker up。

---

## 24. 结论

Rabbit 项目当前已经具备一个安全验证平台第一阶段最重要的东西：真实闭环。它不是只做了页面，也不是只做了工具调用，而是把任务、授权、工具、证据、图推理、漏洞发现、Contract、报告和审计事件连接起来了。这个方向是正确的，而且代码里已经能看出非常强的产品意识：不把工具输出直接包装成漏洞，不用置信度替代证据，不在报告里过度确认，没有证据就生成补证据 intent。

如果只看“本地演示/第一阶段验收”，项目已经相当完整。  
如果看“生产上线/多用户使用”，还需要补认证授权、队列 Worker、Runner 隔离、迁移体系、分页接口、测试覆盖和交付格式。

最建议下一步做法：

1. 先补认证授权和 Artifact 权限，避免平台自身成为高风险入口。
2. 把 agent-worker 做成真实任务消费者，API 不再直接跑 Agent。
3. 把 Runner 执行平面从后端进程中解耦，降低 Docker socket 风险。
4. 补全 Browser runner、PDF/Word/evidence pack，让报告交付闭环更完整。
5. 将 Orchestrator 拆分为 code audit executor、pentest executor、graph reasoner、finding builder，降低长期维护成本。

总体评价：这是一个方向清晰、闭环完整、工程意识较强的 AI 安全验证平台雏形。它已经有“系统”的骨架和血管，下一阶段重点应该从“跑通”转向“安全、稳定、可维护、可运营”。
