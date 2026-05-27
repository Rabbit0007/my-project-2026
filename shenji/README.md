# Rabbit AI Security Validation Platform

Rabbit 是一个 AI 原生安全验证平台的第一阶段实现。当前版本已经不是只有骨架，而是具备真实可运行的最小闭环：

- 上传代码，自动审计
- 输入授权范围，自动验证
- 证据真实落库
- 报告可导出、可回溯、可交付

Rabbit 不是扫描器。Rabbit 不是 CVE/PoC 搜索器。Rabbit 不是报告优先的漏洞格式化系统。Rabbit 是 Cairn-style 状态空间探索系统。

核心闭环是：

```text
Fact / Observation / Evidence
-> Hypothesis / Intent
-> Runner / Explore
-> Evidence / New Fact
-> Capability / NegativeFact / UnverifiedRisk
-> Next Intent
```

工具只负责观察和验证。Finding 是交付产物，不是探索驱动力。Contract 是报告质量闸门，不是主规划器。Report 是最终输出，不是主循环。图探索闭环才是产品核心。

## 当前交付状态

当前项目已经达到“可演示、可验收、可导出报告”的第一阶段交付状态：

- 前端可访问，任务创建 / 上传 ZIP / 启动 / 查看详情 / 查看报告都可用
- 后端健康检查正常
- code-audit / pentest / sandbox runner 都是 Docker 动态执行
- ToolRun / Evidence / Contract / Report 都是真实落库和真实产物
- Artifact 已进入 MinIO
- 报告支持 Markdown / HTML，且已提升为正式交付版式
- 模型配置支持真实 CRUD
- 任务可绑定模型配置，模型已参与 iteration planning 与缺字段补证据 intent 生成
- 模型调用可观测，时间线可显示 `agent.model_plan` / `agent.model_fallback`
- 模型不可用时会自动回退到 deterministic runtime，不会直接打坏闭环

## 启动

```bash
cp .env.example .env
docker compose up -d
```

如果是首次构建，建议直接使用：

```bash
docker compose up -d --build
```

默认配置直连 Docker Hub，并使用完整镜像名，便于复用本地已拉取镜像。

如果 Docker Desktop 在 `docker build` 阶段偶发卡在 `auth.docker.io/token`，可以先预拉取基础镜像，再执行构建：

```bash
docker pull docker.io/library/golang:1.25-alpine
docker pull docker.io/library/alpine:3.21
docker pull docker.io/library/node:25-alpine
docker pull docker.io/library/nginx:1.27-alpine
docker compose build
```

这能让 BuildKit 直接复用本地已解析的镜像摘要，减少再次访问 Docker Hub token 接口的概率。

如果某次网络不稳定，可以在 `.env` 中把镜像变量切到国内镜像站，例如：

```text
POSTGRES_IMAGE=m.daocloud.io/docker.io/library/postgres:16-alpine
REDIS_IMAGE=m.daocloud.io/docker.io/library/redis:7-alpine
MINIO_IMAGE=m.daocloud.io/docker.io/minio/minio:RELEASE.2025-01-20T14-49-07Z
GO_BASE_IMAGE=m.daocloud.io/docker.io/library/golang:1.25-alpine
ALPINE_BASE_IMAGE=m.daocloud.io/docker.io/library/alpine:3.21
NODE_BASE_IMAGE=m.daocloud.io/docker.io/library/node:25-alpine
NGINX_BASE_IMAGE=m.daocloud.io/docker.io/library/nginx:1.27-alpine
```

这样我们可以按镜像逐个切换，不需要把整个项目绑死在某一个镜像前缀上。

当前默认访问：

```text
前端: http://localhost:13110
后端: http://localhost:18190
```

后端健康检查：

```text
http://localhost:18190/healthz
```

MinIO：

```text
API: http://localhost:19110
Console: http://localhost:19111
```

推荐演示入口：

- 任务工作台：`http://localhost:13110`
- 新建任务：`http://localhost:13110/tasks/new`
- 报告中心：`http://localhost:13110/reports`
- 系统设置 / 模型配置：`http://localhost:13110/settings`

## 第一阶段能力

- 创建代码审计、渗透验证或混合任务。
- 代码审计任务支持 ZIP 上传，并进行 zip slip、路径穿越、文件数量和大小限制检查。
- Agent 运行时会创建 Loop/Iteration，围绕 Intent 调用注册工具，并持久化 ToolRun / Evidence / Contract / Report。
- SafePolicy 默认允许授权的只读证明，阻断破坏、持久化和出范围动作。
- Finding 不使用置信度作为结论依据，Contract incomplete 会降级并生成补证据 Intent。
- 报告支持 Markdown + HTML，并根据 Finding 状态控制措辞。
- 模型配置支持真实 CRUD，任务创建时可选择已保存模型配置。
- 前端面向用户展示任务、证据和报告，复杂黑板信息仅放在高级观察区。

## 当前真实执行面

- `code_search` / `code_slice` 通过 `runner-code-audit` Docker 动态容器执行。
- `sandbox_exec` 通过 `runner-sandbox` Docker 动态容器执行。
- `http_request` 通过 `runner-pentest` Docker 动态容器执行。
- `response_diff` 在平台内完成结构化对比并生成证据。
- `Evidence`、`ToolRun stdout/stderr`、`Report` 会进入 MinIO，并以 `minio://...` 形式引用。
- 前端任务详情可查看真实 `ToolRun`、`Evidence`、`Intent`、`Contract Check`、`Report`。
- 前端任务详情时间线可查看模型事件：
  - `agent.model_plan`
  - `agent.model_fallback`

## 重要说明

当前不追求完整的高级搜索、复杂多 Worker 涌现、固定漏洞模板或外部 PoC 仓库，而是把状态空间探索闭环补完整：

- 代码审计闭环
  创建任务 -> 上传 ZIP -> 安全解压 -> Bootstrap Observation -> code_search/code_slice 产生 Observation/Evidence -> Source/Sink/EntryPoint/AuthBoundary 写入 Blackboard Fact -> Hypothesis Formation -> ValidationIntent -> Runner -> Evidence -> Capability / NegativeFact / UnverifiedRisk -> DynamicIntentExpander -> StateExpansionPlanner + ExplorationBudgetManager -> Finding / Contract / Report
- 渗透验证闭环
  创建任务 -> 授权目标 -> Bootstrap Observation -> Recon/Fingerprint 写入 EnvironmentModel / Blackboard Fact / Evidence -> Hypothesis Formation -> ValidationIntent -> http_request / response_diff / behavior_probe -> Evidence -> Capability / NegativeFact / UnverifiedRisk -> DynamicIntentExpander -> StateExpansionPlanner + ExplorationBudgetManager -> Finding / Contract / Report

硬性边界：

- `code_search` 是 Observation 工具。
- `code_slice` 是 Evidence 工具。
- Source/Sink/pattern hit 不是漏洞结论。
- fingerprint 只是 Observation / EnvironmentModel signal。
- fingerprint 不触发外部 PoC，不直接生成 Finding，不直接生成 Capability。
- Finding 只能来自 evidence-backed validated Hypothesis / Capability / reproducible validation path。
- Contract 只能检查交付质量、降级不完整 Finding、记录补证据缺口，不能替代 Reasoner / DynamicIntentExpander。

当前还没有完全进入真实链路的是：

- `browser runner`
- PDF / Word / evidence package 导出
- 更高级的开放式状态空间搜索与多 Worker 协作

当前已经刻意不作为第一阶段前台主流程强调的：

- human review 治理动作
- 固定漏洞模板化扫描
- 规则驱动批量漏洞清单
- CVE/PoC 搜索主线
- 报告优先的漏洞格式化流程

## Smoke 验收

一键验证第一阶段代码审计和渗透验证两条真实闭环：

```bash
bash scripts/smoke-first-stage.sh
```

脚本会自动：

- 创建测试任务
- 上传代码审计 ZIP
- 启动代码审计与渗透验证任务
- 轮询直到任务结束
- 断言 ToolRun / Evidence / Contract / Report 关键结果
- 断言 code-audit / sandbox / pentest runner 的真实容器执行
- 断言关键 Evidence 与 Report 存入 MinIO
- 成功后自动归档测试任务

如果你想验证模型不可用时的自动回退能力，可以另外创建一条指向不可用 base URL 的模型配置，再观察任务详情时间线中的：

- `agent.model_fallback`

如果你之前手工跑过多轮 smoke，想把历史测试任务从正式视图里清掉：

```bash
bash scripts/archive-smoke-tasks.sh
```

## 模型配置

当前系统设置页的模型配置已经接入真实后端接口：

- `GET /api/v1/model-configs`
- `POST /api/v1/model-configs`
- `PATCH /api/v1/model-configs/:id`

推荐把密钥写成环境变量引用，例如：

```text
env://OPENAI_API_KEY
```

然后在任务创建页选择已保存模型配置。

当前已经验证过的一条 OpenAI 兼容配置形式：

```toml
model_provider = "OpenAI"
model = "gpt-5.4"
review_model = "gpt-5.4"
model_reasoning_effort = "xhigh"
disable_response_storage = true
network_access = "enabled"
model_context_window = 1000000
model_auto_compact_token_limit = 900000

[model_providers.OpenAI]
name = "OpenAI"
base_url = "http://103.18.229.74:8080"
wire_api = "responses"
requires_openai_auth = true
```

在平台里对应保存为：

- `provider = OpenAI`
- `baseUrl = http://103.18.229.74:8080`
- `model = gpt-5.4`
- `apiKeyRef = env://OPENAI_API_KEY`

## 验收命令

```bash
docker compose ps
curl http://localhost:18190/healthz
cd backend && go test ./...
cd ../frontend && npm run build
bash scripts/smoke-first-stage.sh
```

## 演示建议

建议按下面顺序演示：

1. 打开工作台，展示任务列表和系统状态
2. 新建代码审计任务
3. 上传 ZIP 并启动
4. 在任务详情页展示：
   - Finding
   - Evidence
   - ToolRun
   - Contract Check
   - 模型调用时间线
5. 打开 Markdown / HTML 报告
6. 切到系统设置页展示模型配置

## 当前我认为最值得的下一步

如果后续继续做第二阶段之前的精修，我建议优先顺序是：

1. `browser runner`
2. PDF / Word 报告导出
3. 更成熟的报告目录 / 打印样式 / 编号体系
4. 更高级的开放式状态空间搜索与多 Worker 协作
