# Rabbit AI Security Validation Platform — 系统架构文档

## 1. 项目概述

Rabbit 是一个 AI 原生安全状态空间探索平台。基于大模型 Agent、黑板架构、状态空间搜索和 Docker 隔离执行，从已有 Fact 出发生成 Intent，执行 Explore，再把新 Evidence / Fact 写回图中。

**核心理念：**
- Rabbit is not a scanner.
- Rabbit is not a CVE/PoC search engine.
- Rabbit is not a report-first vulnerability formatter.
- Rabbit is a Cairn-style state-space exploration system.
- 工具只负责观察和验证。
- Finding 是交付产物，不是探索驱动力。
- Contract 是报告质量闸门，不是主规划器。
- Report 是最终输出，不是主循环。
- 图探索闭环才是产品核心。

核心闭环：

```text
Fact / Observation / Evidence
→ Hypothesis / Intent
→ Runner / Explore
→ Evidence / New Fact
→ Capability / NegativeFact / UnverifiedRisk
→ Next Intent
```

---

## 2. 技术栈

| 层级 | 技术 |
|---|---|
| 后端 | Go 1.25 / Gin / GORM / PostgreSQL / Redis / MinIO |
| 前端 | Vue 3 / TypeScript / Element Plus / Vite / Pinia |
| 执行层 | Docker SDK / 动态 Runner 容器 |
| 模型层 | OpenAI-compatible API（支持 Claude/GLM/GPT 等） |
| 部署 | Docker Compose 一键启动 |

---

## 3. 系统架构

```
┌─────────────────────────────────────────────────────────┐
│  Frontend (Vue 3 + Element Plus)                         │
│  - Dashboard / Task Wizard / Finding Center / Reports    │
│  - AI Chat / Model Logs / User Management / Audit Log    │
└──────────────────────────┬──────────────────────────────┘
                           │ HTTP API
┌──────────────────────────▼──────────────────────────────┐
│  Backend API (Gin)                                       │
│  - Auth (JWT) / Task CRUD / Model Config / Chat          │
│  - Report Generation / Evidence / Finding / Contract     │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│  Agent Worker (Agent Orchestrator)                        │
│  - Cairn Loop (Fact → Intent → Explore → Fact)            │
│  - Blackboard Graph (Fact/Evidence/Hypothesis/Intent)     │
│  - Model Runtime Service (多模型抽象)                     │
│  - Context Builder / Blackboard Compactor                │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│  Tool Registry & Runners                                 │
│  - code_search / code_slice (runner-code-audit)          │
│  - http_request / pentest_probe (runner-pentest)         │
│  - fingerprint / response_diff                           │
│  - sandbox_exec (runner-sandbox)                         │
│  - response_diff / report_assembler                      │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│  Infrastructure                                          │
│  - PostgreSQL (数据持久化)                                │
│  - Redis (队列/缓存)                                     │
│  - MinIO (Artifact 存储)                                 │
│  - Docker SDK (动态容器管理)                              │
└─────────────────────────────────────────────────────────┘
```

---

## 4. 核心数据模型

| 模型 | 用途 |
|---|---|
| AIUser | 用户认证 |
| AISecurityTask | 安全验证任务 |
| AIWorkspace | 隔离工作区 |
| AITaskTarget | 授权目标 |
| AIAgentLoop / Iteration | Agent 执行循环 |
| AIBlackboardNode / Edge | 黑板图（Fact/Intent/Evidence） |
| AIIntent | 探索意图 |
| AIToolRun | 工具执行记录 |
| AIEvidence | 证据 |
| AIFinding | 漏洞发现 |
| AIContractCheckResult | 交付质量检查 |
| AIReport | 报告 |
| AIModelConfig | 模型配置 |
| AIModelCallLog | 模型调用日志 |
| AIAuditEvent | 审计事件 |

---

## 5. Agent 执行流程

### 5.1 代码审计流程

```
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
  - code_trace / dataflow_trace / inspect_auth_boundary
  - inspect_owner_check / validate_candidate_path
  ↓
Runner / ToolRun
  - code_search / code_slice / dataflow_trace
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

### 5.2 渗透测试流程

```
创建任务 → 输入授权目标
  ↓
Bootstrap Observation
  - 创建 origin / goal
  - 写入 target / scope / safe policy
  ↓
Recon / Fingerprint
  - http_surface / http_request / response_diff
  - fingerprint (组件/版本识别)
  - 只写入 EnvironmentModel / Blackboard Fact / Evidence
  - 不触发外部漏洞数据库或公开验证包查询
  ↓
Hypothesis Formation
  - 根据页面、接口、参数、身份、响应差异、环境信息形成 Hypothesis
  ↓
ValidationIntent
  - http_request / response_diff / auth_boundary_test
  - idor_test / state_transition_test / business_logic_test
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

### 5.3 循环终止条件

- no meaningful graph expansion in N rounds
- no new high-value Hypothesis / Intent
- no new Capability
- no pending high-value Intent
- budget exhausted
- explicit terminal goal completed
- safety policy requires stop

Finding 数量不能作为主要终止依据。

---

## 6. 安全策略 (SafePolicy)

**只禁止破坏性命令：**
- rm / rmdir / del / format / mkfs / dd

**允许所有验证性操作：**
- whoami / id / hostname / ifconfig / ipconfig / pwd
- echo marker / printf marker
- HTTP 请求 / 响应差异对比
- marker 文件上传（PHP/JSP/ASPX hello world）
- SQL SELECT 查询
- 反序列化只读命令证明

---

## 7. 模型调用策略（Cairn 式小步快跑）

**核心原则：每次模型调用 prompt < 6000 字符，响应 < 30s**

| 调用类型 | Prompt 大小 | 预期响应时间 |
|---|---|---|
| 迭代规划 (plan) | ~1000 字符 | 3-6s |
| 图推理 (graph_reasoning) | ~3000 字符（8 节点 + 15 边 + 6 片段×600 字符） | 10-20s |
| 代码审计 (code_audit) | ~5000 字符（3 片段×1500 字符） | 10-20s |
| 报告生成 (report_narrative) | ~2000 字符 | 5-10s |
| AI 对话 (chat) | ~1500 字符 | 2-5s |

**超时设置：**
- 模型调用：300s
- 前端 axios：120s
- Nginx proxy_read_timeout：120s

---

## 8. 工具注册表

| 工具名 | 类型 | 用途 |
|---|---|---|
| code_search | code_audit | ripgrep 正则搜索安全 pattern |
| code_slice | code_audit | 提取文件代码片段 |
| http_request | pentest | HTTP 请求执行 |
| http_surface | pentest | HTTP 攻击面发现 |
| pentest_probe | pentest | Kali 式信息收集 |
| fingerprint | pentest | 组件/版本指纹识别 |
| response_diff | pentest | HTTP 响应差异对比 |
| sandbox_exec | sandbox | 沙箱命令执行 |
| report_assembler | report | 报告组装 |

---

## 9. 前端页面

| 页面 | 路由 | 功能 |
|---|---|---|
| 登录 | /login | JWT 认证 |
| 工作台 | / | 任务总览/指标/最近任务 |
| 任务列表 | /tasks | 筛选/启动/归档/删除/重跑 |
| 创建任务 | /tasks/new | 向导式任务创建 |
| 任务详情 | /tasks/:id | 进度/Finding/Evidence/报告/时间线 |
| 漏洞产出 | /findings | 漏洞列表（按严重程度排序） |
| 漏洞详情 | /findings/:id | 报告式三列布局 |
| 报告管理 | /reports | 报告列表/下载 HTML/Markdown/CSV |
| 模型配置 | /settings | 模型 CRUD/测试连接 |
| 用户管理 | /users | 新建/编辑/禁用/重置密码 |
| 操作日志 | /audit-log | 审计事件查询 |
| 模型日志 | /model-logs | 模型调用记录（耗时/状态/tokens） |
| AI 助手 | 右下角浮窗 | 全局对话/任务上下文对话 |

---

## 10. Docker Compose 服务

| 服务 | 端口 | 说明 |
|---|---|---|
| frontend | 13110 | Nginx + Vue SPA |
| backend | 18190 | Go API 服务 |
| agent-worker | - | Agent 执行 Worker |
| postgres | 25440 | 数据库 |
| redis | 16400 | 缓存/队列 |
| minio | 19110/19111 | 对象存储 |

---

## 11. 环境变量

```env
# 核心配置
DATABASE_DSN=host=postgres user=shenji password=shenji dbname=shenji port=5432
REDIS_ADDR=redis:6379
MINIO_ENDPOINT=minio:9000

# Agent 预算
MAX_ITERATIONS=30
MAX_RUNTIME_MINUTES=60
MAX_TOOL_RUNS=60
MAX_PENDING_INTENTS=40
MODEL_TIMEOUT_SECONDS=90
TOOL_TIMEOUT_SECONDS=180

# 认证
JWT_SECRET=rabbit-shenji-change-this-in-production
```

---

## 12. 已修复的关键问题

| 问题 | 根因 | 修复 |
|---|---|---|
| 模型 JSON 解析失败丢弃全部结果 | required_evidence 类型不匹配 | lenient 解析器 |
| reasoning_effort 被强制降为 low | codeAuditReasoningEffort 函数 bug | 保持用户配置值 |
| 模型超时 (Cloudflare 524) | prompt 太长 (25000+ 字符) | Cairn 式小步快跑 (< 6000 字符) |
| PostgreSQL UTF-8 错误 | 模型返回非法字节序列 | GORM 全局 callback 清理 |
| 代码审计覆盖不全 | 随机取片段，大量文件未分析 | 文件级索引 + 逐文件 Intent |
| 预算耗尽报错 | max_iterations 硬失败 | 正常收束生成报告 |
| 模型不可用时无 Finding | 完全依赖模型 | 确定性 Source+Sink 共现生成器 |

---

## 13. 启动方式

```bash
cp .env.example .env
docker compose up -d --build
```

访问：http://localhost:13110
账号：admin / admin123

---

## 14. 后续规划

| 优先级 | 功能 |
|---|---|
| P2 | Dashboard 图表（ECharts） |
| P2 | 通知/消息中心 |
| P2 | PDF/Word 报告导出 |
| P3 | Browser Runner（Playwright） |
| P3 | 多 Worker 并行探索 |
| P3 | 更高级的状态空间搜索 |
