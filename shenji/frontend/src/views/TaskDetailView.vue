<template>
  <section v-if="detail">
    <div class="page-header">
      <div>
        <p class="eyebrow">任务详情</p>
        <h1 class="page-title">{{ detail.task.name }}</h1>
        <p class="subcopy">{{ detail.task.objective }}</p>
        <el-alert
          v-if="nextStepHint"
          style="margin-top: 14px"
          type="info"
          :closable="false"
          show-icon
          :title="nextStepHint"
        />
      </div>
      <div style="display: flex; gap: 10px">
        <el-upload
          v-if="isAdmin && detail.task.taskType !== 'pentest'"
          :show-file-list="false"
          :auto-upload="false"
          accept=".zip"
          :before-upload="beforeUpload"
          @change="handleUpload"
          @error="handleUploadError"
        >
          <el-button :loading="uploading">上传 ZIP</el-button>
        </el-upload>
        <el-button v-if="isAdmin" type="primary" :loading="starting" :disabled="detail.task.status === 'running'" @click="startTask">
          开始执行
        </el-button>
      </div>
    </div>

    <div class="metric-grid">
      <div class="glass-card metric-card">
        <span>当前阶段</span>
        <strong style="font-size: 24px">{{ detail.task.progressStage }}</strong>
      </div>
      <div class="glass-card metric-card metric-card--elapsed">
        <span>运行时长</span>
        <strong>{{ elapsedTimeLabel }}</strong>
      </div>
      <div class="glass-card metric-card">
        <span>关键证据</span>
        <strong>{{ keyEvidence.length }}</strong>
      </div>
      <div class="glass-card metric-card">
        <span>报告漏洞</span>
        <strong>{{ reportableFindings.length }}</strong>
      </div>
      <div class="glass-card metric-card">
        <span>ToolRun</span>
        <strong>{{ detail.toolRuns.length }}</strong>
      </div>
    </div>

    <div class="glass-card section-card" style="margin-top: 16px">
      <div class="section-title">
        <h2>执行进度</h2>
        <StatusPill :status="detail.task.status" />
      </div>
      <el-progress :percentage="detail.task.progressPercent" :stroke-width="14" />
    </div>

    <div class="content-grid">
      <div class="glass-card section-card">
        <div class="section-title">
          <h2>漏洞报告</h2>
          <span class="quiet">点击查看漏洞证明、影响链路和修复建议</span>
        </div>
        <el-empty v-if="reportableFindings.length === 0" description="暂无可交付漏洞" />
        <div v-else class="finding-report-stack">
          <article
            v-for="finding in reportableFindings"
            :key="finding.id"
            class="finding-report-preview"
            :class="`severity-${finding.severity}`"
            @click="openFinding(finding)"
          >
            <div class="finding-report-preview__header">
              <span :class="`severity-chip ${finding.severity}`">{{ severityLabel(finding.severity) }}</span>
              <h3>{{ finding.title }}</h3>
            </div>
            <p>{{ proofSummary(finding) }}</p>
            <div class="finding-report-preview__grid">
              <div>
                <label>漏洞类型</label>
                <strong>{{ finding.vulnerabilityType }}</strong>
              </div>
              <div>
                <label>验证端点</label>
                <strong>{{ proofDetail(finding, 'proof_endpoint') }}</strong>
              </div>
              <div>
                <label>成功判定</label>
                <strong>{{ proofDetail(finding, 'success_criteria') }}</strong>
              </div>
            </div>
            <footer>
              <span>证据 {{ linkedEvidence(finding).length }} 条</span>
              <span>执行记录 {{ linkedToolRuns(finding).length }} 条</span>
              <button type="button">查看漏洞详情</button>
            </footer>
          </article>
        </div>
      </div>

      <!-- Capabilities Section -->
      <div v-if="capabilities.length > 0" class="glass-card section-card">
        <div class="section-title">
          <h2>已获得能力</h2>
          <span class="quiet">{{ capabilities.length }} 项能力</span>
        </div>
        <div class="timeline">
          <div v-for="cap in capabilities" :key="cap.id" class="timeline-item" :class="'cap-' + cap.strength">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px">
              <el-tag :type="capStrengthType(cap.strength)" size="small">{{ cap.strength }}</el-tag>
              <strong>{{ cap.capabilityType }}</strong>
            </div>
            <span class="quiet">{{ cap.target }}</span>
            <p v-if="cap.proofSummary" style="margin: 4px 0 0; font-size: 12px; color: var(--text-secondary)">{{ cap.proofSummary }}</p>
          </div>
        </div>
      </div>

      <div class="glass-card section-card">
        <div class="section-title">
          <h2>报告产物</h2>
          <span class="quiet">{{ detail.reports.length }} 份</span>
        </div>
        <div class="timeline">
          <div v-for="report in detail.reports" :key="report.id" class="timeline-item">
            <strong>{{ report.title }}</strong>
            <span class="quiet">{{ report.summary }}</span>
            <div style="margin-top: 10px">
              <el-button size="small" type="primary" tag="a" :href="artifactUrl(report.htmlRef)" target="_blank">HTML</el-button>
              <el-button size="small" tag="a" :href="artifactUrl(report.markdownRef)" target="_blank">Markdown</el-button>
              <el-button size="small" type="success" tag="a" :href="artifactDownloadUrl(report.htmlRef)">下载 HTML</el-button>
              <el-button size="small" tag="a" :href="artifactDownloadUrl(report.markdownRef)">下载 Markdown</el-button>
              <el-button size="small" :loading="exporting === 'findings'" @click="downloadCsv('findings')">导出漏洞 CSV</el-button>
              <el-button size="small" :loading="exporting === 'evidence'" @click="downloadCsv('evidence')">导出证据 CSV</el-button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="glass-card section-card" style="margin-top: 16px">
      <div class="section-title">
        <h2>复现交付说明</h2>
        <span class="quiet">客户报告以可复现材料为准，不展示内部证据堆叠</span>
      </div>
      <div class="delivery-note-grid">
        <article class="delivery-note-card">
          <strong>报告正文</strong>
          <span>按漏洞逐条输出：漏洞描述、代码链路、原始请求包、PoC 脚本、成功判定、修复建议和复测方法。</span>
        </article>
        <article class="delivery-note-card">
          <strong>后台审计链</strong>
          <span>Evidence、ToolRun、RawRef、Hash 与容器输出仍保留在高级观察区，用于追溯，不作为客户报告主体。</span>
        </article>
      </div>
    </div>

    <div class="content-grid">
      <div class="glass-card section-card">
        <div class="section-title"><h2>执行时间线</h2></div>
        <div class="timeline">
          <div v-for="event in detail.timeline" :key="event.id" class="timeline-item">
            <strong>{{ event.eventType }}</strong>
            <span class="quiet">{{ event.actor }} · {{ event.summary }}</span>
            <div v-if="event.eventType.startsWith('agent.model_')" class="model-event-meta">
              <span v-if="event.metadata?.model">model {{ String(event.metadata.model) }}</span>
              <span v-if="event.metadata?.provider">provider {{ String(event.metadata.provider) }}</span>
              <span v-if="event.metadata?.intentType">intent {{ String(event.metadata.intentType) }}</span>
              <span v-if="event.metadata?.latencyMs">latency {{ String(event.metadata.latencyMs) }} ms</span>
            </div>
          </div>
        </div>
      </div>
      <div class="glass-card section-card">
        <div class="section-title"><h2>Intent 队列</h2></div>
        <div class="timeline">
          <div v-for="intent in detail.intents" :key="intent.id" class="timeline-item">
            <strong>{{ intent.intentType }} · {{ intent.title }}</strong>
            <span class="quiet">{{ intent.status }} · {{ intent.objective }}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="content-grid">
      <div class="glass-card section-card">
        <div class="section-title"><h2>Contract 检查</h2></div>
        <div class="timeline">
          <div v-for="check in detail.contractChecks" :key="check.id" class="timeline-item">
            <strong>{{ check.contractType }} · {{ check.status }}</strong>
            <span class="quiet">{{ check.downgradeReason || '当前检查未降级' }}</span>
          </div>
        </div>
      </div>

      <div class="glass-card section-card">
        <div class="section-title"><h2>高级观察</h2></div>
        <el-collapse>
          <el-collapse-item title="原始 Evidence 与 ToolRun" name="raw-runs">
            <div class="timeline">
              <div v-for="run in detail.toolRuns" :key="run.id" class="timeline-item">
                <strong>{{ run.toolName }} · {{ run.runnerType }}</strong>
                <span class="quiet">{{ run.status }} · {{ run.commandPreview || 'no command preview' }}</span>
                <span class="quiet" v-if="run.containerId">container {{ run.containerId.slice(0, 12) }}</span>
                <span class="quiet" v-if="run.blockReason">{{ run.blockReason }}</span>
                <div style="margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap">
                  <el-button v-if="run.stdoutRef" size="small" tag="a" :href="artifactUrl(run.stdoutRef)" target="_blank">stdout</el-button>
                  <el-button v-if="run.stderrRef" size="small" tag="a" :href="artifactUrl(run.stderrRef)" target="_blank">stderr</el-button>
                </div>
              </div>
              <div v-for="item in detail.evidence" :key="`evidence-${item.id}`" class="timeline-item">
                <strong>#{{ item.id }} · {{ item.evidenceType }}</strong>
                <span class="quiet">{{ item.summary }}</span>
                <el-button size="small" tag="a" :href="item.artifactUrl" target="_blank">原始证据</el-button>
              </div>
            </div>
          </el-collapse-item>
          <el-collapse-item title="Blackboard 节点" name="blackboard">
            <div class="timeline">
              <div v-for="node in detail.blackboard" :key="node.id" class="timeline-item">
                <strong>{{ node.nodeType }} · {{ node.title }}</strong>
                <span class="quiet">{{ node.summary }}</span>
              </div>
            </div>
          </el-collapse-item>
        </el-collapse>
      </div>
    </div>
  </section>
  <section v-else class="task-detail-empty">
    <el-empty :description="taskLoadError || '任务详情加载中...'" />
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import dayjs from 'dayjs'
import type { UploadFile } from 'element-plus'
import { ElMessage } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import StatusPill from '@/components/StatusPill.vue'
import { platformApi, api, type Evidence, type Finding, type ToolRun } from '@/api/client'
import { usePlatformStore } from '@/stores/platform'
import { useAuthStore } from '@/stores/auth'

const props = defineProps<{ id: string }>()
const store = usePlatformStore()
const authStore = useAuthStore()
const route = useRoute()
const router = useRouter()
const starting = ref(false)
const uploading = ref(false)
const exporting = ref<'findings' | 'evidence' | ''>('')
const taskLoadError = ref('')
const detail = computed(() => store.currentTask)
const capabilities = ref<any[]>([])
const now = ref(Date.now())
const isAdmin = computed(() => authStore.user?.role === 'admin')
let clockTimer = 0

async function loadCapabilities() {
  if (!detail.value) return
  try {
    const res = await api.get(`/tasks/${detail.value.task.id}/capabilities`)
    capabilities.value = res.data || []
  } catch { /* ignore */ }
}

function capStrengthType(strength: string) {
  if (strength === 'verified') return 'success'
  if (strength === 'observed') return 'warning'
  return 'info'
}

const nextStepHint = computed(() => {
  if (!detail.value) return ''
  if (route.query.next === 'upload' && detail.value.task.taskType === 'code_audit' && detail.value.evidence.length === 0) {
    return '下一步：上传代码 ZIP，平台会自动安全解压并生成首轮审计证据。'
  }
  if (route.query.next === 'start' && ['pending', 'failed'].includes(detail.value.task.status)) {
    return '下一步：点击开始执行，平台会自动进入基线采集与证据补齐流程。'
  }
  if (detail.value.task.status === 'running') {
    return '任务执行中，页面会自动刷新状态、Intent、ToolRun 与报告产物。'
  }
  if (detail.value.task.status === 'failed') {
    return '任务执行失败，请优先查看时间线和 ToolRun 错误，再决定是否重新启动。'
  }
  return ''
})

const keyEvidence = computed(() => {
  if (!detail.value) return []
  return dedupeEvidence(detail.value.evidence.filter((item) => isKeyEvidence(item))).slice(0, 12)
})

const reportableFindings = computed(() => {
  if (!detail.value) return []
  return detail.value.findings.filter(isReportableFinding)
})

const elapsedTimeLabel = computed(() => {
  if (!detail.value) return '-'
  const task = detail.value.task
  const start = task.startedAt ? dayjs(task.startedAt) : null
  if (!start?.isValid()) {
    return task.status === 'pending' ? '未开始' : '-'
  }
  const end = task.status === 'running'
    ? dayjs(now.value)
    : task.finishedAt
      ? dayjs(task.finishedAt)
      : dayjs(task.updatedAt || task.startedAt)
  const seconds = Math.max(0, end.diff(start, 'second'))
  return formatDuration(seconds)
})

function formatDuration(totalSeconds: number) {
  const days = Math.floor(totalSeconds / 86400)
  const hours = Math.floor((totalSeconds % 86400) / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  if (days > 0) return `${days}天 ${hours}时`
  if (hours > 0) return `${hours}时 ${minutes}分`
  if (minutes > 0) return `${minutes}分 ${seconds}秒`
  return `${seconds}秒`
}

function proofDetail(finding: Finding, key: string) {
  const details = finding.richDetails || {}
  const value = details[key]
  if (Array.isArray(value)) {
    return value.join('；')
  }
  const text = String(value || '').trim()
  return text || '详见报告复现材料'
}

function proofSummary(finding: Finding) {
  const endpoint = proofDetail(finding, 'proof_endpoint')
  const criteria = proofDetail(finding, 'success_criteria')
  if (endpoint === '详见报告复现材料') {
    return cleanReportText(finding.remediation)
  }
  return cleanReportText(`复现入口：${endpoint}。成功判定：${criteria}`)
}

function isReportableFinding(finding: Finding) {
  return finding.contractStatus === 'passed'
    || finding.validationStatus === 'dynamically_validated'
    || finding.status === 'dynamically_validated'
    || finding.status === 'human_confirmed'
}

function severityLabel(severity: string) {
  const labels: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
  return labels[severity] || severity
}

function cleanReportText(value: string) {
  return String(value || '').replaceAll('复核', '检查')
}

function openFinding(finding: Finding) {
  router.push(`/findings/${finding.id}`)
}

async function refresh() {
  try {
    taskLoadError.value = ''
    await store.loadTask(Number(props.id))
  } catch (error: any) {
    store.currentTask = null
    taskLoadError.value = error?.response?.status === 404 ? '任务不存在或已被删除' : (error?.response?.data?.error || '任务详情加载失败')
  }
}

async function startTask() {
  starting.value = true
  try {
    await platformApi.startTask(Number(props.id))
    ElMessage.success('Agent 已启动')
    await refresh()
    store.startTaskPolling(Number(props.id))
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '任务启动失败')
  } finally {
    starting.value = false
  }
}

async function handleUpload(uploadFile: UploadFile) {
  if (!uploadFile.raw) return
  uploading.value = true
  try {
    await platformApi.uploadZip(Number(props.id), uploadFile.raw)
    ElMessage.success('ZIP 已安全解压到隔离 Workspace')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || 'ZIP 上传失败')
  } finally {
    uploading.value = false
  }
}

function beforeUpload(file: File) {
  const isZip = file.name.toLowerCase().endsWith('.zip')
  if (!isZip) {
    ElMessage.error('请上传 ZIP 压缩包')
  }
  return isZip
}

function handleUploadError() {
  ElMessage.error('ZIP 上传失败，请确认文件是 ZIP 且大小未超出限制')
}

function artifactUrl(ref: string) {
  if (!ref) return '#'
  const path = ref.replace('minio://', '').replace('local://', '')
  return `/artifacts/${path}`
}

function artifactDownloadUrl(ref: string) {
  return `${artifactUrl(ref)}?download=1`
}

async function downloadCsv(type: 'findings' | 'evidence') {
  if (!detail.value) return
  exporting.value = type
  try {
    const blob = type === 'findings'
      ? await platformApi.exportTaskFindings(detail.value.task.id)
      : await platformApi.exportTaskEvidence(detail.value.task.id)
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = type === 'findings' ? 'findings.csv' : 'evidence.csv'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || 'CSV 导出失败')
  } finally {
    exporting.value = ''
  }
}

function linkedEvidence(finding: Finding): Evidence[] {
  if (!detail.value) return []
  const refs = Array.isArray((finding as any).evidenceRefs) ? ((finding as any).evidenceRefs as number[]) : []
  if (refs.length === 0) return []
  return detail.value.evidence.filter((item) => refs.includes(item.id))
}

function keyEvidenceForFinding(finding: Finding): Evidence[] {
  return dedupeEvidence(linkedEvidence(finding).filter((item) => isKeyEvidence(item))).slice(0, 6)
}

function isKeyEvidence(item: Evidence) {
  const path = `${item.filePath || ''}`.toLowerCase()
  const summary = `${item.summary || ''}`.toLowerCase()
  if (item.evidenceType === 'command_output') {
    return item.relationType === 'poc_result' || summary.includes('命令执行漏洞验证') || summary.includes('poc')
  }
  if (path.includes('/upload-labs-env') || path.includes('/apache/') || path.includes('/php/') || path.endsWith('.min.js')) return false
  if (summary.includes('php.ini') || summary.includes('jquery.min.js') || summary.includes('httpd.conf')) return false
  return ['code_snippet', 'http_exchange', 'response_diff', 'marker_poc'].includes(item.evidenceType)
    || item.evidenceType === 'command_output'
}

function evidenceTypeLabel(type: string) {
  const labels: Record<string, string> = {
    code_snippet: '代码片段',
    command_output: '命令回显证明',
    http_exchange: 'HTTP 交互',
    response_diff: '响应差异',
    marker_poc: 'Marker 验证',
    tool_output: '工具输出',
  }
  return labels[type] || type
}

function dedupeEvidence(items: Evidence[]) {
  const seen = new Set<string>()
  const result: Evidence[] = []
  for (const item of items) {
    const key = `${item.filePath || ''}:${item.lineStart || 0}:${item.relationType || ''}`
    if (seen.has(key)) continue
    seen.add(key)
    result.push(item)
  }
  return result
}

function linkedToolRuns(finding: Finding): ToolRun[] {
  if (!detail.value) return []
  const runIds = new Set(linkedEvidence(finding).map((item) => item.toolRunId).filter(Boolean) as number[])
  if (runIds.size === 0) return []
  return detail.value.toolRuns.filter((run) => runIds.has(run.id))
}

watch(
  () => detail.value?.task.status,
  (status) => {
    if (!status) return
    if (status === 'running') {
      store.startTaskPolling(Number(props.id))
      return
    }
    if (['completed', 'failed', 'cancelled'].includes(status)) {
      store.stopTaskPolling()
    }
  },
)

onMounted(async () => {
  clockTimer = window.setInterval(() => {
    now.value = Date.now()
  }, 1000)
  await refresh()
  await loadCapabilities()
  if (detail.value?.task.status === 'running') {
    store.startTaskPolling(Number(props.id))
  }
})

onUnmounted(() => {
  if (clockTimer) {
    window.clearInterval(clockTimer)
  }
  store.stopTaskPolling()
})
</script>

<style scoped>
.metric-grid {
  grid-template-columns: repeat(5, minmax(0, 1fr));
}

.metric-card--elapsed strong {
  font-variant-numeric: tabular-nums;
  color: var(--blue);
}

.task-detail-empty {
  min-height: 420px;
  display: grid;
  place-items: center;
}

.finding-report-stack {
  display: grid;
  gap: 10px;
  max-height: 560px;
  overflow-y: auto;
}

.finding-report-preview {
  display: grid;
  gap: 12px;
  padding: 16px;
  border: 1px solid var(--border);
  border-left: 4px solid var(--severity-color, var(--accent));
  border-radius: 8px;
  background: #fff;
  cursor: pointer;
  transition: border-color 0.15s, box-shadow 0.15s, transform 0.15s;
}

.finding-report-preview:hover {
  border-color: rgba(47, 111, 228, 0.3);
  box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08);
  transform: translateY(-1px);
}

.finding-report-preview.severity-critical { --severity-color: #e11d48; }
.finding-report-preview.severity-high { --severity-color: #d97706; }
.finding-report-preview.severity-medium { --severity-color: #2563eb; }
.finding-report-preview.severity-low { --severity-color: #64748b; }

.finding-report-preview__header {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 10px;
  align-items: start;
}

.finding-report-preview__header h3 {
  margin: 0;
  color: var(--text-primary);
  font-size: 16px;
  line-height: 1.35;
}

.severity-chip {
  display: inline-flex;
  padding: 5px 9px;
  border-radius: 6px;
  color: #fff;
  font-size: 12px;
  font-weight: 800;
  white-space: nowrap;
}

.severity-chip.critical { background: #e11d48; }
.severity-chip.high { background: #d97706; }
.severity-chip.medium { background: #2563eb; }
.severity-chip.low { background: #64748b; }

.finding-report-preview p {
  margin: 0;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.7;
}

.finding-report-preview__grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}

.finding-report-preview__grid div {
  min-width: 0;
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #f8fafc;
}

.finding-report-preview__grid label {
  display: block;
  margin-bottom: 5px;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 700;
}

.finding-report-preview__grid strong {
  display: block;
  color: var(--text-primary);
  font-size: 12px;
  line-height: 1.6;
  word-break: break-word;
}

.finding-report-preview footer {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  color: var(--text-muted);
  font-size: 12px;
}

.finding-report-preview footer button {
  margin-left: auto;
  border: 0;
  background: transparent;
  color: var(--accent);
  font-weight: 800;
  cursor: pointer;
}

.delivery-note-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.delivery-note-card {
  display: grid;
  gap: 8px;
  padding: 18px;
  border: 1px solid rgba(31, 42, 68, 0.08);
  border-radius: 22px;
  background: linear-gradient(135deg, #ffffff, #f3f8ff);
}

.delivery-note-card strong {
  color: #17213a;
  font-size: 16px;
}

.delivery-note-card span {
  color: var(--muted);
  line-height: 1.7;
}

.link-chip {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: #f8fbff;
  color: var(--ink-soft);
  font-size: 13px;
}

.model-event-meta {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 8px;
  color: var(--ink-soft);
  font-size: 12px;
  font-weight: 600;
}

@media (max-width: 920px) {
  .metric-grid,
  .finding-report-preview__grid,
  .delivery-note-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 1180px) and (min-width: 921px) {
  .metric-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}
</style>
