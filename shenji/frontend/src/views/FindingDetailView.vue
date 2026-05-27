<template>
  <section v-if="finding" class="finding-report-page">
    <div class="report-hero" :class="`severity-${finding.severity}`">
      <div class="report-hero__content">
        <p class="eyebrow">漏洞报告</p>
        <h1>{{ finding.title }}</h1>
        <div class="report-hero__meta">
          <span :class="`severity-chip ${finding.severity}`">{{ severityLabel(finding.severity) }}</span>
          <span>{{ finding.vulnerabilityType }}</span>
          <span>{{ finding.affectedComponent || finding.affectedTarget }}</span>
        </div>
      </div>
      <el-button @click="$router.back()">返回</el-button>
    </div>

    <div class="report-layout">
      <main class="report-main">
        <section class="report-section report-summary">
          <div class="report-section__heading">
            <span>01</span>
            <h2>漏洞概述</h2>
          </div>
          <p>{{ descriptionText }}</p>
          <div class="summary-grid">
            <div>
              <label>影响目标</label>
              <strong>{{ finding.affectedTarget || '-' }}</strong>
            </div>
            <div>
              <label>影响组件</label>
              <strong>{{ finding.affectedComponent || '-' }}</strong>
            </div>
            <div>
              <label>验证结论</label>
              <strong>{{ deliveryStatusLabel }}</strong>
            </div>
          </div>
        </section>

        <section class="report-section">
          <div class="report-section__heading">
            <span>02</span>
            <h2>漏洞证明</h2>
          </div>
          <div class="proof-grid">
            <div class="proof-item">
              <label>验证端点</label>
              <strong>{{ details.proof_endpoint || details.entrypoint || finding.affectedTarget || '-' }}</strong>
            </div>
            <div class="proof-item">
              <label>成功判定</label>
              <strong>{{ details.success_criteria || '验证证据已满足报告输出条件' }}</strong>
            </div>
          </div>
          <div v-if="proofCommand" class="proof-command">
            <label>PoC / 复现命令</label>
            <pre>{{ proofCommand }}</pre>
          </div>
          <div v-if="details.request_packet || details.response_packet" class="packet-grid">
            <div v-if="details.request_packet">
              <label>请求包</label>
              <pre>{{ details.request_packet }}</pre>
            </div>
            <div v-if="details.response_packet">
              <label>响应包</label>
              <pre>{{ details.response_packet }}</pre>
            </div>
          </div>
        </section>

        <section class="report-section">
          <div class="report-section__heading">
            <span>03</span>
            <h2>影响与链路</h2>
          </div>
          <div class="detail-table">
            <div>
              <label>入口点</label>
              <span>{{ details.entrypoint || '-' }}</span>
            </div>
            <div>
              <label>可控输入</label>
              <span>{{ details.controlled_input || '-' }}</span>
            </div>
            <div>
              <label>传播路径</label>
              <span>{{ details.propagation_path || '-' }}</span>
            </div>
            <div>
              <label>敏感行为 / Sink</label>
              <span>{{ details.sensitive_sink_or_behavior || '-' }}</span>
            </div>
            <div>
              <label>影响说明</label>
              <span>{{ details.impact_explanation || details.exploitability_assessment || '-' }}</span>
            </div>
          </div>
        </section>

        <section class="report-section">
          <div class="report-section__heading">
            <span>04</span>
            <h2>修复建议</h2>
          </div>
          <p>{{ remediationText }}</p>
          <div class="fix-box">
            <label>复测方法</label>
            <span>{{ retestText }}</span>
          </div>
        </section>

        <section v-if="evidenceList.length > 0" class="report-section">
          <div class="report-section__heading">
            <span>05</span>
            <h2>关联证据</h2>
          </div>
          <div class="evidence-report-list">
            <article v-for="ev in evidenceList" :key="ev.id" class="evidence-report-item">
              <div>
                <strong>{{ ev.title || `Evidence #${ev.id}` }}</strong>
                <span>{{ evidenceTypeLabel(ev.evidenceType) }} · {{ ev.relationType || 'evidence' }}</span>
              </div>
              <p>{{ ev.summary }}</p>
              <a v-if="ev.artifactUrl" :href="ev.artifactUrl" target="_blank">打开原始证据</a>
            </article>
          </div>
        </section>
      </main>

      <aside class="report-aside">
        <div class="aside-panel">
          <span>风险等级</span>
          <strong :class="`severity-text ${finding.severity}`">{{ severityLabel(finding.severity) }}</strong>
        </div>
        <div class="aside-panel">
          <span>报告状态</span>
          <strong>{{ deliveryStatusLabel }}</strong>
        </div>
        <div class="aside-panel">
          <span>证据数量</span>
          <strong>{{ evidenceList.length }}</strong>
        </div>
        <div class="aside-note">
          <strong>交付口径</strong>
          <p>这里展示的是已经进入报告的漏洞内容，页面只保留交付信息。</p>
        </div>
      </aside>
    </div>
  </section>
  <section v-else>
    <el-empty description="加载中..." />
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { platformApi, type Evidence, type Finding } from '@/api/client'

const route = useRoute()
const finding = ref<Finding | null>(null)
const evidenceList = ref<Evidence[]>([])

const details = computed(() => {
  if (!finding.value?.richDetails) return {} as Record<string, any>
  return finding.value.richDetails as Record<string, any>
})

const descriptionText = computed(() =>
  cleanReportText(String(details.value.vulnerability_description || details.value.observed_result || finding.value?.remediation || '该漏洞已形成可交付报告条目，详见证明与修复建议。')),
)

const remediationText = computed(() =>
  cleanReportText(finding.value?.remediation || String(details.value.remediation || '请根据影响组件补充输入校验、权限约束、安全 API 使用和回归测试。')),
)

const retestText = computed(() =>
  cleanReportText(finding.value?.retestSteps || String(details.value.retest_steps || '按同一授权范围重新执行复现请求，确认成功判定不再成立。')),
)

const proofCommand = computed(() => {
  const value = details.value.bash_poc || details.value.curl_poc || details.value.python_poc || details.value.trigger_payload_or_action
  return String(value || '').trim()
})

const deliveryStatusLabel = computed(() => {
  const findingValue = finding.value
  if (!findingValue) return '-'
  if (findingValue.contractStatus === 'passed') return '已确认可交付'
  if (findingValue.validationStatus === 'dynamically_validated') return '已动态验证'
  return '已进入报告'
})

async function loadFinding() {
  const findingId = Number(route.params.id)
  try {
    const f = await platformApi.getFinding(findingId)
    finding.value = f
    const detail = await platformApi.getTask(f.taskId)
    const refs = Array.isArray((f as any).evidenceRefs) ? (f as any).evidenceRefs : []
    evidenceList.value = refs.length > 0
      ? detail.evidence.filter(e => refs.includes(e.id))
      : detail.evidence.slice(0, 4)
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '漏洞详情加载失败')
  }
}

function severityLabel(s: string) {
  const map: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
  return map[s] || s || '-'
}

function evidenceTypeLabel(type: string) {
  const map: Record<string, string> = {
    code_snippet: '代码片段',
    command_output: '命令输出',
    http_exchange: 'HTTP 交互',
    response_diff: '响应差异',
    marker_poc: 'PoC 证明',
    tool_output: '工具输出',
  }
  return map[type] || type
}

function cleanReportText(value: string) {
  return String(value || '').replaceAll('复核', '检查')
}

onMounted(loadFinding)
</script>

<style scoped>
.finding-report-page {
  display: grid;
  gap: 18px;
}

.report-hero {
  display: flex;
  justify-content: space-between;
  gap: 24px;
  align-items: flex-start;
  padding: 26px 28px;
  border: 1px solid var(--border);
  border-left: 5px solid var(--severity-color, var(--accent));
  border-radius: 8px;
  background: #fff;
  box-shadow: var(--shadow-sm);
}

.report-hero.severity-critical { --severity-color: #e11d48; }
.report-hero.severity-high { --severity-color: #d97706; }
.report-hero.severity-medium { --severity-color: #2563eb; }
.report-hero.severity-low { --severity-color: #64748b; }

.report-hero h1 {
  max-width: 1080px;
  margin: 0;
  color: var(--text-primary);
  font-size: 30px;
  line-height: 1.25;
  letter-spacing: 0;
}

.report-hero__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-top: 14px;
  color: var(--text-secondary);
  font-size: 13px;
}

.report-hero__meta > span:not(.severity-chip) {
  padding: 5px 8px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: #f8fafc;
}

.severity-chip {
  display: inline-flex;
  padding: 5px 10px;
  border-radius: 6px;
  color: #fff;
  font-size: 12px;
  font-weight: 800;
}

.severity-chip.critical { background: #e11d48; }
.severity-chip.high { background: #d97706; }
.severity-chip.medium { background: #2563eb; }
.severity-chip.low { background: #64748b; }

.report-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 280px;
  gap: 18px;
  align-items: start;
}

.report-main {
  display: grid;
  gap: 14px;
}

.report-section {
  padding: 22px 24px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #fff;
  box-shadow: var(--shadow-sm);
}

.report-section__heading {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
}

.report-section__heading span {
  color: var(--accent);
  font-size: 12px;
  font-weight: 800;
}

.report-section__heading h2 {
  margin: 0;
  color: var(--text-primary);
  font-size: 17px;
}

.report-section p {
  margin: 0;
  color: var(--text-secondary);
  font-size: 14px;
  line-height: 1.8;
}

.summary-grid,
.proof-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-top: 18px;
}

.proof-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin-top: 0;
}

.summary-grid div,
.proof-item,
.fix-box {
  min-width: 0;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #f8fafc;
}

.summary-grid label,
.proof-item label,
.fix-box label,
.proof-command label,
.packet-grid label {
  display: block;
  margin-bottom: 6px;
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 700;
}

.summary-grid strong,
.proof-item strong,
.fix-box span {
  color: var(--text-primary);
  font-size: 13px;
  line-height: 1.6;
  word-break: break-word;
}

.proof-command,
.packet-grid {
  margin-top: 12px;
}

.proof-command pre,
.packet-grid pre {
  margin: 0;
  padding: 14px;
  overflow-x: auto;
  border: 1px solid #dbe4ef;
  border-radius: 8px;
  background: #0f172a;
  color: #e2e8f0;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
}

.packet-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.detail-table {
  display: grid;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}

.detail-table div {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  min-width: 0;
  border-bottom: 1px solid var(--border);
}

.detail-table div:last-child {
  border-bottom: 0;
}

.detail-table label,
.detail-table span {
  padding: 12px 14px;
  font-size: 13px;
  line-height: 1.65;
}

.detail-table label {
  background: #f8fafc;
  color: var(--text-muted);
  font-weight: 700;
}

.detail-table span {
  color: var(--text-primary);
  word-break: break-word;
}

.fix-box {
  display: grid;
  margin-top: 14px;
}

.evidence-report-list {
  display: grid;
  gap: 10px;
}

.evidence-report-item {
  display: grid;
  gap: 8px;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #f8fafc;
}

.evidence-report-item strong {
  color: var(--text-primary);
  font-size: 14px;
}

.evidence-report-item span,
.evidence-report-item a {
  display: block;
  margin-top: 3px;
  color: var(--text-muted);
  font-size: 12px;
}

.evidence-report-item a {
  color: var(--accent);
  font-weight: 700;
}

.report-aside {
  position: sticky;
  top: 80px;
  display: grid;
  gap: 10px;
}

.aside-panel,
.aside-note {
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #fff;
  box-shadow: var(--shadow-sm);
}

.aside-panel span {
  display: block;
  margin-bottom: 8px;
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 700;
}

.aside-panel strong {
  color: var(--text-primary);
  font-size: 20px;
}

.severity-text.critical { color: #e11d48; }
.severity-text.high { color: #d97706; }
.severity-text.medium { color: #2563eb; }
.severity-text.low { color: #64748b; }

.aside-note strong {
  color: var(--text-primary);
}

.aside-note p {
  margin: 8px 0 0;
  color: var(--text-muted);
  font-size: 13px;
  line-height: 1.7;
}

@media (max-width: 1080px) {
  .report-layout,
  .summary-grid,
  .proof-grid,
  .packet-grid {
    grid-template-columns: 1fr;
  }

  .report-aside {
    position: static;
  }
}

@media (max-width: 640px) {
  .report-hero {
    padding: 20px;
    flex-direction: column;
  }

  .report-hero h1 {
    font-size: 24px;
  }

  .report-section {
    padding: 18px;
  }

  .detail-table div {
    grid-template-columns: 1fr;
  }
}
</style>
