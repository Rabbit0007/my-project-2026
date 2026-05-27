<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">漏洞中心</p>
        <h1 class="page-title">漏洞报告</h1>
        <p class="subcopy">只展示已形成报告口径的漏洞条目，点击查看漏洞证明、影响链路和修复建议。</p>
      </div>
    </div>

    <div class="finding-report-metrics">
      <div>
        <span>报告漏洞</span>
        <strong>{{ reportableFindings.length }}</strong>
      </div>
      <div>
        <span>严重 / 高危</span>
        <strong>{{ highSeverityCount }}</strong>
      </div>
      <div>
        <span>已验证</span>
        <strong>{{ verifiedCount }}</strong>
      </div>
      <div>
        <span>涉及任务</span>
        <strong>{{ taskCount }}</strong>
      </div>
    </div>

    <div class="glass-card section-card finding-filter-card">
      <div class="filter-row">
        <el-select v-model="filters.severity" placeholder="风险等级" clearable style="width: 150px">
          <el-option label="严重" value="critical" />
          <el-option label="高危" value="high" />
          <el-option label="中危" value="medium" />
          <el-option label="低危" value="low" />
        </el-select>
        <el-input v-model="filters.keyword" placeholder="搜索标题、组件、目标..." clearable style="width: 260px" />
        <span class="quiet" style="margin-left: auto">共 {{ filteredFindings.length }} 条</span>
      </div>
    </div>

    <div class="finding-report-list">
      <el-empty v-if="filteredFindings.length === 0" description="暂无可交付漏洞" />
      <template v-else>
        <article
          v-for="finding in filteredFindings"
          :key="finding.id"
          class="finding-report-card"
          :class="`severity-${finding.severity}`"
          @click="$router.push(`/findings/${finding.id}`)"
        >
          <div class="finding-report-card__rank">
            <span :class="`severity-badge ${finding.severity}`">{{ severityLabel(finding.severity) }}</span>
          </div>
          <div class="finding-report-card__body">
            <div class="finding-report-card__heading">
              <h2>{{ finding.title }}</h2>
              <el-icon><ArrowRight /></el-icon>
            </div>
            <p>{{ findingSummary(finding) }}</p>
            <div class="finding-report-card__meta">
              <span>{{ finding.vulnerabilityType }}</span>
              <span>{{ finding.affectedTarget || '-' }}</span>
              <span>{{ finding.affectedComponent || '-' }}</span>
            </div>
          </div>
        </article>
      </template>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { ArrowRight } from '@element-plus/icons-vue'
import { platformApi, type Finding } from '@/api/client'

const findings = ref<Finding[]>([])
const filters = reactive({
  severity: '',
  keyword: '',
})

const reportableFindings = computed(() => findings.value.filter(isReportableFinding))

const filteredFindings = computed(() =>
  reportableFindings.value.filter((f) => {
    if (filters.severity && f.severity !== filters.severity) return false
    const kw = filters.keyword.trim().toLowerCase()
    if (!kw) return true
    return [f.title, f.affectedComponent, f.affectedTarget, f.vulnerabilityType]
      .some((value) => String(value || '').toLowerCase().includes(kw))
  }),
)

const verifiedCount = computed(() => reportableFindings.value.filter((f) => f.validationStatus === 'dynamically_validated' || f.contractStatus === 'passed').length)
const highSeverityCount = computed(() => reportableFindings.value.filter((f) => ['critical', 'high'].includes(f.severity)).length)
const taskCount = computed(() => new Set(reportableFindings.value.map((f) => f.taskId)).size)

function isReportableFinding(finding: Finding) {
  return finding.contractStatus === 'passed'
    || finding.validationStatus === 'dynamically_validated'
    || finding.status === 'dynamically_validated'
    || finding.status === 'human_confirmed'
}

function findingSummary(finding: Finding) {
  const details = finding.richDetails || {}
  const text = details.vulnerability_description || details.observed_result || finding.remediation
  return cleanReportText(String(text || '已形成漏洞报告条目，详情包含漏洞证明、影响链路和修复建议。'))
}

function severityLabel(s: string) {
  const map: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
  return map[s] || s
}

function cleanReportText(value: string) {
  return String(value || '').replaceAll('复核', '检查')
}

onMounted(async () => {
  try {
    findings.value = (await platformApi.listFindings())
      .sort((a, b) => {
        const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
        return (rank[a.severity] ?? 99) - (rank[b.severity] ?? 99)
      })
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载失败')
  }
})
</script>

<style scoped>
.finding-report-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.finding-report-metrics > div {
  padding: 18px 20px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #fff;
  box-shadow: var(--shadow-sm);
}

.finding-report-metrics span {
  display: block;
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 700;
}

.finding-report-metrics strong {
  display: block;
  margin-top: 8px;
  color: var(--text-primary);
  font-size: 28px;
}

.finding-filter-card {
  margin-bottom: 16px;
}

.filter-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.finding-report-list {
  display: grid;
  gap: 10px;
}

.finding-report-card {
  display: grid;
  grid-template-columns: 92px minmax(0, 1fr);
  gap: 18px;
  padding: 18px;
  border: 1px solid var(--border);
  border-left: 4px solid var(--severity-color, var(--accent));
  border-radius: 8px;
  background: #fff;
  box-shadow: var(--shadow-sm);
  cursor: pointer;
  transition: border-color 0.15s, box-shadow 0.15s, transform 0.15s;
}

.finding-report-card:hover {
  border-color: rgba(47, 111, 228, 0.26);
  box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08);
  transform: translateY(-1px);
}

.finding-report-card.severity-critical { --severity-color: #e11d48; }
.finding-report-card.severity-high { --severity-color: #d97706; }
.finding-report-card.severity-medium { --severity-color: #2563eb; }
.finding-report-card.severity-low { --severity-color: #64748b; }

.finding-report-card__rank {
  display: flex;
  align-items: flex-start;
}

.severity-badge {
  display: inline-flex;
  padding: 6px 10px;
  border-radius: 6px;
  color: #fff;
  font-size: 12px;
  font-weight: 800;
}

.severity-badge.critical { background: #e11d48; }
.severity-badge.high { background: #d97706; }
.severity-badge.medium { background: #2563eb; }
.severity-badge.low { background: #64748b; }

.finding-report-card__body {
  min-width: 0;
}

.finding-report-card__heading {
  display: flex;
  justify-content: space-between;
  gap: 12px;
}

.finding-report-card__heading h2 {
  margin: 0;
  color: var(--text-primary);
  font-size: 17px;
  line-height: 1.35;
}

.finding-report-card__heading .el-icon {
  margin-top: 3px;
  color: var(--accent);
  flex-shrink: 0;
}

.finding-report-card p {
  display: -webkit-box;
  margin: 8px 0 0;
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.7;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}

.finding-report-card__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 12px;
}

.finding-report-card__meta span {
  max-width: 360px;
  padding: 5px 8px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: #f8fafc;
  color: var(--text-muted);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 820px) {
  .finding-report-metrics,
  .finding-report-card {
    grid-template-columns: 1fr;
  }
}
</style>
