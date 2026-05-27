<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">系统管理</p>
        <h1 class="page-title">模型调用日志</h1>
        <p class="subcopy">记录所有 AI 模型 API 调用，用于监控用量和排查问题。</p>
      </div>
    </div>

    <div class="glass-card section-card">
      <div class="toolbar">
        <div style="display: flex; gap: 10px; align-items: center">
          <el-select v-model="filterPurpose" placeholder="调用目的" clearable style="width: 150px" @change="loadLogs">
            <el-option label="全部" value="" />
            <el-option label="对话" value="chat" />
            <el-option label="代码审计" value="code_audit" />
            <el-option label="图推理" value="graph_reasoning" />
            <el-option label="迭代规划" value="plan" />
            <el-option label="报告生成" value="report_narrative" />
          </el-select>
          <el-input v-model="filterTaskId" placeholder="任务 ID" clearable style="width: 100px" @change="loadLogs" />
          <el-button @click="loadLogs">查询</el-button>
        </div>
        <span class="quiet">共 {{ logs.length }} 条</span>
      </div>

      <el-table :data="logs" style="width: 100%" max-height="600" empty-text="暂无调用记录">
        <el-table-column prop="calledAt" label="时间" width="170">
          <template #default="{ row }">{{ formatTime(row.calledAt) }}</template>
        </el-table-column>
        <el-table-column prop="modelName" label="模型" width="160" />
        <el-table-column prop="purpose" label="调用目的" width="130">
          <template #default="{ row }">
            <el-tag size="small" :type="purposeTagType(row.purpose)">{{ purposeLabel(row.purpose) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="latencyMs" label="耗时" width="90">
          <template #default="{ row }">
            <span :style="{ color: row.latencyMs > 30000 ? 'var(--danger)' : row.latencyMs > 10000 ? 'var(--warning)' : 'var(--success)' }">
              {{ formatLatency(row.latencyMs) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.status === 'success' ? 'success' : 'danger'" size="small">{{ row.status === 'success' ? '成功' : '失败' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="promptTokens" label="提示" width="80" />
        <el-table-column prop="compTokens" label="补全" width="80" />
        <el-table-column prop="taskId" label="任务" width="60" />
        <el-table-column prop="errorMessage" label="错误信息" min-width="200">
          <template #default="{ row }">
            <span v-if="row.errorMessage" class="error-text">{{ row.errorMessage.slice(0, 100) }}</span>
            <span v-else class="quiet">-</span>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '@/api/client'

const logs = ref<any[]>([])
const filterPurpose = ref('')
const filterTaskId = ref('')

async function loadLogs() {
  const params = new URLSearchParams()
  if (filterPurpose.value) params.set('purpose', filterPurpose.value)
  if (filterTaskId.value) params.set('taskId', filterTaskId.value)
  const suffix = params.toString()
  const res = await api.get(`/model-call-logs${suffix ? '?' + suffix : ''}`)
  logs.value = res.data || []
}

function formatTime(t: string) {
  return new Date(t).toLocaleString('zh-CN')
}

function formatLatency(ms: number) {
  if (ms < 1000) return ms + 'ms'
  return (ms / 1000).toFixed(1) + 's'
}

function purposeLabel(p: string) {
  const map: Record<string, string> = {
    chat: '对话',
    code_audit: '代码审计',
    graph_reasoning: '图推理',
    plan: '迭代规划',
    report_narrative: '报告生成',
    evidence_intent: '补证据',
  }
  return map[p] || p
}

function purposeTagType(p: string) {
  if (p === 'chat') return ''
  if (p === 'code_audit') return 'warning'
  if (p === 'graph_reasoning') return 'danger'
  return 'info'
}

onMounted(loadLogs)
</script>

<style scoped>
.error-text {
  font-size: 11px;
  color: var(--danger);
}
</style>
