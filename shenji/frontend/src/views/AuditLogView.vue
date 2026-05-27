<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">系统管理</p>
        <h1 class="page-title">操作日志</h1>
        <p class="subcopy">平台所有操作的审计记录，包括任务执行、模型调用、安全策略事件。</p>
      </div>
    </div>

    <div class="glass-card section-card">
      <div class="toolbar">
        <div style="display: flex; gap: 10px">
          <el-input v-model="filterType" placeholder="事件类型筛选" clearable style="width: 200px" @change="loadEvents" />
          <el-input v-model="filterTaskId" placeholder="任务 ID" clearable style="width: 120px" @change="loadEvents" />
          <el-button @click="loadEvents">查询</el-button>
        </div>
        <span class="quiet">共 {{ events.length }} 条</span>
      </div>

      <el-table :data="events" style="width: 100%" max-height="600" empty-text="暂无日志">
        <el-table-column prop="occurredAt" label="时间" width="170">
          <template #default="{ row }">{{ formatTime(row.occurredAt) }}</template>
        </el-table-column>
        <el-table-column prop="eventType" label="事件类型" width="220">
          <template #default="{ row }">
            <el-tag size="small" :type="eventTagType(row.eventType)">{{ row.eventType }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="actor" label="执行者" width="140" />
        <el-table-column prop="taskId" label="任务" width="70" />
        <el-table-column prop="summary" label="摘要" min-width="300">
          <template #default="{ row }">
            <span class="log-summary">{{ row.summary }}</span>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { platformApi } from '@/api/client'

const events = ref<any[]>([])
const filterType = ref('')
const filterTaskId = ref('')

async function loadEvents() {
  events.value = await platformApi.listAuditEvents({
    eventType: filterType.value || undefined,
    taskId: filterTaskId.value || undefined,
  })
}

function formatTime(t: string) {
  return new Date(t).toLocaleString('zh-CN')
}

function eventTagType(type: string) {
  if (type.includes('failed') || type.includes('error')) return 'danger'
  if (type.includes('completed') || type.includes('success')) return 'success'
  if (type.includes('model') || type.includes('reason')) return 'warning'
  return 'info'
}

onMounted(loadEvents)
</script>

<style scoped>
.log-summary {
  font-size: 12px;
  color: var(--text-secondary);
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
</style>
