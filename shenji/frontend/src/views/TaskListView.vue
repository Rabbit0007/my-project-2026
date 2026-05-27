<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">任务中心</p>
        <h1 class="page-title">任务列表</h1>
        <p class="subcopy">围绕目标、证据、报告和执行时长组织安全验证任务，适合持续审计与正式报告交付。</p>
      </div>
      <el-button v-if="isAdmin" type="primary" @click="$router.push('/tasks/new')">新建任务</el-button>
    </div>

    <div class="glass-card section-card task-filter-card">
      <div class="task-filter-grid">
        <div class="task-filter-item">
          <label>任务状态</label>
          <el-select v-model="filters.status" placeholder="请选择状态" clearable>
            <el-option label="待启动" value="pending" />
            <el-option label="运行中" value="running" />
            <el-option label="已完成" value="completed" />
            <el-option label="失败" value="failed" />
          </el-select>
        </div>
        <div class="task-filter-item">
          <label>任务类型</label>
          <el-select v-model="filters.taskType" placeholder="请选择任务类型" clearable>
            <el-option label="代码审计" value="code_audit" />
            <el-option label="渗透验证" value="pentest" />
            <el-option label="混合任务" value="hybrid" />
          </el-select>
        </div>
        <div class="task-filter-item">
          <label>关键词</label>
          <el-input v-model="filters.keyword" placeholder="支持任务名称、目标描述" clearable />
        </div>
      </div>
      <div class="task-filter-toggle-row">
        <el-checkbox v-model="filters.includeTests">显示测试任务</el-checkbox>
      </div>
      <div class="task-filter-actions">
        <el-button @click="resetFilters">重置</el-button>
        <el-button type="primary" :loading="loadingTasks" @click="refreshTasks">查询</el-button>
      </div>
    </div>

    <div class="glass-card section-card">
      <div class="task-toolbar">
        <div class="task-toolbar__actions">
          <template v-if="isAdmin">
            <el-button type="primary" :loading="actionLoading" @click="startSelectedTasks">开始</el-button>
            <el-button disabled>终止</el-button>
            <el-button type="danger" plain :loading="actionLoading" @click="deleteSelectedTasks">删除</el-button>
            <el-button type="primary" plain @click="$router.push('/tasks/new')">新建</el-button>
          </template>
        </div>
        <div class="task-toolbar__meta">
          <span>共 {{ filteredTasks.length }} 条</span>
        </div>
      </div>

      <el-table
        :data="filteredTasks"
        row-key="id"
        style="width: 100%"
        empty-text="暂无任务"
        class="rabbit-table"
        @selection-change="handleSelectionChange"
      >
        <el-table-column type="selection" width="54" reserve-selection />
        <el-table-column prop="id" label="ID" width="86" />
        <el-table-column prop="name" label="任务名称" min-width="220" />
        <el-table-column label="创建时间" min-width="210">
          <template #default="{ row }">{{ formatDate(row.createdAt) }}</template>
        </el-table-column>
        <el-table-column prop="taskType" label="任务类型" width="130" />
        <el-table-column prop="progressStage" label="当前阶段" min-width="200" />
        <el-table-column label="运行时长" width="150">
          <template #default="{ row }">
            <span class="elapsed-time" :class="{ running: row.status === 'running' }">
              {{ elapsedTimeLabel(row) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="130">
          <template #default="{ row }"><StatusPill :status="row.status" /></template>
        </el-table-column>
        <el-table-column label="进度" width="180">
          <template #default="{ row }"><el-progress :percentage="row.progressPercent" :stroke-width="8" /></template>
        </el-table-column>
        <el-table-column label="操作项" width="240">
          <template #default="{ row }">
            <div class="task-actions">
              <el-button type="primary" text @click="$router.push(`/tasks/${row.id}`)">详情</el-button>
              <template v-if="isAdmin">
                <el-button text @click="restartSingleTask(row)" :disabled="row.status === 'running'">重跑</el-button>
                <el-button text type="danger" @click="deleteSingleTask(row)" :disabled="row.status === 'running'">删除</el-button>
              </template>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import dayjs from 'dayjs'
import { ElMessage, ElMessageBox } from 'element-plus'
import { platformApi, type SecurityTask } from '@/api/client'
import StatusPill from '@/components/StatusPill.vue'
import { usePlatformStore } from '@/stores/platform'
import { useAuthStore } from '@/stores/auth'

const store = usePlatformStore()
const authStore = useAuthStore()
const tasks = computed(() => store.tasks)
const isAdmin = computed(() => authStore.user?.role === 'admin')
const selectedTasks = ref<SecurityTask[]>([])
const actionLoading = ref(false)
const loadingTasks = ref(false)
const now = ref(Date.now())
const filters = reactive({
  status: '',
  taskType: '',
  keyword: '',
  includeTests: false,
})

const filteredTasks = computed(() =>
  tasks.value.filter((task) => {
    const matchStatus = !filters.status || task.status === filters.status
    const matchType = !filters.taskType || task.taskType === filters.taskType
    const keyword = filters.keyword.trim().toLowerCase()
    const matchKeyword = !keyword || task.name.toLowerCase().includes(keyword) || task.objective.toLowerCase().includes(keyword)
    return matchStatus && matchType && matchKeyword
  }),
)

const selectedTaskIds = computed(() => new Set(selectedTasks.value.map((task) => task.id)))
const currentSelectedTasks = computed(() => tasks.value.filter((task) => selectedTaskIds.value.has(task.id)))

let refreshTimer = 0
let clockTimer = 0

onMounted(async () => {
  await refreshTasks()
  clockTimer = window.setInterval(() => {
    now.value = Date.now()
  }, 1000)
  refreshTimer = window.setInterval(() => {
    refreshTasks(false)
  }, 5000)
})

onUnmounted(() => {
  if (refreshTimer) {
    window.clearInterval(refreshTimer)
  }
  if (clockTimer) {
    window.clearInterval(clockTimer)
  }
})

function resetFilters() {
  filters.status = ''
  filters.taskType = ''
  filters.keyword = ''
  filters.includeTests = false
  refreshTasks()
}

function formatDate(value: string) {
  return dayjs(value).format('YYYY-MM-DD HH:mm:ss')
}

function elapsedTimeLabel(task: SecurityTask) {
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
}

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

function handleSelectionChange(selection: SecurityTask[]) {
  selectedTasks.value = selection
}

async function startSelectedTasks() {
  const candidates = currentSelectedTasks.value.filter((task) => ['pending', 'failed'].includes(task.status))
  if (candidates.length === 0) {
    ElMessage.warning('请选择待启动或失败的任务')
    return
  }
  actionLoading.value = true
  try {
    for (const task of candidates) {
      await platformApi.startTask(task.id)
    }
    ElMessage.success(`已提交 ${candidates.length} 个任务的启动请求`)
    await refreshTasks(false)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '任务启动失败')
  } finally {
    actionLoading.value = false
  }
}

async function deleteSelectedTasks() {
  if (currentSelectedTasks.value.length === 0) {
    ElMessage.warning('请先选择任务')
    return
  }
  const candidates = currentSelectedTasks.value.filter((task) => task.status !== 'running')
  if (candidates.length === 0) {
    ElMessage.warning('运行中的任务不能删除')
    return
  }
  try {
    await ElMessageBox.confirm(`确定要删除选中的 ${candidates.length} 个任务吗？此操作会移除任务、证据和报告记录，且不可恢复。`, '删除确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  } catch { return }
  actionLoading.value = true
  try {
    for (const task of candidates) {
      await platformApi.deleteTask(task.id)
    }
    ElMessage.success(`已删除 ${candidates.length} 个任务`)
    await refreshTasks(false)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '任务删除失败')
  } finally {
    actionLoading.value = false
  }
}

async function restartSingleTask(task: SecurityTask) {
  actionLoading.value = true
  try {
    await platformApi.restartTask(task.id)
    ElMessage.success('任务已重新启动')
    await refreshTasks(false)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '重新启动失败')
  } finally {
    actionLoading.value = false
  }
}

async function deleteSingleTask(task: SecurityTask) {
  try {
    await ElMessageBox.confirm(`确定要删除任务「${task.name}」吗？此操作不可恢复。`, '删除确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  } catch { return }
  actionLoading.value = true
  try {
    await platformApi.deleteTask(task.id)
    ElMessage.success('任务已删除')
    await refreshTasks(false)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除失败')
  } finally {
    actionLoading.value = false
  }
}

async function refreshTasks(showError = true) {
  loadingTasks.value = true
  try {
    await store.loadTasks(filters.includeTests)
  } catch (error: any) {
    if (showError) {
      ElMessage.error(error?.response?.data?.error || '任务列表加载失败')
    }
  } finally {
    loadingTasks.value = false
  }
}
</script>

<style scoped>
.task-filter-card {
  margin-bottom: 16px;
}

.elapsed-time {
  font-variant-numeric: tabular-nums;
  color: var(--text-secondary);
  font-weight: 700;
}

.elapsed-time.running {
  color: var(--blue);
}

.task-filter-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 24px 28px;
}

.task-filter-item label {
  display: block;
  margin-bottom: 10px;
  color: var(--ink);
  font-size: 14px;
  font-weight: 700;
}

.task-filter-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 22px;
}

.task-filter-toggle-row {
  display: flex;
  gap: 18px;
  margin-top: 18px;
}

.task-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 18px;
}

.task-toolbar__actions {
  display: flex;
  gap: 12px;
}

.task-toolbar__meta {
  color: var(--ink-soft);
  font-weight: 600;
}

.task-actions {
  display: flex;
  align-items: center;
  gap: 4px;
}

:deep(.rabbit-table .el-table__header-wrapper th) {
  background: #f6f8fc;
  color: #617392;
  font-size: 14px;
  font-weight: 700;
}

:deep(.rabbit-table .el-table) {
  --el-table-border-color: #e8edf5;
}

:deep(.task-filter-card .el-input__wrapper),
:deep(.task-filter-card .el-select__wrapper) {
  min-height: 46px;
  border-radius: 10px;
  box-shadow: 0 0 0 1px #d9e3f0 inset;
}

@media (max-width: 1080px) {
  .task-filter-grid {
    grid-template-columns: 1fr;
  }

  .task-toolbar {
    flex-direction: column;
    align-items: flex-start;
    gap: 14px;
  }
}
</style>
