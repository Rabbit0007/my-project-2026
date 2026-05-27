<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">Rabbit 状态空间</p>
        <h1 class="page-title">Cairn-style 自主探索工作台</h1>
        <p class="subcopy">
          从事实出发形成假设和意图，Runner 只负责观察与验证，Evidence 写回图状态后继续扩展下一轮探索。
        </p>
      </div>
      <el-button type="primary" size="large" @click="$router.push('/tasks/new')">新建探索任务</el-button>
    </div>

    <div class="loop-strip">
      <div v-for="step in loopSteps" :key="step.name" class="loop-step" :class="step.tone">
        <span>{{ step.kicker }}</span>
        <strong>{{ step.name }}</strong>
      </div>
    </div>

    <div class="metric-grid">
      <div class="glass-card metric-card">
        <span>探索任务</span>
        <strong>{{ overview?.totalTasks ?? 0 }}</strong>
      </div>
      <div class="glass-card metric-card">
        <span>运行中循环</span>
        <strong>{{ overview?.runningTasks ?? 0 }}</strong>
      </div>
      <div class="glass-card metric-card">
        <span>待补证据缺口</span>
        <strong>{{ overview?.pendingReviews ?? 0 }}</strong>
      </div>
      <div class="glass-card metric-card">
        <span>高影响结果</span>
        <strong>{{ overview?.highRiskFindings ?? 0 }}</strong>
      </div>
    </div>

    <div class="content-grid">
      <div class="glass-card section-card">
        <div class="section-title">
          <h2>最近探索</h2>
          <RouterLink class="quiet" to="/tasks">查看全部</RouterLink>
        </div>
        <el-table :data="overview?.recentTasks || []" style="width: 100%" empty-text="还没有任务，先创建一个授权探索吧">
          <el-table-column prop="name" label="任务" min-width="180" />
          <el-table-column prop="taskType" label="类型" width="120" />
          <el-table-column label="状态" width="150">
            <template #default="{ row }">
              <StatusPill :status="row.status" />
            </template>
          </el-table-column>
          <el-table-column label="进度" width="180">
            <template #default="{ row }">
              <el-progress :percentage="row.progressPercent" :stroke-width="8" />
            </template>
          </el-table-column>
          <el-table-column width="120">
            <template #default="{ row }">
              <el-button text type="primary" @click="$router.push(`/tasks/${row.id}`)">查看</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="glass-card section-card hero-panel">
        <div class="section-title">
          <h2>Runner / ToolRun</h2>
          <span class="status-pill">ready</span>
        </div>
        <div class="timeline">
          <div v-for="(status, name) in overview?.runnerHealth" :key="name" class="timeline-item">
            <strong>{{ name }}</strong>
            <span class="quiet">{{ status }} · 观察/验证 · Evidence 回写</span>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import StatusPill from '@/components/StatusPill.vue'
import { usePlatformStore } from '@/stores/platform'

const store = usePlatformStore()
const overview = computed(() => store.overview)

const loopSteps = [
  { kicker: '01', name: 'Fact / Observation', tone: 'signal-blue' },
  { kicker: '02', name: 'Hypothesis / Intent', tone: 'signal-amber' },
  { kicker: '03', name: 'Runner / Evidence', tone: 'signal-green' },
  { kicker: '04', name: 'Capability / NegativeFact', tone: 'signal-red' },
  { kicker: '05', name: 'Next Intent', tone: 'signal-indigo' },
]

onMounted(() => {
  store.loadOverview()
})
</script>
