<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">报告中心</p>
        <h1 class="page-title">报告中心</h1>
        <p class="subcopy">第一阶段支持 Markdown 与 HTML 导出，报告措辞会根据 Finding 状态自动收敛。</p>
      </div>
    </div>
    <div class="glass-card section-card">
      <el-empty v-if="reports.length === 0" description="暂无报告" />
      <div v-else class="timeline">
        <div v-for="report in reports" :key="report.id" class="timeline-item">
          <strong>{{ report.title }}</strong>
          <span class="quiet">{{ report.summary }}</span>
          <div style="margin-top: 10px">
            <el-button size="small" type="primary" tag="a" :href="artifactUrl(report.htmlRef)" target="_blank">打开 HTML</el-button>
            <el-button size="small" tag="a" :href="artifactUrl(report.markdownRef)" target="_blank">打开 Markdown</el-button>
            <el-button size="small" type="success" tag="a" :href="artifactDownloadUrl(report.htmlRef)">下载 HTML</el-button>
            <el-button size="small" tag="a" :href="artifactDownloadUrl(report.markdownRef)">下载 Markdown</el-button>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { platformApi, type Report } from '@/api/client'

const reports = ref<Report[]>([])

function artifactUrl(ref: string) {
  if (!ref) return '#'
  // Strip minio:// or local:// prefix for the backend artifact endpoint
  const path = ref.replace('minio://', '').replace('local://', '')
  return `/artifacts/${path}`
}

function artifactDownloadUrl(ref: string) {
  return `${artifactUrl(ref)}?download=1`
}

onMounted(async () => {
  try {
    reports.value = await platformApi.listReports()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '报告列表加载失败')
  }
})
</script>
