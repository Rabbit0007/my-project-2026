import { defineStore } from 'pinia'
import { platformApi, type Overview, type SecurityTask, type TaskDetail } from '@/api/client'

export const usePlatformStore = defineStore('platform', {
  state: () => ({
    overview: null as Overview | null,
    tasks: [] as SecurityTask[],
    currentTask: null as TaskDetail | null,
    loading: false,
    currentTaskPollTimer: 0 as number,
  }),
  actions: {
    async loadOverview() {
      this.overview = await platformApi.overview()
      return this.overview
    },
    async loadTasks(includeTests = false) {
      this.tasks = await apiTaskList(includeTests)
      return this.tasks
    },
    async loadTask(id: number) {
      this.currentTask = await platformApi.getTask(id)
      return this.currentTask
    },
    startTaskPolling(taskId: number, intervalMs = 2500) {
      this.stopTaskPolling()
      this.currentTaskPollTimer = window.setInterval(async () => {
        try {
          const detail = await this.loadTask(taskId)
          if (['completed', 'failed', 'cancelled'].includes(detail.task.status)) {
            this.stopTaskPolling()
          }
        } catch {
          this.stopTaskPolling()
        }
      }, intervalMs)
    },
    stopTaskPolling() {
      if (this.currentTaskPollTimer) {
        window.clearInterval(this.currentTaskPollTimer)
        this.currentTaskPollTimer = 0
      }
    },
  },
})

async function apiTaskList(includeTests: boolean) {
  const query = new URLSearchParams()
  if (includeTests) query.set('include_tests', 'true')
  const suffix = query.toString()
  return platformApi.listTasksWithQuery(suffix ? `?${suffix}` : '')
}
