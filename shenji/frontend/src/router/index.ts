import { createRouter, createWebHistory } from 'vue-router'
import DashboardView from '@/views/DashboardView.vue'
import TaskWizardView from '@/views/TaskWizardView.vue'
import TaskListView from '@/views/TaskListView.vue'
import TaskDetailView from '@/views/TaskDetailView.vue'
import FindingCenterView from '@/views/FindingCenterView.vue'
import FindingDetailView from '@/views/FindingDetailView.vue'
import ReportCenterView from '@/views/ReportCenterView.vue'
import SettingsView from '@/views/SettingsView.vue'
import LoginView from '@/views/LoginView.vue'
import UserManageView from '@/views/UserManageView.vue'
import AuditLogView from '@/views/AuditLogView.vue'
import ModelCallLogView from '@/views/ModelCallLogView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: LoginView, meta: { public: true } },
    { path: '/', name: 'dashboard', component: DashboardView },
    { path: '/tasks/new', name: 'task-wizard', component: TaskWizardView, meta: { requiresAdmin: true } },
    { path: '/tasks', name: 'tasks', component: TaskListView },
    { path: '/tasks/:id', name: 'task-detail', component: TaskDetailView, props: true },
    { path: '/findings', name: 'findings', component: FindingCenterView },
    { path: '/findings/:id', name: 'finding-detail', component: FindingDetailView, props: true },
    { path: '/reports', name: 'reports', component: ReportCenterView },
    { path: '/settings', name: 'settings', component: SettingsView, meta: { requiresAdmin: true } },
    { path: '/users', name: 'users', component: UserManageView, meta: { requiresAdmin: true } },
    { path: '/audit-log', name: 'audit-log', component: AuditLogView, meta: { requiresAdmin: true } },
    { path: '/model-logs', name: 'model-logs', component: ModelCallLogView, meta: { requiresAdmin: true } },
  ],
})

function storedRole() {
  try {
    const raw = localStorage.getItem('rabbit_user')
    if (!raw) return ''
    const user = JSON.parse(raw)
    return typeof user?.role === 'string' ? user.role : ''
  } catch {
    localStorage.removeItem('rabbit_user')
    return ''
  }
}

// Auth guard
router.beforeEach((to) => {
  const token = localStorage.getItem('rabbit_token')
  if (!to.meta?.public && !token) {
    return { name: 'login' }
  }
  if (to.meta?.requiresAdmin && storedRole() !== 'admin') {
    return { name: 'tasks' }
  }
  if (to.name === 'login' && token) {
    return { name: 'dashboard' }
  }
})

export default router
