import axios from 'axios'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api/v1',
  timeout: 30000,
})

// Add auth token to all requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('rabbit_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle 401 responses globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('rabbit_token')
      localStorage.removeItem('rabbit_user')
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export interface SecurityTask {
  id: number
  name: string
  taskType: 'code_audit' | 'pentest' | 'hybrid'
  status: string
  objective: string
  modelConfigId?: number
  workerModelConfigId?: number
  isTestTask?: boolean
  archived?: boolean
  progressStage: string
  progressPercent: number
  scopeJson: unknown
  authorizationJson: unknown
  safePolicyJson: unknown
  createdAt: string
  updatedAt: string
  startedAt?: string
  finishedAt?: string
}

export interface ToolRun {
  id: number
  taskId: number
  runnerType: string
  toolName: string
  commandPreview: string
  containerId: string
  imageName: string
  workspacePath: string
  networkPolicy: string
  status: string
  blockReason: string
  stdoutRef: string
  stderrRef: string
  createdAt: string
  startedAt: string
  finishedAt?: string
}

export interface Evidence {
  id: number
  taskId: number
  toolRunId?: number
  evidenceType: string
  title: string
  summary: string
  hash: string
  target: string
  filePath: string
  lineStart?: number
  artifactUrl: string
  relationType: string
  redacted: boolean
  createdAt: string
}

export interface Finding {
  id: number
  taskId: number
  title: string
  vulnerabilityType: string
  affectedTarget: string
  affectedComponent: string
  severity: string
  status: string
  validationStatus: string
  contractStatus: string
  richDetails?: Record<string, unknown>
  evidenceRefs?: number[]
  remediation: string
  retestSteps: string
  humanReviewStatus: string
  humanReviewNote: string
  createdAt: string
}

export interface Report {
  id: number
  taskId: number
  title: string
  status: string
  format: string
  markdownRef: string
  htmlRef: string
  summary: string
  generatedAt?: string
}

export interface TimelineEvent {
  id: number
  taskId?: number
  eventType: string
  actor: string
  summary: string
  metadata?: Record<string, unknown>
  occurredAt: string
}

export interface BlackboardNode {
  id: number
  nodeType: string
  title: string
  summary: string
  importanceScore: number
  status: string
}

export interface TaskDetail {
  task: SecurityTask
  toolRuns: ToolRun[]
  evidence: Evidence[]
  findings: Finding[]
  reports: Report[]
  intents: Intent[]
  contractChecks: ContractCheck[]
  timeline: TimelineEvent[]
  blackboard: BlackboardNode[]
}

export interface Overview {
  totalTasks: number
  runningTasks: number
  pendingReviews: number
  highRiskFindings: number
  recentTasks: SecurityTask[]
  runnerHealth: Record<string, string>
}

export interface CreateTaskPayload {
  name: string
  taskType: string
  objective: string
  targets: string[]
  includePaths: string[]
  excludePaths: string[]
  authorizationLevel: number
  allowChainExploration: boolean
  allowReadOnlyCommands: boolean
  allowEvidenceProofCommands?: boolean
  modelConfigId?: number
  workerModelConfigId?: number
  isTestTask?: boolean
}

export interface Intent {
  id: number
  taskId: number
  intentType: string
  title: string
  objective: string
  priorityScore: number
  status: string
  createdBy: string
  createdReason: string
  createdAt: string
  updatedAt: string
}

export interface ContractCheck {
  id: number
  findingId: number
  taskId: number
  contractType: string
  status: string
  downgradeReason: string
  checkedAt: string
}

export interface ModelConfig {
  id: number
  name: string
  purpose: 'brain' | 'worker'
  provider: string
  baseUrl: string
  model: string
  apiKeyRef: string
  optionsJson: unknown
  enabled: boolean
  createdAt: string
  updatedAt: string
}

export const platformApi = {
  overview: async () => (await api.get<Overview>('/overview')).data,
  listModelConfigs: async () => (await api.get<ModelConfig[]>('/model-configs')).data,
  createModelConfig: async (payload: Omit<ModelConfig, 'id' | 'createdAt' | 'updatedAt'>) => (await api.post<ModelConfig>('/model-configs', payload)).data,
  updateModelConfig: async (id: number, payload: Omit<ModelConfig, 'id' | 'createdAt' | 'updatedAt'>) => (await api.patch<ModelConfig>(`/model-configs/${id}`, payload)).data,
  listTasks: async () => (await api.get<SecurityTask[]>('/tasks')).data,
  listTasksWithQuery: async (suffix = '') => (await api.get<SecurityTask[]>(`/tasks${suffix}`)).data,
  listFindings: async () => (await api.get<Finding[]>('/findings')).data,
  listReports: async () => (await api.get<Report[]>('/reports')).data,
  createTask: async (payload: CreateTaskPayload) => (await api.post<SecurityTask>('/tasks', payload)).data,
  getTask: async (id: number) => (await api.get<TaskDetail>(`/tasks/${id}`)).data,
  getFinding: async (id: number) => (await api.get<Finding>(`/findings/${id}`)).data,
  startTask: async (id: number) => (await api.post(`/tasks/${id}/start`)).data,
  deleteTask: async (id: number) => (await api.delete(`/tasks/${id}`)).data,
  restartTask: async (id: number) => (await api.post(`/tasks/${id}/restart`)).data,
  exportTaskFindings: async (id: number) => (await api.get(`/tasks/${id}/export/findings?format=csv`, { responseType: 'blob' })).data as Blob,
  exportTaskEvidence: async (id: number) => (await api.get(`/tasks/${id}/export/evidence?format=csv`, { responseType: 'blob' })).data as Blob,
  uploadZip: async (id: number, file: File) => {
    const form = new FormData()
    form.append('file', file)
    return (await api.post(`/tasks/${id}/upload`, form)).data
  },
  // User management
  listUsers: async () => (await api.get('/users')).data,
  createUser: async (payload: { username: string; password: string; displayName: string; role: string }) => (await api.post('/users', payload)).data,
  updateUser: async (id: number, payload: any) => (await api.patch(`/users/${id}`, payload)).data,
  // Audit log
  listAuditEvents: async (params?: { taskId?: string; eventType?: string }) => {
    const query = new URLSearchParams()
    if (params?.taskId) query.set('taskId', params.taskId)
    if (params?.eventType) query.set('eventType', params.eventType)
    const suffix = query.toString()
    return (await api.get(`/audit-events${suffix ? '?' + suffix : ''}`)).data
  },
}
