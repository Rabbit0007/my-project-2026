<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">系统管理</p>
        <h1 class="page-title">模型管理</h1>
        <p class="subcopy">配置 AI 模型接口，平台会自动检测接口类型并用于代码审计和渗透测试的深度推理。</p>
      </div>
    </div>

    <!-- Model Cards -->
    <div class="model-section">
      <div class="model-toolbar">
        <el-button type="primary" @click="openCreateDialog">
          <el-icon><Plus /></el-icon> 新建模型
        </el-button>
      </div>
      <div class="model-overview">
        <div class="model-overview__item">
          <span class="model-overview__label">启用 Brain</span>
          <strong>{{ brainCount }}</strong>
        </div>
        <div class="model-overview__item worker">
          <span class="model-overview__label">启用 Worker 配置</span>
          <strong>{{ workerCount }}</strong>
        </div>
        <div class="model-overview__item">
          <span class="model-overview__label">启用 Pi Container Worker</span>
          <strong>{{ piWorkerCount }}</strong>
        </div>
      </div>

      <div class="worker-explainer">
        <div>
          <strong>Worker 是用途角色</strong>
          <span>一个模型配置只能选择 Brain 或 Worker。Worker 配置会进入 Intent 执行池。</span>
        </div>
        <div>
          <strong>Pi Container Kali 是执行方式</strong>
          <span>执行方式选择 Pi Container Kali 后，它就是一个 Pi Worker；需要同一供应商同时做 Brain 和 Pi 时，请创建两条单角色配置。</span>
        </div>
      </div>

      <div v-if="configs.length > 0 && workerCount === 0" class="worker-empty-hint">
        <strong>当前还没有 Worker 模型。</strong>
        <span>点击“新建模型”，用途选择 Worker，再选择 Pi Container Kali，就会进入多 worker 执行池。</span>
      </div>

      <div v-if="configs.length === 0" class="model-empty">
        <el-empty description="暂无模型配置，点击上方按钮添加" />
      </div>

      <div v-else class="model-grid">
        <div
          v-for="config in configs"
          :key="config.id"
          class="model-card"
          :class="{ disabled: !config.enabled, 'is-worker': isWorkerConfig(config), 'is-brain': !isWorkerConfig(config) }"
        >
          <div class="model-card__header">
            <div class="model-card__icon">
              <span>{{ config.model.charAt(0).toUpperCase() }}</span>
            </div>
            <div class="model-card__info">
              <strong>{{ configTitle(config) }}</strong>
              <span class="model-card__provider">{{ configSubtitle(config) }}</span>
            </div>
            <span class="model-card__role" :class="{ worker: isWorkerConfig(config) }">
              {{ isWorkerConfig(config) ? workerDriverLabel(config) : 'Brain' }}
            </span>
            <span class="model-card__status" :class="config._status || (config.enabled ? 'online' : 'offline')">
              {{ config._statusText || (config.enabled ? '未测试' : '已禁用') }}
            </span>
          </div>
          <div class="model-card__body">
            <div class="model-card__purpose">
              {{ roleDescription(config) }}
            </div>
            <div class="model-card__field">
              <label>接口地址</label>
              <span>{{ config.baseUrl || '-' }}</span>
            </div>
            <div class="model-card__field">
              <label>API 密钥</label>
              <span>{{ maskKey(config.apiKeyRef) }}</span>
            </div>
            <template v-if="isWorkerConfig(config)">
              <div class="model-card__field">
                <label>执行方式</label>
                <span>{{ workerDriverLabel(config) }}</span>
              </div>
              <div class="model-card__field">
                <label>并发/优先级</label>
                <span>{{ workerConcurrencyLabel(config) }}</span>
              </div>
              <div class="model-card__field">
                <label>适用任务</label>
                <span>{{ workerTaskTypesLabel(config) }}</span>
              </div>
              <div class="tool-chip-row">
                <span v-for="tool in workerTools(config)" :key="tool" class="tool-chip">{{ tool }}</span>
              </div>
            </template>
          </div>
          <div class="model-card__footer">
            <span class="model-card__time">{{ formatTime(config.updatedAt || config.createdAt) }}</span>
            <div class="model-card__actions">
              <el-button size="small" text @click="testConnection(config)" :loading="config._testing">
                测试
              </el-button>
              <el-button size="small" text @click="copyConfig(config)" :loading="config._copying">
                <el-icon><CopyDocument /></el-icon>
                复制
              </el-button>
              <el-button size="small" text @click="openEditDialog(config)">
                <el-icon><Edit /></el-icon>
              </el-button>
              <el-button size="small" text type="danger" @click="toggleEnabled(config)">
                {{ config.enabled ? '禁用' : '启用' }}
              </el-button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create/Edit Dialog -->
    <el-dialog
      v-model="dialogVisible"
      :title="editingId ? '编辑模型' : '新建模型'"
      width="520px"
      :close-on-click-modal="false"
    >
      <el-form :model="form" label-position="top" class="model-form">
        <div class="form-row">
          <el-form-item label="用途" class="form-half">
            <el-select v-model="form.purpose" placeholder="选择用途">
              <el-option label="Brain：推理 / 报告 / 聊天" value="brain" />
              <el-option label="Worker：只进入 Intent 执行池" value="worker" />
            </el-select>
          </el-form-item>
          <el-form-item label="模型厂商" class="form-half">
            <el-select v-model="form.provider" placeholder="选择厂商">
              <el-option label="OpenAI 兼容 / 本地网关" value="openai-compatible" />
              <el-option label="OpenAI 官方" value="openai" />
              <el-option label="智谱" value="zhipu" />
              <el-option label="百炼" value="bailian" />
            </el-select>
          </el-form-item>
          <el-form-item label="模型名称" class="form-half">
            <el-input v-model="form.model" placeholder="例如：glm-5" />
          </el-form-item>
        </div>
        <div v-if="form.purpose !== 'brain'" class="form-row">
          <el-form-item label="Worker 优先级" class="form-half">
            <el-input-number v-model="form.workerPriority" :min="0" :max="100" controls-position="right" />
          </el-form-item>
          <el-form-item label="最大并发" class="form-half">
            <el-input-number v-model="form.workerMaxRunning" :min="1" :max="20" controls-position="right" />
          </el-form-item>
        </div>
        <el-form-item v-if="form.purpose !== 'brain'" label="Worker 适用任务">
          <el-select v-model="form.workerTaskTypes" multiple placeholder="不选表示所有 Intent">
            <el-option label="全部" value="all" />
            <el-option label="渗透验证" value="pentest" />
            <el-option label="代码审计" value="code_audit" />
            <el-option label="Reason" value="reason" />
            <el-option label="Explore" value="explore" />
          </el-select>
        </el-form-item>
        <div v-if="form.purpose !== 'brain'" class="form-row">
          <el-form-item label="执行方式" class="form-half">
            <el-select v-model="form.workerDriver" placeholder="选择执行方式">
              <el-option label="Pi Container Kali：Pi Worker" value="pi_container_kali" />
              <el-option label="Native：Rabbit 内置 Runner 兜底" value="native" />
            </el-select>
          </el-form-item>
          <el-form-item label="Worker 工具" class="form-half">
            <el-select v-model="form.workerTools" multiple placeholder="Pi 可用工具">
              <el-option label="read" value="read" />
              <el-option label="write" value="write" />
              <el-option label="edit" value="edit" />
              <el-option label="bash" value="bash" />
              <el-option label="grep" value="grep" />
              <el-option label="find" value="find" />
              <el-option label="ls" value="ls" />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item label="接口地址">
          <el-input v-model="form.baseUrl" placeholder="例如：http://10.2.8.77:3000/v1" />
        </el-form-item>
        <el-form-item label="API 密钥">
          <el-input v-model="form.apiKeyRef" placeholder="输入 API Key" show-password />
        </el-form-item>
        <el-form-item label="自定义请求头">
          <el-input
            v-model="form.customHeaders"
            type="textarea"
            :rows="3"
            placeholder="JSON 格式，例如：{}"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveConfig">保存</el-button>
      </template>
    </el-dialog>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus, Edit, CopyDocument } from '@element-plus/icons-vue'
import { platformApi, type ModelConfig } from '@/api/client'
import { api } from '@/api/client'

const configs = ref<any[]>([])
const saving = ref(false)
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const defaultWorkerTools = ['read', 'write', 'edit', 'bash', 'grep', 'find', 'ls']

const form = reactive({
  purpose: 'brain' as 'brain' | 'worker',
  provider: 'openai-compatible',
  model: '',
  baseUrl: '',
  apiKeyRef: '',
  customHeaders: '',
  workerPriority: 0,
  workerMaxRunning: 2,
  workerTaskTypes: [] as string[],
  workerDriver: 'native' as 'native' | 'pi_container_kali',
  workerTools: [] as string[],
})

const brainCount = computed(() => configs.value.filter((config) => config.enabled && (config.purpose === 'brain' || !config.purpose)).length)
const workerCount = computed(() => configs.value.filter((config) => config.enabled && isWorkerConfig(config)).length)
const piWorkerCount = computed(() => configs.value.filter((config) => config.enabled && isWorkerConfig(config) && workerDriver(config).startsWith('pi_')).length)

async function loadConfigs() {
  try {
    configs.value = await platformApi.listModelConfigs()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载失败')
  }
}

function openCreateDialog() {
  editingId.value = null
  form.purpose = 'brain'
  form.provider = 'openai-compatible'
  form.model = ''
  form.baseUrl = ''
  form.apiKeyRef = ''
  form.customHeaders = ''
  form.workerPriority = 0
  form.workerMaxRunning = 2
  form.workerTaskTypes = []
  form.workerDriver = 'pi_container_kali'
  form.workerTools = []
  dialogVisible.value = true
}

function openEditDialog(config: ModelConfig) {
  editingId.value = config.id
  form.purpose = config.purpose === 'worker' ? 'worker' : 'brain'
  form.provider = config.provider
  form.model = config.model
  form.baseUrl = config.baseUrl
  form.apiKeyRef = config.apiKeyRef
  const options = normalizeOptions(config.optionsJson)
  form.customHeaders = options.customHeaders ? JSON.stringify(options.customHeaders, null, 2) : ''
  form.workerPriority = Number(options.workerPriority ?? 0)
  form.workerMaxRunning = Number(options.workerMaxRunning ?? 2)
  form.workerTaskTypes = Array.isArray(options.workerTaskTypes) ? options.workerTaskTypes.map(String) : []
  form.workerDriver = options.workerDriver === 'native' ? 'native' : 'pi_container_kali'
  form.workerTools = Array.isArray(options.workerTools) ? options.workerTools.map(String) : []
  dialogVisible.value = true
}

async function saveConfig() {
  if (!form.model.trim()) {
    ElMessage.warning('请填写模型名称')
    return
  }
  if (!form.baseUrl.trim()) {
    ElMessage.warning('请填写接口地址')
    return
  }
  saving.value = true
  try {
    // Auto-detect wire API from base URL
    const wireApi = 'chat_completions'
    let customHeaders = {}
    if (form.customHeaders.trim()) {
      try {
        const parsed = JSON.parse(form.customHeaders)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          ElMessage.warning('自定义请求头必须是 JSON 对象')
          return
        }
        customHeaders = parsed
      } catch {
        ElMessage.warning('自定义请求头不是合法 JSON')
        return
      }
    }

    const payload = {
      name: form.model,
      purpose: form.purpose,
      provider: form.provider,
      baseUrl: form.baseUrl.replace(/\/+$/, ''),
      model: form.model,
      apiKeyRef: form.apiKeyRef,
      optionsJson: {
        wireApi,
        modelReasoningEffort: 'high',
        requiresOpenAIAuth: !!form.apiKeyRef,
        networkAccess: 'enabled',
        customHeaders,
        workerPriority: form.workerPriority,
        workerMaxRunning: form.workerMaxRunning,
        workerTaskTypes: form.workerTaskTypes,
        workerDriver: form.workerDriver,
        workerTools: form.workerTools,
      },
      enabled: true,
    }
    if (editingId.value) {
      await platformApi.updateModelConfig(editingId.value, payload)
      ElMessage.success('模型已更新')
    } else {
      await platformApi.createModelConfig(payload)
      ElMessage.success('模型已创建')
    }
    dialogVisible.value = false
    await loadConfigs()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}

async function toggleEnabled(config: ModelConfig) {
  try {
    await platformApi.updateModelConfig(config.id, {
      ...config,
      purpose: config.purpose === 'worker' ? 'worker' : 'brain',
      enabled: !config.enabled,
    } as any)
    await loadConfigs()
    ElMessage.success(config.enabled ? '已禁用' : '已启用')
  } catch (error: any) {
    ElMessage.error('操作失败')
  }
}

async function copyConfig(config: any) {
  config._copying = true
  try {
    const payload = {
      name: duplicateName(config),
      purpose: config.purpose === 'worker' ? 'worker' : 'brain',
      provider: config.provider,
      baseUrl: config.baseUrl,
      model: config.model,
      apiKeyRef: config.apiKeyRef,
      optionsJson: cloneOptions(config.optionsJson),
      enabled: false,
    }
    await platformApi.createModelConfig(payload as any)
    await loadConfigs()
    ElMessage.success('已复制为禁用副本，可编辑后启用')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '复制失败')
  } finally {
    config._copying = false
  }
}

async function testConnection(config: any) {
  config._testing = true
  config._status = ''
  config._statusText = '测试中...'
  try {
    const res = await api.post(`/model-configs/${config.id}/test`)
    if (res.data.success) {
      config._status = 'online'
      config._statusText = `在线 ${res.data.latencyMs}ms`
      ElMessage.success(`${config.model} 连接成功 (${res.data.latencyMs}ms)`)
    } else {
      config._status = 'offline'
      config._statusText = '离线'
      ElMessage.error(res.data.message || '连接失败')
    }
  } catch (err: any) {
    config._status = 'offline'
    config._statusText = '离线'
    ElMessage.error(err?.response?.data?.error || '测试失败')
  } finally {
    config._testing = false
  }
}

function maskKey(key: string) {
  if (!key) return '-'
  if (key.length <= 12) return '••••••••'
  return key.slice(0, 8) + '••••' + key.slice(-4)
}

function formatTime(time: string) {
  if (!time) return ''
  const d = new Date(time)
  return d.toLocaleDateString('zh-CN') + ' ' + d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
}

function purposeLabel(purpose: string) {
  if (purpose === 'worker') return 'Worker'
  if (purpose === 'both') return '旧 Both（请编辑）'
  return 'Brain'
}

function configTitle(config: ModelConfig | any) {
  return config?.name || config?.model || '-'
}

function configSubtitle(config: ModelConfig | any) {
  const model = config?.name && config.name !== config.model ? ` · ${config.model}` : ''
  return `${config?.provider || '-'}${model} · ${purposeLabel(config?.purpose)}`
}

function duplicateName(config: ModelConfig | any) {
  const baseName = (config?.name || config?.model || 'model').trim()
  const existingNames = new Set(configs.value.map((item) => String(item.name || '').trim()).filter(Boolean))
  let candidate = `${baseName} 副本`
  let index = 2
  while (existingNames.has(candidate)) {
    candidate = `${baseName} 副本 ${index}`
    index += 1
  }
  return candidate
}

function cloneOptions(value: unknown) {
  return JSON.parse(JSON.stringify(normalizeOptions(value)))
}

function normalizeOptions(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>
  return {}
}

function modelOptions(config: ModelConfig | any): Record<string, unknown> {
  return normalizeOptions(config?.optionsJson)
}

function isWorkerConfig(config: ModelConfig | any) {
  return config?.purpose === 'worker'
}

function workerDriver(config: ModelConfig | any) {
  const value = modelOptions(config).workerDriver
  if (value === 'pi_container_kali') return 'pi_container_kali'
  if (value === 'pi_cli') return 'pi_container_kali'
  return 'native'
}

function workerDriverLabel(config: ModelConfig | any) {
  const driver = workerDriver(config)
  if (driver === 'pi_container_kali') return 'Pi Container Kali Worker'
  return 'Native Worker'
}

function workerTools(config: ModelConfig | any) {
  const value = modelOptions(config).workerTools
  if (!Array.isArray(value) || value.length === 0) return defaultWorkerTools
  return value.map(String).filter(Boolean)
}

function workerTaskTypesLabel(config: ModelConfig | any) {
  const value = modelOptions(config).workerTaskTypes
  if (!Array.isArray(value) || value.length === 0 || value.includes('all')) return '全部 Intent'
  return value.map(String).join(' / ')
}

function workerConcurrencyLabel(config: ModelConfig | any) {
  const options = modelOptions(config)
  const maxRunning = Number(options.workerMaxRunning ?? 2)
  const priority = Number(options.workerPriority ?? 0)
  return `并发 ${maxRunning} · 优先级 ${priority}`
}

function roleDescription(config: ModelConfig | any) {
  if (config?.purpose === 'both') return '旧版双用途配置已停用为有效角色；请编辑后选择 Brain 或 Worker。'
  if (config?.purpose === 'worker') return '只作为 Worker 执行 Intent，结果以 Fact / Evidence 回写图状态。'
  return '作为 Brain 负责推理、报告、聊天与图状态判断，不直接执行 Intent。'
}

onMounted(loadConfigs)
</script>

<style scoped>
.model-section {
  margin-top: 8px;
}

.model-toolbar {
  margin-bottom: 20px;
}

.model-overview {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 14px;
  max-width: 720px;
}

.model-overview__item {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--bg-card) 92%, #ffffff);
  padding: 12px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 52px;
}

.model-overview__item.worker {
  border-color: rgba(37, 99, 235, 0.28);
  background: rgba(37, 99, 235, 0.06);
}

.model-overview__label {
  font-size: 12px;
  color: var(--text-muted);
}

.model-overview__item strong {
  font-size: 22px;
  color: var(--text-primary);
}

.worker-empty-hint {
  max-width: 720px;
  margin-bottom: 18px;
  border: 1px solid rgba(37, 99, 235, 0.22);
  border-radius: 8px;
  background: rgba(37, 99, 235, 0.06);
  padding: 12px 14px;
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  font-size: 13px;
  color: var(--text-secondary);
}

.worker-empty-hint strong {
  color: var(--text-primary);
}

.worker-explainer {
  max-width: 920px;
  margin-bottom: 14px;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.worker-explainer > div {
  min-height: 78px;
  padding: 14px 16px;
  border: 1px solid rgba(37, 99, 235, 0.16);
  border-radius: 8px;
  background: rgba(37, 99, 235, 0.045);
}

.worker-explainer strong {
  display: block;
  margin-bottom: 6px;
  color: var(--text-primary);
  font-size: 13px;
}

.worker-explainer span {
  display: block;
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.6;
}

.model-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: 16px;
}

.model-card {
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg-card);
  padding: 20px;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.model-card:hover {
  border-color: var(--border-active);
  box-shadow: var(--shadow-glow);
}

.model-card.is-worker {
  border-color: rgba(37, 99, 235, 0.28);
  background: linear-gradient(180deg, rgba(37, 99, 235, 0.04), var(--bg-card) 42%);
}

.model-card.disabled {
  opacity: 0.5;
}

.model-card__header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.model-card__icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: linear-gradient(135deg, #38bdf8, #6366f1);
  display: grid;
  place-items: center;
  flex-shrink: 0;
}

.model-card__icon span {
  color: #fff;
  font-size: 18px;
  font-weight: 700;
}

.model-card__info {
  flex: 1;
  min-width: 0;
}

.model-card__info strong {
  display: block;
  font-size: 15px;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.model-card__provider {
  font-size: 12px;
  color: var(--text-muted);
}

.model-card__status {
  font-size: 11px;
  font-weight: 600;
  padding: 3px 8px;
  border-radius: 999px;
}

.model-card__role {
  font-size: 11px;
  font-weight: 700;
  color: #334155;
  background: rgba(100, 116, 139, 0.1);
  border: 1px solid rgba(100, 116, 139, 0.16);
  padding: 4px 8px;
  border-radius: 999px;
  white-space: nowrap;
}

.model-card__role.worker {
  color: #1d4ed8;
  background: rgba(37, 99, 235, 0.1);
  border-color: rgba(37, 99, 235, 0.22);
}

.model-card__status.online {
  background: rgba(16, 185, 129, 0.12);
  color: var(--success);
}

.model-card__status.offline {
  background: rgba(244, 63, 94, 0.1);
  color: var(--danger);
}

.model-card__body {
  display: grid;
  gap: 8px;
  margin-bottom: 14px;
}

.model-card__purpose {
  font-size: 12px;
  line-height: 1.55;
  color: var(--text-muted);
  padding: 8px 10px;
  border-radius: 8px;
  background: rgba(148, 163, 184, 0.08);
}

.model-card__field {
  display: flex;
  align-items: baseline;
  gap: 8px;
  font-size: 12px;
}

.model-card__field label {
  color: var(--text-muted);
  flex-shrink: 0;
  min-width: 56px;
}

.model-card__field span {
  color: var(--text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.tool-chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding-top: 2px;
}

.tool-chip {
  font-size: 11px;
  line-height: 1;
  color: #1d4ed8;
  border: 1px solid rgba(37, 99, 235, 0.2);
  background: rgba(37, 99, 235, 0.08);
  border-radius: 999px;
  padding: 5px 8px;
}

.model-card__footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-top: 12px;
  border-top: 1px solid var(--border);
}

.model-card__time {
  font-size: 11px;
  color: var(--text-muted);
}

.model-card__actions {
  display: flex;
  gap: 4px;
}

.model-form .form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.model-form .form-half {
  margin-bottom: 0;
}

.model-empty {
  padding: 60px 0;
  text-align: center;
}

@media (max-width: 860px) {
  .model-overview,
  .worker-explainer {
    grid-template-columns: 1fr;
  }
}
</style>
