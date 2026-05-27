<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">Task Wizard</p>
        <h1 class="page-title">{{ pageTitle }}</h1>
        <p class="subcopy">{{ pageSubcopy }}</p>
      </div>
    </div>

    <div class="glass-card section-card">
      <el-steps :active="active" finish-status="success" align-center>
        <el-step v-for="step in stepTitles" :key="step" :title="step" />
      </el-steps>

      <div style="margin-top: 28px">
        <div v-if="active === 0" class="two-column">
          <el-card shadow="never" :class="{ selected: form.taskType === 'code_audit' }" @click="form.taskType = 'code_audit'">
            <h2>代码审计</h2>
            <p class="quiet">上传 ZIP，执行安全解压、Source/Sink 检索、证据沉淀与报告生成。</p>
          </el-card>
          <el-card shadow="never" :class="{ selected: form.taskType === 'pentest' }" @click="form.taskType = 'pentest'">
            <h2>渗透验证</h2>
            <p class="quiet">输入授权 URL/域名，执行 HTTP baseline、范围校验和证据采集。</p>
          </el-card>
        </div>

        <el-form v-if="active === 1" label-position="top">
          <div v-if="form.taskType === 'code_audit'" class="wizard-note-card">
            <strong>代码审计交付路径</strong>
            <p>这一步只填写代码包说明与审计目标，不在这里上传源码。创建任务后会自动跳转到任务详情页，下一步就是上传 ZIP 并启动审计。</p>
          </div>
          <el-form-item label="任务名称">
            <el-input v-model="form.name" placeholder="例如：生产门户代码审计" />
          </el-form-item>
          <el-form-item :label="scopeLabel">
            <el-input
              v-model="targetText"
              type="textarea"
              :rows="5"
              :placeholder="scopePlaceholder"
            />
          </el-form-item>
          <el-alert
            v-if="form.taskType === 'code_audit'"
            style="margin-bottom: 18px"
            type="info"
            :closable="false"
            show-icon
            title="代码审计任务会在创建后进入任务详情页，下一步需要上传 ZIP 代码包，再启动审计。"
          />
          <el-form-item :label="descriptionLabel">
            <el-input v-model="form.objective" type="textarea" :rows="4" :placeholder="descriptionPlaceholder" />
          </el-form-item>
        </el-form>

        <el-form v-if="active === 2" label-position="top">
          <div class="evidence-policy-card">
            <div>
              <p class="policy-kicker">Evidence Proof Policy</p>
              <strong>非破坏性证据证明策略</strong>
              <p>
                Worker 可以在授权范围内执行证据证明动作，例如 whoami / id / hostname、marker 回显、临时 proof 文件、无害上传证明、请求包与响应包采集。
              </p>
            </div>
            <div class="policy-lists">
              <div>
                <span>允许</span>
                <p>命令回显、marker、proof 文件、授权范围内 HTTP 验证、上传证明 URL。</p>
              </div>
              <div>
                <span>阻断</span>
                <p>删除、杀进程、下载执行、持久化、清痕、资源破坏和出范围访问。</p>
              </div>
            </div>
          </div>
          <el-form-item style="margin-top: 18px" label="Brain 模型">
            <el-select v-model="form.modelConfigId" placeholder="可选：选择一个已保存模型配置" clearable>
              <el-option v-for="config in enabledBrainModelConfigs" :key="config.id" :label="`${config.name} · ${config.model}`" :value="config.id" />
            </el-select>
          </el-form-item>
          <div class="worker-pool-card" :class="{ empty: enabledWorkerModelConfigs.length === 0 }">
            <div>
              <p class="policy-kicker">Worker Pool</p>
              <strong>{{ workerPoolTitle }}</strong>
              <p>{{ workerPoolDescription }}</p>
            </div>
            <div class="worker-pool-stats">
              <span>Pi Container：{{ enabledPiWorkerConfigs.length }}</span>
              <span>Native：{{ enabledNativeWorkerConfigs.length }}</span>
            </div>
          </div>
          <el-alert
            v-if="enabledWorkerModelConfigs.length === 0"
            style="margin: 14px 0 18px"
            type="warning"
            :closable="false"
            show-icon
            title="当前没有启用的 Worker。请到模型管理启用用途为 Worker 且执行方式为 Pi Container Kali 的模型配置。"
          />
          <el-form-item label="执行 Worker">
            <el-select
              v-model="form.workerModelConfigId"
              :placeholder="workerSelectPlaceholder"
              :disabled="enabledWorkerModelConfigs.length === 0"
              clearable
            >
              <el-option
                v-for="config in enabledWorkerModelConfigs"
                :key="config.id"
                :label="`${config.name} · ${config.model} · ${workerDriverLabel(config)}`"
                :value="config.id"
              >
                <div class="worker-option">
                  <span>{{ config.name }} · {{ config.model }}</span>
                  <small>{{ workerDriverLabel(config) }} · {{ workerConcurrencyLabel(config) }}</small>
                </div>
              </el-option>
            </el-select>
            <p class="quiet model-help">
              留空会使用所有可用 Worker 池自动调度；选择一个 Worker 会把这个任务固定到该 Worker。Worker 只执行当前 Intent 并回写 Fact / Evidence。
            </p>
          </el-form-item>
        </el-form>

        <div v-if="active === 3">
          <el-descriptions border :column="2">
            <el-descriptions-item label="任务名称">{{ form.name || '未命名任务' }}</el-descriptions-item>
            <el-descriptions-item label="任务类型">{{ form.taskType }}</el-descriptions-item>
            <el-descriptions-item label="证据策略">非破坏性证据证明</el-descriptions-item>
            <el-descriptions-item label="目标数量">{{ targets.length }}</el-descriptions-item>
            <el-descriptions-item label="Brain 模型">{{ selectedModelLabel }}</el-descriptions-item>
            <el-descriptions-item label="执行 Worker">{{ selectedWorkerModelLabel }}</el-descriptions-item>
          </el-descriptions>
          <el-alert
            v-if="form.taskType === 'code_audit'"
            style="margin-top: 18px"
            type="info"
            show-icon
            :closable="false"
            title="创建完成后会立即跳转到任务详情页。下一步顺序是：上传 ZIP 代码包 -> 等待安全解压 -> 点击开始执行。"
          />
          <el-alert
            style="margin-top: 18px"
            type="warning"
            show-icon
            title="平台会阻断删除、杀进程、下载执行、持久化、清痕、资源破坏和出范围访问。"
          />
        </div>
      </div>

      <div class="toolbar" style="margin-top: 28px">
        <el-button :disabled="active === 0" @click="active--">上一步</el-button>
        <div>
          <el-button v-if="active < 3" type="primary" @click="goNext">下一步</el-button>
          <el-button v-else type="primary" :loading="submitting" @click="submit">{{ submitLabel }}</el-button>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { platformApi, type ModelConfig } from '@/api/client'

const router = useRouter()
const active = ref(0)
const submitting = ref(false)
const targetText = ref('')
const modelConfigs = ref<ModelConfig[]>([])
const form = reactive({
  name: '',
  taskType: 'code_audit',
  objective: '',
  authorizationLevel: 1,
  allowReadOnlyCommands: true,
  allowChainExploration: true,
  allowEvidenceProofCommands: true,
  modelConfigId: undefined as number | undefined,
  workerModelConfigId: undefined as number | undefined,
})

const pageTitle = computed(() => (form.taskType === 'code_audit' ? '创建代码审计任务' : '创建授权验证任务'))
const pageSubcopy = computed(() =>
  form.taskType === 'code_audit'
    ? '先创建任务并说明代码包背景，随后在任务详情页上传 ZIP，平台会完成安全解压、代码检索、证据沉淀与报告生成。'
    : '用产品语言配置任务，底层会自动转换为 Scope、SafePolicy、Intent 和 Evidence。',
)
const stepTitles = computed(() =>
  form.taskType === 'code_audit'
    ? ['任务类型', '代码包说明', '验证与模型', '创建并上传']
    : ['任务类型', '目标范围', '验证与模型', '确认启动'],
)
const targets = computed(() => targetText.value.split('\n').map((item) => item.trim()).filter(Boolean))
const enabledModelConfigs = computed(() => modelConfigs.value.filter((config) => config.enabled))
const enabledBrainModelConfigs = computed(() => enabledModelConfigs.value.filter((config) => !config.purpose || config.purpose === 'brain'))
const enabledWorkerModelConfigs = computed(() => enabledModelConfigs.value.filter((config) => config.purpose === 'worker'))
const enabledPiWorkerConfigs = computed(() => enabledWorkerModelConfigs.value.filter((config) => workerDriver(config) === 'pi_container_kali'))
const enabledNativeWorkerConfigs = computed(() => enabledWorkerModelConfigs.value.filter((config) => workerDriver(config) === 'native'))
const scopeLabel = computed(() => (form.taskType === 'code_audit' ? '代码包说明 / 仓库信息' : '授权目标 / 范围'))
const scopePlaceholder = computed(() =>
  form.taskType === 'code_audit'
    ? '可填写仓库名称、分支、语言、框架或代码包说明。ZIP 会在任务创建后单独上传。'
    : '每行一个 URL、域名、IP、CIDR 或仓库说明',
)
const descriptionLabel = computed(() => (form.taskType === 'code_audit' ? '审计说明' : '验证说明'))
const descriptionPlaceholder = computed(() =>
  form.taskType === 'code_audit'
    ? '补充业务背景、重点模块、关注语言/框架或报告交付目标'
    : '补充业务背景、重点资产或报告交付目标',
)
const selectedModelLabel = computed(() => {
  const selected = enabledBrainModelConfigs.value.find((config) => config.id === form.modelConfigId)
  return selected ? `${selected.name} · ${selected.model}` : '默认模型'
})
const selectedWorkerModelLabel = computed(() => {
  const selected = enabledWorkerModelConfigs.value.find((config) => config.id === form.workerModelConfigId)
  return selected ? `${selected.name} · ${selected.model} · ${workerDriverLabel(selected)}` : '自动选择 Worker 池'
})
const submitLabel = computed(() => (form.taskType === 'code_audit' ? '创建任务并进入上传' : '创建任务'))
const workerPoolTitle = computed(() => {
  if (enabledWorkerModelConfigs.value.length === 0) return '没有可用 Worker'
  return `${enabledWorkerModelConfigs.value.length} 个可用 Worker，${enabledPiWorkerConfigs.value.length} 个 Pi Container Worker`
})
const workerPoolDescription = computed(() => {
  if (enabledWorkerModelConfigs.value.length === 0) return '任务可以创建，但启动后没有外部 Worker 可接手 Intent，需要先启用 Worker 配置。'
  return '不指定执行 Worker 时，后端会从这个池里按优先级、并发和任务类型自动选择；一个 Intent 只会被一个 Worker 领取。'
})
const workerSelectPlaceholder = computed(() => (
  enabledWorkerModelConfigs.value.length === 0 ? '没有可用 Worker' : '留空使用全部 Worker 池'
))

function validateBasics() {
  if (!form.name.trim()) {
    ElMessage.warning('请填写任务名称')
    return false
  }
  if (targets.value.length === 0) {
    ElMessage.warning(form.taskType === 'code_audit' ? '请填写代码包说明 / 仓库信息' : '请填写至少一个授权目标')
    return false
  }
  if (!form.objective.trim()) {
    ElMessage.warning(form.taskType === 'code_audit' ? '请填写审计说明' : '请填写验证说明')
    return false
  }
  return true
}

function validateCurrentStep() {
  if (active.value === 1) return validateBasics()
  return true
}

function goNext() {
  if (!validateCurrentStep()) return
  active.value += 1
}

function modelOptions(config: ModelConfig | any): Record<string, unknown> {
  const raw = config?.optionsJson
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  return raw as Record<string, unknown>
}

function workerDriverLabel(config: ModelConfig | any) {
  const driver = workerDriver(config)
  if (driver === 'pi_container_kali') return 'Pi Container Kali Worker'
  return 'Native Worker'
}

function workerDriver(config: ModelConfig | any) {
  const driver = modelOptions(config).workerDriver
  if (driver === 'pi_container_kali' || driver === 'pi_cli') return 'pi_container_kali'
  return 'native'
}

function workerConcurrencyLabel(config: ModelConfig | any) {
  const options = modelOptions(config)
  const maxRunning = Number(options.workerMaxRunning ?? 2)
  const priority = Number(options.workerPriority ?? 0)
  return `并发 ${maxRunning} / 优先级 ${priority}`
}

async function submit() {
  if (!validateBasics()) return
  submitting.value = true
  try {
    const task = await platformApi.createTask({
      ...form,
      authorizationLevel: 1,
      allowReadOnlyCommands: true,
      allowChainExploration: true,
      allowEvidenceProofCommands: true,
      targets: targets.value,
      includePaths: [],
      excludePaths: [],
    })
    if (form.taskType === 'code_audit') {
      ElMessage.success('任务已创建，下一步请上传代码 ZIP 并启动审计')
      router.push({ path: `/tasks/${task.id}`, query: { next: 'upload' } })
    } else {
      ElMessage.success('任务已创建，下一步请直接启动授权验证')
      router.push({ path: `/tasks/${task.id}`, query: { next: 'start' } })
    }
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '任务创建失败')
  } finally {
    submitting.value = false
  }
}

onMounted(async () => {
  modelConfigs.value = await platformApi.listModelConfigs()
  const preferred = enabledBrainModelConfigs.value.find((config) => !config.name.toLowerCase().includes('fallback'))
    || enabledBrainModelConfigs.value[0]
  if (preferred && !form.modelConfigId) {
    form.modelConfigId = preferred.id
  }
})
</script>

<style scoped>
.selected {
  outline: 2px solid var(--pine);
  background: rgba(111, 143, 88, 0.12);
}

.wizard-note-card {
  margin-bottom: 18px;
  padding: 16px 18px;
  border: 1px solid #d9e6fb;
  border-radius: 14px;
  background: linear-gradient(180deg, #f8fbff 0%, #f1f6ff 100%);
}

.wizard-note-card strong {
  display: block;
  margin-bottom: 8px;
  color: var(--blue);
  font-size: 14px;
  font-weight: 800;
}

.wizard-note-card p {
  margin: 0;
  color: var(--ink-soft);
  line-height: 1.7;
}

.evidence-policy-card {
  display: grid;
  gap: 18px;
  padding: 18px;
  border: 1px solid #d9e6fb;
  border-radius: 8px;
  background: #f8fbff;
}

.policy-kicker {
  margin: 0 0 6px;
  color: var(--blue);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0;
  text-transform: uppercase;
}

.evidence-policy-card strong {
  display: block;
  margin-bottom: 8px;
  color: var(--ink);
  font-size: 16px;
}

.evidence-policy-card p {
  margin: 0;
  color: var(--ink-soft);
  line-height: 1.7;
}

.policy-lists {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.policy-lists > div {
  min-height: 96px;
  padding: 14px;
  border: 1px solid rgba(37, 69, 102, 0.12);
  border-radius: 8px;
  background: #ffffff;
}

.policy-lists span {
  display: block;
  margin-bottom: 6px;
  color: var(--ink);
  font-size: 13px;
  font-weight: 800;
}

.worker-pool-card {
  margin-top: 18px;
  margin-bottom: 16px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 16px;
  align-items: center;
  padding: 16px 18px;
  border: 1px solid rgba(37, 99, 235, 0.18);
  border-radius: 8px;
  background: rgba(37, 99, 235, 0.045);
}

.worker-pool-card.empty {
  border-color: rgba(217, 119, 6, 0.28);
  background: rgba(217, 119, 6, 0.07);
}

.worker-pool-card strong {
  display: block;
  margin-bottom: 6px;
  color: var(--ink);
  font-size: 15px;
}

.worker-pool-card p {
  margin: 0;
  color: var(--ink-soft);
  line-height: 1.65;
}

.worker-pool-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: flex-end;
}

.worker-pool-stats span {
  color: #1d4ed8;
  border: 1px solid rgba(37, 99, 235, 0.2);
  background: rgba(37, 99, 235, 0.08);
  border-radius: 999px;
  padding: 6px 10px;
  font-size: 12px;
  font-weight: 700;
  white-space: nowrap;
}

.worker-option {
  display: grid;
  gap: 2px;
  line-height: 1.3;
}

.worker-option small {
  color: var(--ink-soft);
  font-size: 12px;
}

@media (max-width: 760px) {
  .policy-lists,
  .worker-pool-card {
    grid-template-columns: 1fr;
  }

  .worker-pool-stats {
    justify-content: flex-start;
  }
}
</style>
