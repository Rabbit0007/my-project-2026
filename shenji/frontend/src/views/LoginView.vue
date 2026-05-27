<template>
  <div class="login-page">
    <div class="login-bg">
      <div class="login-bg__grid"></div>
    </div>
    <div class="login-card">
      <div class="login-card__header">
        <div class="login-logo">
          <span class="login-logo__mark">R</span>
        </div>
        <h1>Rabbit Security</h1>
        <p>AI 安全验证平台</p>
      </div>
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        class="login-form"
        @submit.prevent="handleLogin"
      >
        <el-form-item prop="username">
          <el-input
            v-model="form.username"
            placeholder="用户名"
            prefix-icon="User"
            size="large"
            @keyup.enter="handleLogin"
          />
        </el-form-item>
        <el-form-item prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="密码"
            prefix-icon="Lock"
            size="large"
            show-password
            @keyup.enter="handleLogin"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            size="large"
            class="login-btn"
            :loading="loading"
            @click="handleLogin"
          >
            登 录
          </el-button>
        </el-form-item>
      </el-form>
      <div class="login-card__footer">
        <span>默认账号: admin / admin123</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()
const loading = ref(false)
const formRef = ref()

const form = reactive({
  username: '',
  password: '',
})

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

async function handleLogin() {
  if (!formRef.value) return
  await formRef.value.validate()
  loading.value = true
  try {
    await authStore.login(form.username, form.password)
    ElMessage.success('登录成功')
    router.push('/')
  } catch (err: any) {
    const msg = err?.response?.data?.error || '登录失败，请检查用户名和密码'
    ElMessage.error(msg)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  background: #0a0e1a;
  overflow: hidden;
}

.login-bg {
  position: absolute;
  inset: 0;
  z-index: 0;
}

.login-bg__grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(56, 189, 248, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(56, 189, 248, 0.03) 1px, transparent 1px);
  background-size: 60px 60px;
}

.login-card {
  position: relative;
  z-index: 1;
  width: 400px;
  padding: 48px 40px 36px;
  background: rgba(15, 23, 42, 0.85);
  border: 1px solid rgba(56, 189, 248, 0.15);
  border-radius: 16px;
  backdrop-filter: blur(20px);
  box-shadow: 0 24px 80px rgba(0, 0, 0, 0.5), 0 0 60px rgba(56, 189, 248, 0.05);
}

.login-card__header {
  text-align: center;
  margin-bottom: 36px;
}

.login-logo {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 56px;
  height: 56px;
  border-radius: 14px;
  background: linear-gradient(135deg, #38bdf8, #6366f1);
  margin-bottom: 16px;
}

.login-logo__mark {
  font-size: 28px;
  font-weight: 800;
  color: #fff;
  font-family: 'Inter', system-ui, sans-serif;
}

.login-card__header h1 {
  font-size: 22px;
  font-weight: 700;
  color: #f1f5f9;
  margin: 0 0 6px;
}

.login-card__header p {
  font-size: 13px;
  color: #94a3b8;
  margin: 0;
}

.login-form {
  margin-top: 8px;
}

.login-form :deep(.el-input__wrapper) {
  background: rgba(30, 41, 59, 0.8);
  border: 1px solid rgba(71, 85, 105, 0.4);
  border-radius: 10px;
  box-shadow: none;
  transition: border-color 0.2s;
}

.login-form :deep(.el-input__wrapper:hover),
.login-form :deep(.el-input__wrapper.is-focus) {
  border-color: rgba(56, 189, 248, 0.5);
}

.login-form :deep(.el-input__inner) {
  color: #e2e8f0;
}

.login-form :deep(.el-input__prefix .el-icon) {
  color: #64748b;
}

.login-btn {
  width: 100%;
  height: 44px;
  border-radius: 10px;
  font-size: 15px;
  font-weight: 600;
  background: linear-gradient(135deg, #38bdf8, #6366f1);
  border: none;
  margin-top: 8px;
}

.login-btn:hover {
  opacity: 0.9;
}

.login-card__footer {
  text-align: center;
  margin-top: 24px;
  font-size: 12px;
  color: #64748b;
}
</style>
