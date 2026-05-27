<template>
  <div v-if="isLoginPage" class="app-login-shell">
    <RouterView />
  </div>
  <div v-else class="app-shell">
    <header class="topbar">
      <div class="topbar-brand">
        <div class="rabbit-mark">
          <span class="rabbit-mark__r">R</span>
        </div>
        <div>
          <strong>Rabbit</strong>
          <span>AI Security Validation Platform</span>
        </div>
      </div>
      <nav class="topbar-nav">
        <RouterLink to="/">工作空间</RouterLink>
        <RouterLink to="/tasks">探索任务</RouterLink>
        <RouterLink to="/reports">交付输出</RouterLink>
        <RouterLink v-if="isAdmin" to="/settings">系统管理</RouterLink>
      </nav>
      <div class="topbar-user">
        <el-switch
          v-model="isDark"
          inline-prompt
          active-text="暗"
          inactive-text="亮"
          style="margin-right: 12px"
          @change="toggleTheme"
        />
        <el-dropdown trigger="click" @command="handleUserCommand">
          <span class="topbar-user__trigger">
            <el-avatar :size="32" class="topbar-user__avatar">
              {{ authStore.displayName?.charAt(0) || 'U' }}
            </el-avatar>
            <span class="topbar-user__name">{{ authStore.displayName }}</span>
            <el-icon><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="password">修改密码</el-dropdown-item>
              <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </header>

    <div class="workspace-shell">
      <aside class="workspace-sidebar">
        <div class="workspace-sidebar__section">
          <span class="workspace-sidebar__label">探索导航</span>
          <nav class="workspace-menu">
            <RouterLink to="/tasks" class="workspace-menu__item">探索任务</RouterLink>
            <RouterLink v-if="isAdmin" to="/tasks/new" class="workspace-menu__item">创建探索</RouterLink>
            <RouterLink to="/findings" class="workspace-menu__item">漏洞报告</RouterLink>
            <RouterLink to="/reports" class="workspace-menu__item">交付报告</RouterLink>
            <RouterLink v-if="isAdmin" to="/settings" class="workspace-menu__item">模型配置</RouterLink>
            <RouterLink v-if="isAdmin" to="/users" class="workspace-menu__item">用户管理</RouterLink>
            <RouterLink v-if="isAdmin" to="/audit-log" class="workspace-menu__item">操作日志</RouterLink>
            <RouterLink v-if="isAdmin" to="/model-logs" class="workspace-menu__item">模型日志</RouterLink>
          </nav>
        </div>

        <div class="sidebar-signal">
          <span class="sidebar-signal__dot"></span>
          <div>
            <strong>探索闭环在线</strong>
            <small>Fact、Intent、Evidence 服务在线</small>
          </div>
        </div>
      </aside>

      <main class="workspace-main">
        <RouterView />
      </main>
    </div>

    <!-- Change Password Dialog -->
    <el-dialog v-model="showPasswordDialog" title="修改密码" width="400px" :close-on-click-modal="false">
      <el-form :model="passwordForm" label-width="80px">
        <el-form-item label="原密码">
          <el-input v-model="passwordForm.oldPassword" type="password" show-password />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="passwordForm.newPassword" type="password" show-password />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input v-model="passwordForm.confirmPassword" type="password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showPasswordDialog = false">取消</el-button>
        <el-button type="primary" :loading="passwordLoading" @click="handleChangePassword">确认修改</el-button>
      </template>
    </el-dialog>

    <!-- AI Chat Floating Widget -->
    <AiChat />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'
import { ArrowDown } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import AiChat from '@/components/AiChat.vue'

const route = useRoute()
const authStore = useAuthStore()

const isLoginPage = computed(() => route.name === 'login')
const isAdmin = computed(() => authStore.user?.role === 'admin')

const isDark = ref(localStorage.getItem('rabbit_theme') === 'dark')

function toggleTheme(dark: boolean) {
  if (dark) {
    document.documentElement.setAttribute('data-theme', 'dark')
    localStorage.setItem('rabbit_theme', 'dark')
  } else {
    document.documentElement.removeAttribute('data-theme')
    localStorage.setItem('rabbit_theme', 'light')
  }
}

// Apply saved theme on load
if (isDark.value) {
  document.documentElement.setAttribute('data-theme', 'dark')
}

const showPasswordDialog = ref(false)
const passwordLoading = ref(false)
const passwordForm = reactive({
  oldPassword: '',
  newPassword: '',
  confirmPassword: '',
})

function handleUserCommand(command: string) {
  if (command === 'logout') {
    authStore.logout()
  } else if (command === 'password') {
    passwordForm.oldPassword = ''
    passwordForm.newPassword = ''
    passwordForm.confirmPassword = ''
    showPasswordDialog.value = true
  }
}

async function handleChangePassword() {
  if (!passwordForm.oldPassword || !passwordForm.newPassword) {
    ElMessage.warning('请填写完整')
    return
  }
  if (passwordForm.newPassword !== passwordForm.confirmPassword) {
    ElMessage.warning('两次输入的新密码不一致')
    return
  }
  if (passwordForm.newPassword.length < 6) {
    ElMessage.warning('新密码长度不能少于6位')
    return
  }
  passwordLoading.value = true
  try {
    await authStore.changePassword(passwordForm.oldPassword, passwordForm.newPassword)
    ElMessage.success('密码修改成功，请重新登录')
    showPasswordDialog.value = false
    setTimeout(() => authStore.logout(), 1500)
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '修改失败')
  } finally {
    passwordLoading.value = false
  }
}
</script>
