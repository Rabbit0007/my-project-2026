<template>
  <section>
    <div class="page-header">
      <div>
        <p class="eyebrow">系统管理</p>
        <h1 class="page-title">用户管理</h1>
        <p class="subcopy">管理平台用户账号、角色和权限。</p>
      </div>
      <el-button type="primary" @click="openCreate">新建用户</el-button>
    </div>

    <div class="glass-card section-card">
      <el-table :data="users" style="width: 100%" empty-text="暂无用户">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="username" label="用户名" width="140" />
        <el-table-column prop="displayName" label="显示名称" width="140" />
        <el-table-column prop="role" label="角色" width="100">
          <template #default="{ row }">
            <el-tag :type="row.role === 'admin' ? '' : 'info'" size="small">{{ row.role }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="enabled" label="状态" width="80">
          <template #default="{ row }">
            <span :style="{ color: row.enabled ? 'var(--success)' : 'var(--danger)' }">{{ row.enabled ? '启用' : '禁用' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="lastLoginAt" label="最后登录" width="180">
          <template #default="{ row }">{{ row.lastLoginAt ? formatTime(row.lastLoginAt) : '从未登录' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200">
          <template #default="{ row }">
            <el-button size="small" text @click="openEdit(row)">编辑</el-button>
            <el-button size="small" text @click="toggleUser(row)">{{ row.enabled ? '禁用' : '启用' }}</el-button>
            <el-button size="small" text @click="resetPassword(row)">重置密码</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Create/Edit Dialog -->
    <el-dialog v-model="dialogVisible" :title="editingId ? '编辑用户' : '新建用户'" width="420px">
      <el-form :model="form" label-position="top">
        <el-form-item label="用户名">
          <el-input v-model="form.username" :disabled="!!editingId" placeholder="登录用户名" />
        </el-form-item>
        <el-form-item label="显示名称">
          <el-input v-model="form.displayName" placeholder="显示名称" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="form.role">
            <el-option label="管理员" value="admin" />
            <el-option label="查看者" value="viewer" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="!editingId" label="密码">
          <el-input v-model="form.password" type="password" show-password placeholder="至少6位" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveUser">保存</el-button>
      </template>
    </el-dialog>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { platformApi } from '@/api/client'

const users = ref<any[]>([])
const dialogVisible = ref(false)
const saving = ref(false)
const editingId = ref<number | null>(null)
const form = reactive({ username: '', displayName: '', role: 'admin', password: '' })

async function loadUsers() {
  try {
    users.value = await platformApi.listUsers()
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '用户列表加载失败')
  }
}

function openCreate() {
  editingId.value = null
  form.username = ''
  form.displayName = ''
  form.role = 'admin'
  form.password = ''
  dialogVisible.value = true
}

function openEdit(user: any) {
  editingId.value = user.id
  form.username = user.username
  form.displayName = user.displayName
  form.role = user.role
  form.password = ''
  dialogVisible.value = true
}

async function saveUser() {
  saving.value = true
  try {
    if (editingId.value) {
      await platformApi.updateUser(editingId.value, { displayName: form.displayName, role: form.role })
    } else {
      if (!form.username || !form.password) { ElMessage.warning('请填写完整'); return }
      if (form.password.length < 6) { ElMessage.warning('密码至少6位'); return }
      await platformApi.createUser({ username: form.username, password: form.password, displayName: form.displayName, role: form.role })
    }
    ElMessage.success('保存成功')
    dialogVisible.value = false
    await loadUsers()
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '操作失败')
  } finally {
    saving.value = false
  }
}

async function toggleUser(user: any) {
  try {
    await platformApi.updateUser(user.id, { enabled: !user.enabled })
    ElMessage.success(user.enabled ? '已禁用' : '已启用')
    await loadUsers()
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '操作失败')
  }
}

async function resetPassword(user: any) {
  try {
    const { value } = await ElMessageBox.prompt('输入新密码（至少6位）', '重置密码', { inputType: 'password' })
    if (!value || value.length < 6) { ElMessage.warning('密码至少6位'); return }
    await platformApi.updateUser(user.id, { password: value })
    ElMessage.success('密码已重置')
  } catch (err: any) {
    if (err === 'cancel' || err === 'close') return
    ElMessage.error(err?.response?.data?.error || '密码重置失败')
  }
}

function formatTime(t: string) {
  return new Date(t).toLocaleString('zh-CN')
}

onMounted(loadUsers)
</script>
