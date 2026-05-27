import { defineStore } from 'pinia'
import { api } from '@/api/client'

export interface User {
  id: number
  username: string
  displayName: string
  role: string
  lastLoginAt?: string
}

function readStoredUser(): User | null {
  const raw = localStorage.getItem('rabbit_user')
  if (!raw) return null
  try {
    const value = JSON.parse(raw)
    if (!value || typeof value !== 'object') return null
    return value as User
  } catch {
    localStorage.removeItem('rabbit_user')
    return null
  }
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('rabbit_token') || '',
    user: readStoredUser(),
  }),
  getters: {
    isLoggedIn: (state) => !!state.token,
    displayName: (state) => state.user?.displayName || state.user?.username || '未登录',
  },
  actions: {
    async login(username: string, password: string) {
      const res = await api.post('/auth/login', { username, password })
      const { token } = res.data
      this.token = token
      localStorage.setItem('rabbit_token', token)
      // Fetch user info
      await this.fetchUser()
    },
    async fetchUser() {
      try {
        const res = await api.get('/auth/me')
        this.user = res.data
        localStorage.setItem('rabbit_user', JSON.stringify(this.user))
      } catch {
        this.logout()
      }
    },
    async changePassword(oldPassword: string, newPassword: string) {
      await api.post('/auth/change-password', { oldPassword, newPassword })
    },
    logout() {
      this.token = ''
      this.user = null
      localStorage.removeItem('rabbit_token')
      localStorage.removeItem('rabbit_user')
      window.location.href = '/login'
    },
  },
})
