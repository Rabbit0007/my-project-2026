<template>
  <div class="ai-chat">
    <!-- Floating Bubble -->
    <div class="ai-chat__bubble" @click="toggleChat" :class="{ active: visible }">
      <el-icon :size="22"><ChatDotRound /></el-icon>
    </div>

    <!-- Chat Window -->
    <transition name="chat-slide">
      <div v-if="visible" class="ai-chat__window">
        <div class="ai-chat__header">
          <div class="ai-chat__header-info">
            <strong>AI 安全助手</strong>
            <span>基于 {{ modelName }} 驱动</span>
          </div>
          <el-button text size="small" @click="clearMessages">清空</el-button>
          <el-button text size="small" @click="visible = false">
            <el-icon><Close /></el-icon>
          </el-button>
        </div>

        <div class="ai-chat__messages" ref="messagesRef">
          <div v-if="messages.length === 0" class="ai-chat__empty">
            <p>👋 你好！我是 Rabbit AI 安全助手。</p>
            <p>你可以问我：</p>
            <ul>
              <li>漏洞原理和利用方式</li>
              <li>当前任务的分析结果</li>
              <li>修复建议和安全加固</li>
              <li>渗透测试方法论</li>
            </ul>
          </div>
          <div v-for="(msg, idx) in messages" :key="idx" class="ai-chat__msg" :class="msg.role">
            <div class="ai-chat__msg-content">
              <pre v-if="msg.role === 'assistant'" v-html="formatReply(msg.content)"></pre>
              <span v-else>{{ msg.content }}</span>
            </div>
          </div>
          <div v-if="loading" class="ai-chat__msg assistant">
            <div class="ai-chat__msg-content">
              <span class="ai-chat__typing">思考中...</span>
            </div>
          </div>
        </div>

        <div class="ai-chat__input">
          <el-input
            v-model="inputText"
            placeholder="输入问题..."
            @keyup.enter="sendMessage"
            :disabled="loading"
          />
          <el-button type="primary" :loading="loading" @click="sendMessage" :disabled="!inputText.trim()">
            发送
          </el-button>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, nextTick, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ChatDotRound, Close } from '@element-plus/icons-vue'
import { api } from '@/api/client'

interface Message {
  role: 'user' | 'assistant'
  content: string
}

const route = useRoute()
const visible = ref(false)
const loading = ref(false)
const inputText = ref('')
const messages = ref<Message[]>([])
const messagesRef = ref<HTMLElement>()
const modelName = ref('AI')

function toggleChat() {
  visible.value = !visible.value
}

function clearMessages() {
  messages.value = []
}

async function sendMessage() {
  const text = inputText.value.trim()
  if (!text || loading.value) return

  messages.value.push({ role: 'user', content: text })
  inputText.value = ''
  loading.value = true
  scrollToBottom()

  try {
    // Get task ID from route if on task detail page
    let taskId: number | undefined
    if (route.name === 'task-detail' && route.params.id) {
      taskId = Number(route.params.id)
    }

    const res = await api.post('/chat', {
      messages: messages.value.slice(-10).map(m => ({
        role: m.role,
        content: m.role === 'assistant' ? m.content.slice(0, 2000) : m.content,
      })),
      taskId: taskId || undefined,
    })

    messages.value.push({ role: 'assistant', content: res.data.reply })
    if (res.data.modelId) {
      modelName.value = res.data.modelId
    }
  } catch (err: any) {
    const errMsg = err?.response?.data?.error || '请求失败，请检查模型配置'
    messages.value.push({ role: 'assistant', content: '❌ ' + errMsg })
  } finally {
    loading.value = false
    scrollToBottom()
  }
}

function scrollToBottom() {
  nextTick(() => {
    if (messagesRef.value) {
      messagesRef.value.scrollTop = messagesRef.value.scrollHeight
    }
  })
}

function formatReply(text: string) {
  // Basic markdown-like formatting
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/`(.*?)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br>')
}

watch(visible, (val) => {
  if (val) scrollToBottom()
})
</script>

<style scoped>
.ai-chat {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 9999;
}

.ai-chat__bubble {
  width: 52px;
  height: 52px;
  border-radius: 50%;
  background: linear-gradient(135deg, #4f8cff, #2f6fe4);
  display: grid;
  place-items: center;
  cursor: pointer;
  box-shadow: 0 4px 16px rgba(47, 111, 228, 0.35);
  transition: transform 0.2s, box-shadow 0.2s;
  color: #fff;
}

.ai-chat__bubble:hover {
  transform: scale(1.08);
  box-shadow: 0 6px 24px rgba(47, 111, 228, 0.45);
}

.ai-chat__bubble.active {
  background: #e8ecf0;
  color: #4e5969;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.ai-chat__window {
  position: absolute;
  bottom: 64px;
  right: 0;
  width: 420px;
  height: 560px;
  background: #fff;
  border: 1px solid #e8ecf0;
  border-radius: 16px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.12);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.ai-chat__header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 14px 16px;
  border-bottom: 1px solid #f0f2f5;
  background: #fafbfc;
}

.ai-chat__header-info {
  flex: 1;
}

.ai-chat__header-info strong {
  display: block;
  font-size: 14px;
  color: #1d2129;
}

.ai-chat__header-info span {
  font-size: 11px;
  color: #86909c;
}

.ai-chat__messages {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.ai-chat__messages::-webkit-scrollbar { width: 4px; }
.ai-chat__messages::-webkit-scrollbar-thumb { background: #e8ecf0; border-radius: 2px; }

.ai-chat__empty {
  color: #86909c;
  font-size: 13px;
  line-height: 1.8;
}

.ai-chat__empty ul {
  margin: 8px 0 0;
  padding-left: 18px;
}

.ai-chat__msg {
  display: flex;
}

.ai-chat__msg.user {
  justify-content: flex-end;
}

.ai-chat__msg.user .ai-chat__msg-content {
  background: #2f6fe4;
  color: #fff;
  border-radius: 12px 12px 2px 12px;
  max-width: 80%;
  padding: 10px 14px;
  font-size: 13px;
  line-height: 1.6;
}

.ai-chat__msg.assistant .ai-chat__msg-content {
  background: #f4f6f8;
  color: #1d2129;
  border-radius: 12px 12px 12px 2px;
  max-width: 85%;
  padding: 10px 14px;
  font-size: 13px;
  line-height: 1.6;
}

.ai-chat__msg-content pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: inherit;
  font-size: inherit;
  line-height: inherit;
}

.ai-chat__msg-content code {
  background: rgba(47, 111, 228, 0.08);
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 12px;
  font-family: "SF Mono", "Fira Code", monospace;
}

.ai-chat__typing {
  color: #86909c;
  animation: pulse 1.2s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.ai-chat__input {
  display: flex;
  gap: 8px;
  padding: 12px 14px;
  border-top: 1px solid #f0f2f5;
  background: #fafbfc;
}

.ai-chat__input .el-input {
  flex: 1;
}

/* Transition */
.chat-slide-enter-active,
.chat-slide-leave-active {
  transition: all 0.25s ease;
}

.chat-slide-enter-from,
.chat-slide-leave-to {
  opacity: 0;
  transform: translateY(12px) scale(0.95);
}

@media (max-width: 720px) {
  .ai-chat {
    right: 14px;
    bottom: 88px;
  }

  .ai-chat__bubble {
    width: 48px;
    height: 48px;
  }

  .ai-chat__window {
    position: fixed;
    right: 10px;
    bottom: 148px;
    width: calc(100vw - 20px);
    height: min(560px, calc(100vh - 180px));
  }
}
</style>
