<template>
  <span class="status-pill" :class="tone">{{ label }}</span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ status: string }>()

const label = computed(() => props.status || 'unknown')
const tone = computed(() => {
  if (['failed', 'blocked', 'critical', 'high', 'false_positive'].includes(props.status)) return 'danger'
  if (['pending', 'contract_incomplete', 'candidate_incomplete', 'not_checked'].includes(props.status)) return 'gold'
  return ''
})
</script>
