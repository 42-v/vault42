<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useAuth } from '../composables/useAuth'

defineProps<{
  /** Set to true to enable rendering. Defaults to false (hidden in production). */
  enabled?: boolean
}>()

const isDev = (import.meta as unknown as { env: { DEV: boolean } }).env.DEV

const { accessToken, decodedToken, tokenExpiresIn, isTokenExpired, isAuthenticated } = useAuth()

const now = ref(Date.now())
let timer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  timer = setInterval(() => {
    now.value = Date.now()
  }, 1000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})

const truncatedToken = computed(() => {
  if (!accessToken.value) return null
  const t = accessToken.value
  if (t.length <= 40) return t
  return t.slice(0, 20) + '...' + t.slice(-20)
})

const payloadPretty = computed(() => {
  if (!decodedToken.value) return null
  return JSON.stringify(decodedToken.value.payload, null, 2)
})

// Force recompute of tokenExpiresIn using now
const expiresInLive = computed(() => {
  void now.value // dependency
  return tokenExpiresIn.value
})

function formatSeconds(s: number): string {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return `${m}m ${sec}s`
}
</script>

<template>
  <template v-if="enabled && isDev">
    <div v-if="isAuthenticated" class="vault42-token-debug">
      <h3>Token Debug</h3>

      <div class="vault42-token-debug__section">
        <strong>Access Token</strong>
        <code>{{ truncatedToken }}</code>
      </div>

      <div v-if="decodedToken" class="vault42-token-debug__section">
        <strong>Header</strong>
        <pre>alg: {{ decodedToken.header.alg }}  kid: {{ decodedToken.header.kid }}</pre>
      </div>

      <div v-if="decodedToken" class="vault42-token-debug__section">
        <strong>Payload</strong>
        <pre>{{ payloadPretty }}</pre>
      </div>

      <div class="vault42-token-debug__section">
        <strong>Expires in</strong>
        <span :class="{ 'vault42-token-debug--expired': isTokenExpired }">
          {{ isTokenExpired ? 'EXPIRED' : formatSeconds(expiresInLive) }}
        </span>
      </div>
    </div>
    <div v-else class="vault42-token-debug vault42-token-debug--empty">
      <p>Not authenticated</p>
    </div>
  </template>
</template>
