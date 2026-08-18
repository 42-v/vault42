<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useVaultClient, useT } from '@vault42/vue'
import { useRoute, useRouter } from 'vue-router'
import { friendlyError } from '../errorMessages'
import { safeRedirect } from '../utils/safeRedirect'

const client = useVaultClient()
const route = useRoute()
const router = useRouter()
const { t } = useT()

const status = ref<'loading' | 'success' | 'error'>('loading')
const errorCode = ref('')
const redirecting = ref(false)
const countdown = ref(3)
const intervalId = ref<ReturnType<typeof setInterval> | null>(null)

onUnmounted(() => {
  if (intervalId.value) {
    clearInterval(intervalId.value)
    intervalId.value = null
  }
})

onMounted(async () => {
  const token = route.query.token as string
  if (!token) {
    status.value = 'error'
    errorCode.value = 'missing_token'
    return
  }

  try {
    await client.verifyEmail(token)
    status.value = 'success'

    // Auto-redirect after success
    const redirectTo = safeRedirect(route.query.redirect as string | null, '/login')
    redirecting.value = true

    intervalId.value = setInterval(() => {
      countdown.value--
      if (countdown.value <= 0) {
        if (intervalId.value) clearInterval(intervalId.value)
        intervalId.value = null
        router.push(redirectTo)
      }
    }, 1000)
  } catch (e: unknown) {
    status.value = 'error'
    errorCode.value = (e && typeof e === 'object' && 'code' in e ? (e as { code: string }).code : null) || 'verification_failed'
  }
})
</script>

<template>
  <div class="min-h-[80vh] flex items-center justify-center px-4">
    <div class="w-full max-w-sm text-center">
      <!-- Loading -->
      <div v-if="status === 'loading'" class="vault42-card py-12">
        <div class="vault42-spinner vault42-spinner-lg mx-auto mb-4"></div>
        <p class="text-vault42-muted">{{ t('verifyEmail.verifying') }}</p>
      </div>

      <!-- Success -->
      <div v-else-if="status === 'success'" class="vault42-card py-10" role="status">
        <div class="w-14 h-14 rounded-full bg-vault42-success/15 flex items-center justify-center mx-auto mb-4">
          <svg class="w-7 h-7 text-vault42-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h2 class="text-xl font-semibold mb-2">{{ t('verifyEmail.verified') }}</h2>
        <p class="text-sm text-vault42-muted mb-6">{{ t('verifyEmail.verifiedDesc') }}</p>
        <p v-if="redirecting" class="text-xs text-vault42-muted mb-4">
          {{ t('verifyEmail.redirecting', { count: countdown }) }}
        </p>
        <router-link to="/login" class="vault42-btn inline-block">{{ t('verifyEmail.signInNow') }}</router-link>
      </div>

      <!-- Error -->
      <div v-else class="vault42-card py-10" role="alert">
        <div class="w-14 h-14 rounded-full bg-vault42-error/15 flex items-center justify-center mx-auto mb-4">
          <svg class="w-7 h-7 text-vault42-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </div>
        <h2 class="text-xl font-semibold text-vault42-error mb-2">{{ t('verifyEmail.failed') }}</h2>
        <p class="text-sm text-vault42-muted mb-2">{{ friendlyError(errorCode) }}</p>
        <p class="text-xs text-vault42-muted">{{ t('verifyEmail.linkExpired') }}</p>
      </div>
    </div>
  </div>
</template>
