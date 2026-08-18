<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuth, useOAuth, useProfile, useT } from '@vault42/vue'

const router = useRouter()
const { accessToken: authAccessToken, requires2FA, challengeToken } = useAuth()
const { parseCallback, exchangeCode } = useOAuth()
const { fetchProfile } = useProfile()
const { t } = useT()
const error = ref<string | null>(null)

onMounted(async () => {
  const result = parseCallback(window.location.hash)

  // Clean tokens from URL so they don't linger in history
  history.replaceState(null, '', window.location.pathname)

  if (!result) {
    error.value = t('oauth.noData')
    return
  }

  if (result.error) {
    error.value = result.error as string
    return
  }

  if (result.requires_2fa) {
    requires2FA.value = true
    challengeToken.value = (result.challenge_token as string) || null
    router.replace('/login')
    return
  }

  if (result.code) {
    try {
      const tokenResult = await exchangeCode(result.code as string)
      authAccessToken.value = tokenResult.access_token
      try {
        await fetchProfile()
      } catch {
        // Profile fetch is non-critical
      }
      router.replace('/')
    } catch {
      error.value = t('oauth.completeFailed')
    }
    return
  }

  error.value = t('oauth.unexpected')
})
</script>

<template>
  <div class="min-h-[80vh] flex items-center justify-center px-4">
    <div class="w-full max-w-sm text-center">
      <div v-if="error" class="vault42-card" role="alert">
        <div class="text-4xl mb-4">&#x26a0;&#xfe0f;</div>
        <h1 class="text-xl font-bold mb-2">{{ t('oauth.failed') }}</h1>
        <p class="text-sm text-vault42-muted mb-6">{{ error }}</p>
        <router-link to="/login" class="vault42-btn">{{ t('oauth.backToSignIn') }}</router-link>
      </div>
      <div v-else>
        <div class="vault42-spinner vault42-spinner-lg mx-auto mb-4"></div>
        <p class="text-sm text-vault42-muted">{{ t('oauth.completing') }}</p>
      </div>
    </div>
  </div>
</template>
