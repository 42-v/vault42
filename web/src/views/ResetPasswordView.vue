<script setup lang="ts">
import { ref, computed } from 'vue'
import { usePasswordReset, useT } from '@vault42/vue'
import { useRoute, useRouter } from 'vue-router'
import { friendlyError } from '../errorMessages'
import { usePasswordStrength } from '../composables/usePasswordStrength'

const { isLoading, error, confirmed, confirmReset } = usePasswordReset()
const { t } = useT()
const route = useRoute()
const router = useRouter()

const password = ref('')
const confirmPassword = ref('')

// Validate token format: only alphanumeric, hyphens, underscores, 10-256 chars
const rawToken = route.query.token as string
const token = rawToken && /^[a-zA-Z0-9_-]{10,256}$/.test(rawToken) ? rawToken : ''

const { passwordLength, passwordStrength, strengthBarColor } = usePasswordStrength(password)

const canSubmit = computed(() =>
  token &&
  password.value.length >= 15 &&
  password.value === confirmPassword.value &&
  !isLoading.value
)

async function handleSubmit() {
  if (!canSubmit.value) return
  try {
    await confirmReset(token, password.value)
    // Zero sensitive fields after successful reset
    password.value = ''
    confirmPassword.value = ''
  } catch {
    // error handled by composable
  }
}

function goToLogin() {
  router.push('/login')
}
</script>

<template>
  <div class="min-h-[80vh] flex items-center justify-center px-4">
    <div class="w-full max-w-sm">
      <div class="text-center mb-8">
        <div class="text-4xl mb-3">&#x1f511;</div>
        <h1 class="text-2xl font-bold">{{ t('resetPassword.title') }}</h1>
        <p class="text-sm text-vault42-muted mt-1">{{ t('resetPassword.subtitle') }}</p>
      </div>

      <!-- No token -->
      <div v-if="!token" class="vault42-card text-center py-10" role="alert">
        <div class="w-14 h-14 rounded-full bg-vault42-error/15 flex items-center justify-center mx-auto mb-4">
          <svg class="w-7 h-7 text-vault42-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </div>
        <h2 class="text-lg font-semibold text-vault42-error mb-2">{{ t('resetPassword.invalidLink') }}</h2>
        <p class="text-sm text-vault42-muted mb-6">{{ t('resetPassword.invalidLinkDesc') }}</p>
        <router-link to="/forgot-password" class="vault42-btn inline-block">{{ t('resetPassword.requestNewLink') }}</router-link>
      </div>

      <!-- Success -->
      <div v-else-if="confirmed" class="vault42-card text-center py-10" role="status">
        <div class="w-14 h-14 rounded-full bg-vault42-success/15 flex items-center justify-center mx-auto mb-4">
          <svg class="w-7 h-7 text-vault42-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h2 class="text-lg font-semibold text-vault42-success mb-2">{{ t('resetPassword.success') }}</h2>
        <p class="text-sm text-vault42-muted mb-6">{{ t('resetPassword.successDesc') }}</p>
        <button class="vault42-btn" @click="goToLogin">{{ t('common.signIn') }}</button>
      </div>

      <!-- Form -->
      <div v-else class="vault42-card">
        <div v-if="error" class="vault42-alert-error mb-4" role="alert">
          {{ friendlyError(error.code) }}
        </div>

        <form class="space-y-5" @submit.prevent="handleSubmit">
          <div>
            <label class="vault42-label">{{ t('resetPassword.newPassword') }}</label>
            <input
              v-model="password"
              type="password"
              autocomplete="new-password"
              minlength="15"
              required
              class="vault42-input"
            />
            <div v-if="passwordStrength" class="mt-2">
              <div class="h-1 bg-vault42-border rounded-full overflow-hidden">
                <div
                  :class="[
                    'h-full rounded-full transition-all duration-300',
                    passwordStrength.width,
                    strengthBarColor
                  ]"
                ></div>
              </div>
              <p :class="['text-xs mt-1', passwordStrength.color]">
                {{ t(passwordStrength.labelKey) }} ({{ t('password.characters', { count: passwordLength }) }})
              </p>
            </div>
          </div>

          <div>
            <label class="vault42-label">{{ t('resetPassword.confirmPassword') }}</label>
            <input
              v-model="confirmPassword"
              type="password"
              autocomplete="new-password"
              required
              class="vault42-input"
            />
            <p v-if="confirmPassword && password !== confirmPassword" class="text-vault42-error text-xs mt-1" aria-live="polite">
              {{ t('resetPassword.passwordsDoNotMatch') }}
            </p>
          </div>

          <button type="submit" :disabled="!canSubmit" class="vault42-btn w-full">
            <span v-if="isLoading" class="vault42-spinner mr-2"></span>
            {{ isLoading ? t('resetPassword.resetting') : t('resetPassword.submit') }}
          </button>
        </form>
      </div>
    </div>
  </div>
</template>
