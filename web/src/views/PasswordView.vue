<script setup lang="ts">
import { ref, computed } from 'vue'
import { usePasswordReset, useAuth, VaultAuthGuard, useT } from '@vault42/vue'
import { useRouter } from 'vue-router'
import { friendlyError } from '../errorMessages'
import { usePasswordStrength } from '../composables/usePasswordStrength'

const { isLoading, error, changePassword } = usePasswordReset()
const { logout } = useAuth()
const router = useRouter()
const { t } = useT()

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')

const { passwordLength, passwordStrength, strengthBarColor } = usePasswordStrength(newPassword)

const canSubmit = computed(() =>
  currentPassword.value.length > 0 &&
  newPassword.value.length >= 15 &&
  newPassword.value === confirmPassword.value &&
  !isLoading.value
)

async function handleChange() {
  if (!canSubmit.value) return
  try {
    await changePassword(currentPassword.value, newPassword.value)
    // Backend revokes all sessions on password change — logout and redirect to login
    await logout()
    router.push({ path: '/login', query: { reason: 'password_changed' } })
  } catch {
    // error is set by composable
  }
}
</script>

<template>
  <VaultAuthGuard>
    <template #default>
      <div class="max-w-md mx-auto px-4 sm:px-6 py-8">
        <div class="mb-6">
          <h1 class="text-2xl font-bold">{{ t('password.title') }}</h1>
          <p class="text-sm text-vault42-muted mt-1">{{ t('password.subtitle') }}</p>
        </div>

        <div v-if="error" class="vault42-alert-error mb-4" role="alert">{{ friendlyError(error.code) }}</div>

        <form class="vault42-card space-y-5" @submit.prevent="handleChange">
          <div>
            <label for="password-current" class="vault42-label">{{ t('password.currentPassword') }}</label>
            <input
              id="password-current"
              v-model="currentPassword"
              type="password"
              autocomplete="current-password"
              required
              class="vault42-input"
            />
          </div>

          <div>
            <label for="password-new" class="vault42-label">{{ t('password.newPassword') }}</label>
            <input
              id="password-new"
              v-model="newPassword"
              type="password"
              autocomplete="new-password"
              minlength="15"
              required
              class="vault42-input"
            />
            <!-- Strength meter -->
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
            <label for="password-confirm" class="vault42-label">{{ t('password.confirmNewPassword') }}</label>
            <input
              id="password-confirm"
              v-model="confirmPassword"
              type="password"
              autocomplete="new-password"
              required
              class="vault42-input"
            />
            <p v-if="confirmPassword && newPassword !== confirmPassword" class="text-vault42-error text-xs mt-1" aria-live="polite">
              {{ t('password.passwordsDoNotMatch') }}
            </p>
          </div>

          <button type="submit" :disabled="!canSubmit" class="vault42-btn w-full">
            <span v-if="isLoading" class="vault42-spinner mr-2"></span>
            {{ isLoading ? t('password.updating') : t('password.submit') }}
          </button>
        </form>
      </div>
    </template>

    <template #loading>
      <div class="flex justify-center py-20">
        <div class="vault42-spinner vault42-spinner-lg"></div>
      </div>
    </template>
  </VaultAuthGuard>
</template>
