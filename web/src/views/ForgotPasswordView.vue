<script setup lang="ts">
import { ref } from 'vue'
import { usePasswordReset, useT } from '@vault42/vue'
import { friendlyError } from '../errorMessages'

const { isLoading, error, requested, requestReset } = usePasswordReset()
const { t } = useT()

const email = ref('')

async function handleSubmit() {
  if (!email.value) return
  await requestReset(email.value)
}
</script>

<template>
  <div class="min-h-[80vh] flex items-center justify-center px-4">
    <div class="w-full max-w-sm">
      <div class="text-center mb-8">
        <div class="text-4xl mb-3">&#x1f511;</div>
        <h1 class="text-2xl font-bold">{{ t('forgotPassword.title') }}</h1>
        <p class="text-sm text-vault42-muted mt-1">{{ t('forgotPassword.subtitle') }}</p>
      </div>

      <div v-if="requested" class="vault42-card text-center py-10">
        <div class="w-14 h-14 rounded-full bg-vault42-success/15 flex items-center justify-center mx-auto mb-4">
          <svg class="w-7 h-7 text-vault42-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        </div>
        <h2 class="text-lg font-semibold mb-2">{{ t('forgotPassword.checkEmail') }}</h2>
        <p class="text-sm text-vault42-muted mb-6">
          {{ t('forgotPassword.checkEmailDesc') }}
        </p>
        <router-link to="/login" class="text-sm text-vault42-primary hover:text-vault42-accent transition-colors">
          {{ t('forgotPassword.backToSignIn') }}
        </router-link>
      </div>

      <div v-else class="vault42-card">
        <div v-if="error" class="vault42-alert-error mb-4" role="alert">{{ friendlyError(error.code) }}</div>

        <form class="space-y-5" @submit.prevent="handleSubmit">
          <div>
            <label for="reset-email" class="vault42-label">{{ t('forgotPassword.emailAddress') }}</label>
            <input
              id="reset-email"
              v-model="email"
              type="email"
              autocomplete="email"
              required
              class="vault42-input"
              placeholder="you@example.com"
            />
          </div>

          <button type="submit" :disabled="isLoading || !email" class="vault42-btn w-full">
            <span v-if="isLoading" class="vault42-spinner mr-2"></span>
            {{ isLoading ? t('forgotPassword.sending') : t('forgotPassword.sendResetLink') }}
          </button>
        </form>

        <p class="text-center text-sm text-vault42-muted mt-5">
          {{ t('forgotPassword.rememberPassword') }}
          <router-link to="/login" class="text-vault42-primary hover:text-vault42-accent transition-colors">{{ t('common.signIn') }}</router-link>
        </p>
      </div>
    </div>
  </div>
</template>
