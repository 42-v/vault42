<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useT } from '@vault42/vue'

const router = useRouter()
const { t } = useT()

function setupAuthenticator() {
  router.push('/2fa')
}

function setupWebAuthn() {
  router.push('/2fa#webauthn')
}

function skip() {
  router.push('/')
}
</script>

<template>
  <div class="max-w-lg mx-auto px-4 sm:px-6 py-12">
    <div class="vault42-card text-center">
      <h1 class="text-2xl font-bold mb-2">{{ t('mfaOnboarding.title') }}</h1>
      <p class="text-vault42-muted mb-8">
        {{ t('mfaOnboarding.description') }}
      </p>

      <div class="space-y-3">
        <button class="vault42-btn w-full" @click="setupAuthenticator">
          {{ t('mfaOnboarding.setupAuthenticator') }}
        </button>

        <button class="vault42-btn-outline w-full" @click="setupWebAuthn">
          {{ t('mfaOnboarding.setupSecurityKey') }}
        </button>
      </div>

      <p class="mt-6">
        <a
          href="#"
          class="text-sm text-vault42-muted hover:text-vault42-text transition-colors"
          @click.prevent="skip"
        >
          {{ t('mfaOnboarding.skip') }}
        </a>
      </p>
    </div>
  </div>
</template>
