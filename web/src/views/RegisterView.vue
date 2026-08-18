<script setup lang="ts">
import { ref } from 'vue'
import { VaultRegisterForm, useT } from '@vault42/vue'

const { t } = useT()
const registered = ref(false)

function onSuccess() {
  registered.value = true
}
</script>

<template>
  <div class="min-h-[80vh] flex items-center justify-center px-4">
    <div class="w-full max-w-sm">
      <div class="text-center mb-8">
        <div class="text-4xl mb-3">&#x1f510;</div>
        <h1 class="text-2xl font-bold">{{ t('register.title') }}</h1>
        <p class="text-sm text-vault42-muted mt-1">{{ t('register.subtitle') }}</p>
      </div>

      <div v-if="registered" class="vault42-card text-center">
        <div class="text-3xl mb-3">&#x2709;</div>
        <h2 class="text-lg font-semibold text-vault42-success mb-2">{{ t('register.accountCreated') }}</h2>
        <p class="text-sm text-vault42-muted mb-5">{{ t('register.checkEmail') }}</p>
        <router-link to="/login" class="vault42-btn inline-block">{{ t('common.signIn') }}</router-link>
      </div>

      <div v-else class="vault42-card">
        <VaultRegisterForm @success="onSuccess" />
        <p class="text-center text-sm text-vault42-muted mt-5">
          {{ t('register.alreadyHaveAccount') }}
          <router-link to="/login" class="text-vault42-accent hover:text-vault42-text transition-colors">{{ t('common.signIn') }}</router-link>
        </p>
      </div>
    </div>
  </div>
</template>
