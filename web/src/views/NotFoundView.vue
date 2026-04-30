<script setup lang="ts">
import { useT } from '@vault42/vue'
const { t } = useT()
</script>

<template>
  <div class="min-h-[80vh] flex items-center justify-center px-4">
    <div class="text-center">
      <p class="text-6xl font-bold text-vault42-border mb-4">404</p>
      <h1 class="text-xl font-semibold mb-2">{{ t('notFound.title') }}</h1>
      <p class="text-sm text-vault42-muted mb-6">{{ t('notFound.description') }}</p>
      <router-link to="/" class="vault42-btn inline-block">{{ t('notFound.goHome') }}</router-link>
    </div>
  </div>
</template>
