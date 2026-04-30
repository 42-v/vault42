<script setup lang="ts">
import { useAuth } from '../composables/useAuth'

const { isAuthenticated, isLoading, initialized } = useAuth()
</script>

<template>
  <template v-if="isAuthenticated">
    <slot />
  </template>
  <template v-else-if="isLoading || !initialized">
    <slot name="loading">
      <p>Loading...</p>
    </slot>
  </template>
  <template v-else>
    <slot name="fallback">
      <p>Please sign in to continue.</p>
    </slot>
  </template>
</template>
