<script setup lang="ts">
import { onMounted } from 'vue'
import { useProfile, VaultAuthGuard, useT } from '@vault42/vue'
import { friendlyError } from '../errorMessages'

const { profile, isLoading, error, fetchProfile } = useProfile()
const { t, formatDate } = useT()

onMounted(() => fetchProfile())
</script>

<template>
  <VaultAuthGuard>
    <template #default>
      <div class="max-w-3xl mx-auto px-4 sm:px-6 py-8">
        <h1 class="text-2xl font-bold mb-6">{{ t('profile.title') }}</h1>

        <div v-if="isLoading" class="flex justify-center py-12">
          <div class="vault42-spinner vault42-spinner-lg"></div>
        </div>

        <div v-else-if="error" class="vault42-alert-error">
          {{ friendlyError(error.code) }}
        </div>

        <div v-else-if="profile" class="space-y-6">
          <!-- Identity card -->
          <div class="vault42-card flex items-start gap-5">
            <div class="w-14 h-14 rounded-full bg-vault42-primary/20 flex items-center justify-center flex-shrink-0">
              <span class="text-xl font-bold text-vault42-primary">
                {{ (profile.display_name || profile.email)[0].toUpperCase() }}
              </span>
            </div>
            <div class="min-w-0">
              <h2 class="text-lg font-semibold">{{ profile.display_name || t('profile.noDisplayName') }}</h2>
              <p class="text-sm text-vault42-muted truncate">{{ profile.email }}</p>
              <div class="mt-2">
                <span v-if="profile.email_verified" class="vault42-badge-success">{{ t('profile.emailVerified') }}</span>
                <span v-else class="vault42-badge-error">{{ t('profile.emailNotVerified') }}</span>
              </div>
            </div>
          </div>

          <!-- Details grid -->
          <div class="vault42-card">
            <h3 class="text-sm font-semibold text-vault42-muted uppercase tracking-wider mb-4">{{ t('profile.accountDetails') }}</h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-y-5 gap-x-8">
              <div>
                <p class="text-xs text-vault42-muted mb-0.5">{{ t('profile.accountId') }}</p>
                <p class="text-sm font-mono text-vault42-text/70">{{ profile.id }}</p>
              </div>
              <div>
                <p class="text-xs text-vault42-muted mb-0.5">{{ t('profile.email') }}</p>
                <p class="text-sm">{{ profile.email }}</p>
              </div>
              <div>
                <p class="text-xs text-vault42-muted mb-0.5">{{ t('profile.locale') }}</p>
                <p class="text-sm">{{ profile.locale || t('profile.notSet') }}</p>
              </div>
              <div>
                <p class="text-xs text-vault42-muted mb-0.5">{{ t('profile.mfa') }}</p>
                <p class="text-sm">
                  <span v-if="profile.mfa_enabled" class="text-vault42-success">{{ t('common.enabled') }}</span>
                  <span v-else class="text-vault42-muted">
                    {{ t('common.disabled') }} &mdash;
                    <router-link to="/2fa" class="text-vault42-primary hover:text-vault42-accent transition-colors">{{ t('profile.enable') }}</router-link>
                  </span>
                </p>
              </div>
              <div>
                <p class="text-xs text-vault42-muted mb-0.5">{{ t('profile.created') }}</p>
                <p class="text-sm">{{ formatDate(new Date(profile.created_at)) }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>

    <template #loading>
      <div class="flex justify-center py-20">
        <div class="vault42-spinner vault42-spinner-lg"></div>
      </div>
    </template>
  </VaultAuthGuard>
</template>
