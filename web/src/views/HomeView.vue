<script setup lang="ts">
import { onMounted } from 'vue'
import { useAuth, useProfile, use2FA, VaultAuthGuard, useT } from '@vault42/vue'

const { user } = useAuth()
const { t, formatDate } = useT()
const { profile, fetchProfile } = useProfile()
const { mfaStatus, fetchMFAStatus } = use2FA()

onMounted(() => {
  fetchProfile()
  fetchMFAStatus()
})
</script>

<template>
  <VaultAuthGuard>
    <template #default>
      <div class="max-w-4xl mx-auto px-4 sm:px-6 py-8 space-y-6">
        <!-- Welcome -->
        <div>
          <h1 class="text-2xl sm:text-3xl font-bold">
            {{ t('home.welcomeBack') }}<span v-if="user?.display_name">, {{ user.display_name }}</span>
          </h1>
          <p class="text-vault42-muted mt-1">{{ t('home.manageSettings') }}</p>
        </div>

        <!-- Security overview -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div class="vault42-card flex items-start gap-4">
            <div class="w-10 h-10 rounded-lg bg-vault42-primary/15 flex items-center justify-center flex-shrink-0">
              <svg class="w-5 h-5 text-vault42-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
              </svg>
            </div>
            <div>
              <p class="text-sm text-vault42-muted">{{ t('home.email') }}</p>
              <p class="text-sm font-medium truncate">{{ user?.email }}</p>
              <span v-if="profile?.email_verified" class="vault42-badge-success mt-1">{{ t('common.verified') }}</span>
              <span v-else class="vault42-badge-error mt-1">{{ t('common.unverified') }}</span>
            </div>
          </div>

          <div class="vault42-card flex items-start gap-4">
            <div
              :class="[
                'w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0',
                (mfaStatus?.totp_enabled || mfaStatus?.webauthn_enabled) ? 'bg-vault42-success/15' : 'bg-vault42-error/15'
              ]"
            >
              <svg class="w-5 h-5" :class="(mfaStatus?.totp_enabled || mfaStatus?.webauthn_enabled) ? 'text-vault42-success' : 'text-vault42-error'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <p class="text-sm text-vault42-muted">{{ t('home.twoFactor') }}</p>
              <p class="text-sm font-medium">{{ (mfaStatus?.totp_enabled || mfaStatus?.webauthn_enabled) ? t('common.enabled') : t('common.disabled') }}</p>
              <router-link v-if="!(mfaStatus?.totp_enabled || mfaStatus?.webauthn_enabled)" to="/2fa" class="text-xs text-vault42-primary hover:text-vault42-accent transition-colors">
                {{ t('home.enableNow') }}
              </router-link>
            </div>
          </div>

          <div class="vault42-card flex items-start gap-4">
            <div class="w-10 h-10 rounded-lg bg-vault42-primary/15 flex items-center justify-center flex-shrink-0">
              <svg class="w-5 h-5 text-vault42-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
              </svg>
            </div>
            <div>
              <p class="text-sm text-vault42-muted">{{ t('home.securityKeys') }}</p>
              <p v-if="mfaStatus?.webauthn_enabled" class="text-sm font-medium text-vault42-success">{{ t('home.registered') }}</p>
              <p v-else class="text-sm font-medium text-vault42-muted">{{ t('home.notConfigured') }}</p>
              <router-link to="/2fa" class="text-xs text-vault42-primary hover:text-vault42-accent transition-colors">
                {{ mfaStatus?.webauthn_enabled ? t('home.manageKeys') : t('home.setUp') }}
              </router-link>
            </div>
          </div>

          <div class="vault42-card flex items-start gap-4">
            <div class="w-10 h-10 rounded-lg bg-vault42-primary/15 flex items-center justify-center flex-shrink-0">
              <svg class="w-5 h-5 text-vault42-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div>
              <p class="text-sm text-vault42-muted">{{ t('home.memberSince') }}</p>
              <p class="text-sm font-medium">{{ profile?.created_at ? formatDate(new Date(profile.created_at)) : '...' }}</p>
            </div>
          </div>
        </div>

        <!-- Quick actions -->
        <div>
          <h2 class="text-lg font-semibold mb-3">{{ t('home.securitySettings') }}</h2>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <router-link to="/profile" class="vault42-card group hover:border-vault42-primary/50 transition-colors flex items-center gap-4">
              <div class="w-9 h-9 rounded-lg bg-vault42-border flex items-center justify-center group-hover:bg-vault42-primary/15 transition-colors">
                <svg class="w-4 h-4 text-vault42-muted group-hover:text-vault42-primary transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
              </div>
              <div>
                <p class="text-sm font-medium group-hover:text-vault42-primary transition-colors">{{ t('home.profile') }}</p>
                <p class="text-xs text-vault42-muted">{{ t('home.profileDesc') }}</p>
              </div>
            </router-link>

            <router-link to="/sessions" class="vault42-card group hover:border-vault42-primary/50 transition-colors flex items-center gap-4">
              <div class="w-9 h-9 rounded-lg bg-vault42-border flex items-center justify-center group-hover:bg-vault42-primary/15 transition-colors">
                <svg class="w-4 h-4 text-vault42-muted group-hover:text-vault42-primary transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <div>
                <p class="text-sm font-medium group-hover:text-vault42-primary transition-colors">{{ t('home.sessionsDevices') }}</p>
                <p class="text-xs text-vault42-muted">{{ t('home.sessionsDevicesDesc') }}</p>
              </div>
            </router-link>

            <router-link to="/2fa" class="vault42-card group hover:border-vault42-primary/50 transition-colors flex items-center gap-4">
              <div class="w-9 h-9 rounded-lg bg-vault42-border flex items-center justify-center group-hover:bg-vault42-primary/15 transition-colors">
                <svg class="w-4 h-4 text-vault42-muted group-hover:text-vault42-primary transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <p class="text-sm font-medium group-hover:text-vault42-primary transition-colors">{{ t('home.twoFactorAuth') }}</p>
                <p class="text-xs text-vault42-muted">{{ t('home.twoFactorAuthDesc') }}</p>
              </div>
            </router-link>

            <router-link to="/password" class="vault42-card group hover:border-vault42-primary/50 transition-colors flex items-center gap-4">
              <div class="w-9 h-9 rounded-lg bg-vault42-border flex items-center justify-center group-hover:bg-vault42-primary/15 transition-colors">
                <svg class="w-4 h-4 text-vault42-muted group-hover:text-vault42-primary transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
              </div>
              <div>
                <p class="text-sm font-medium group-hover:text-vault42-primary transition-colors">{{ t('home.changePassword') }}</p>
                <p class="text-xs text-vault42-muted">{{ t('home.changePasswordDesc') }}</p>
              </div>
            </router-link>

            <router-link to="/identity" class="vault42-card group hover:border-vault42-primary/50 transition-colors flex items-center gap-4">
              <div class="w-9 h-9 rounded-lg bg-vault42-border flex items-center justify-center group-hover:bg-vault42-primary/15 transition-colors">
                <svg class="w-4 h-4 text-vault42-muted group-hover:text-vault42-primary transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                </svg>
              </div>
              <div>
                <p class="text-sm font-medium group-hover:text-vault42-primary transition-colors">{{ t('home.personalInfo') }}</p>
                <p class="text-xs text-vault42-muted">{{ t('home.personalInfoDesc') }}</p>
              </div>
            </router-link>

            <router-link to="/storage" class="vault42-card group hover:border-vault42-primary/50 transition-colors flex items-center gap-4">
              <div class="w-9 h-9 rounded-lg bg-vault42-border flex items-center justify-center group-hover:bg-vault42-primary/15 transition-colors">
                <svg class="w-4 h-4 text-vault42-muted group-hover:text-vault42-primary transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                </svg>
              </div>
              <div>
                <p class="text-sm font-medium group-hover:text-vault42-primary transition-colors">{{ t('home.encryptedStorage') }}</p>
                <p class="text-xs text-vault42-muted">{{ t('home.encryptedStorageDesc') }}</p>
              </div>
            </router-link>
          </div>
        </div>
      </div>
    </template>

    <template #loading>
      <div class="flex items-center justify-center min-h-[60vh]">
        <div class="vault42-spinner vault42-spinner-lg"></div>
      </div>
    </template>

    <template #fallback>
      <div class="max-w-2xl mx-auto px-4 sm:px-6 py-20 text-center">
        <div class="text-5xl mb-6">&#x1f510;</div>
        <h1 class="text-3xl sm:text-4xl font-bold mb-3">{{ t('home.hero.title') }}</h1>
        <p class="text-vault42-muted text-lg mb-8 max-w-md mx-auto">
          {{ t('home.hero.description') }}
        </p>
        <div class="flex justify-center gap-4">
          <router-link to="/login" class="vault42-btn px-6">{{ t('home.hero.signIn') }}</router-link>
          <router-link to="/register" class="vault42-btn-outline px-6">{{ t('home.hero.createAccount') }}</router-link>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-16 text-left">
          <div class="vault42-card">
            <div class="text-vault42-primary text-lg mb-2">&#x1f512;</div>
            <h3 class="text-sm font-semibold mb-1">{{ t('home.feature.securityFirst') }}</h3>
            <p class="text-xs text-vault42-muted">{{ t('home.feature.securityFirstDesc') }}</p>
          </div>
          <div class="vault42-card">
            <div class="text-vault42-primary text-lg mb-2">&#x1f511;</div>
            <h3 class="text-sm font-semibold mb-1">{{ t('home.feature.rs256') }}</h3>
            <p class="text-xs text-vault42-muted">{{ t('home.feature.rs256Desc') }}</p>
          </div>
          <div class="vault42-card">
            <div class="text-vault42-primary text-lg mb-2">&#x1f6e1;</div>
            <h3 class="text-sm font-semibold mb-1">{{ t('home.feature.zeroDeps') }}</h3>
            <p class="text-xs text-vault42-muted">{{ t('home.feature.zeroDepsDesc') }}</p>
          </div>
        </div>
      </div>
    </template>
  </VaultAuthGuard>
</template>
