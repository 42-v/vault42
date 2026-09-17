<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useAuth, useT } from '@vault42/vue'
import { useRouter, useRoute } from 'vue-router'
import LanguageSwitcher from './components/LanguageSwitcher.vue'

const { isAuthenticated, user, logout, init, initialized, registrationEnabled } = useAuth()
const { t } = useT()
const router = useRouter()
const route = useRoute()
const mobileOpen = ref(false)

const navLinks = computed(() => [
  { to: '/', short: t('nav.dashboard'), long: t('nav.dashboard') },
  { to: '/profile', short: t('nav.profile'), long: t('nav.profile') },
  { to: '/sessions', short: t('nav.sessions'), long: t('nav.sessionsDevices') },
  { to: '/2fa', short: t('nav.2fa'), long: t('nav.twoFactorAuth') },
  { to: '/password', short: t('nav.password'), long: t('nav.changePassword') },
  { to: '/identity', short: t('nav.identity'), long: t('nav.personalInfo') },
  { to: '/storage', short: t('nav.storage'), long: t('nav.encryptedStorage') },
])

onMounted(() => {
  init()
})

async function handleLogout() {
  await logout()
  mobileOpen.value = false
  router.push('/login')
}

function closeMobile() {
  mobileOpen.value = false
}

function isActive(path: string): boolean {
  return route.path === path
}
</script>

<template>
  <div class="min-h-screen flex flex-col">
    <!-- Navigation -->
    <nav class="sticky top-0 z-50 bg-vault42-surface/80 backdrop-blur-xl border-b border-vault42-border">
      <div class="max-w-6xl mx-auto px-4 sm:px-6">
        <div class="flex items-center justify-between h-14">
          <!-- Logo -->
          <router-link to="/" class="flex items-center gap-2 group" @click="closeMobile">
            <span class="text-xl">&#x1f510;</span>
            <span class="text-lg font-bold text-vault42-text group-hover:text-vault42-accent transition-colors">{{ t('brand.name') }}</span>
          </router-link>

          <!-- Desktop nav -->
          <div v-if="initialized" class="hidden md:flex items-center gap-1">
            <template v-if="isAuthenticated">
              <router-link
                v-for="link in navLinks"
                :key="link.to"
                :to="link.to"
                :aria-current="isActive(link.to) ? 'page' : undefined"
                :class="[
                  'px-3 py-1.5 rounded-lg text-sm transition-all duration-200',
                  isActive(link.to)
                    ? 'bg-vault42-primary/15 text-vault42-accent font-medium'
                    : 'text-vault42-muted hover:text-vault42-text hover:bg-vault42-border/50'
                ]"
              >
                {{ link.short }}
              </router-link>

              <div class="w-px h-6 bg-vault42-border mx-2"></div>

              <span class="text-sm text-vault42-muted truncate max-w-[160px]">{{ user?.email }}</span>
              <button
                class="ml-1 px-3 py-1.5 rounded-lg text-sm text-vault42-error hover:bg-vault42-error/10 transition-all duration-200"
                @click="handleLogout"
              >
                {{ t('common.signOut') }}
              </button>
            </template>
            <template v-else>
              <router-link
                to="/login"
                :aria-current="isActive('/login') ? 'page' : undefined"
                :class="[
                  'px-3 py-1.5 rounded-lg text-sm transition-all duration-200',
                  isActive('/login') ? 'text-vault42-accent' : 'text-vault42-muted hover:text-vault42-text'
                ]"
              >
                {{ t('common.signIn') }}
              </router-link>
              <router-link
                v-if="registrationEnabled"
                to="/register"
                class="vault42-btn vault42-btn-sm ml-1"
              >
                {{ t('nav.getStarted') }}
              </router-link>
            </template>
          </div>

          <!-- Mobile hamburger -->
          <button
            aria-label="Toggle menu"
            :aria-expanded="mobileOpen"
            class="md:hidden p-2 text-vault42-muted hover:text-vault42-text"
            @click="mobileOpen = !mobileOpen"
          >
            <svg v-if="!mobileOpen" class="w-5 h-5" aria-hidden="true" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
            <svg v-else class="w-5 h-5" aria-hidden="true" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>

      <!-- Mobile menu -->
      <div v-if="mobileOpen" class="md:hidden border-t border-vault42-border bg-vault42-surface">
        <div class="px-4 py-3 space-y-1">
          <template v-if="isAuthenticated">
            <div class="px-3 py-2 text-xs text-vault42-muted uppercase tracking-wider">{{ t('nav.account') }}</div>
            <router-link
              v-for="link in navLinks"
              :key="link.to"
              :to="link.to"
              :aria-current="isActive(link.to) ? 'page' : undefined"
              :class="[
                'block px-3 py-2 rounded-lg text-sm transition-colors',
                isActive(link.to) ? 'bg-vault42-primary/15 text-vault42-accent' : 'text-vault42-text hover:bg-vault42-border/50'
              ]"
              @click="closeMobile"
            >
              {{ link.long }}
            </router-link>
            <div class="border-t border-vault42-border mt-2 pt-2">
              <div class="px-3 py-1.5 text-xs text-vault42-muted truncate">{{ user?.email }}</div>
              <button class="w-full text-left px-3 py-2 rounded-lg text-sm text-vault42-error hover:bg-vault42-error/10" @click="handleLogout">
                {{ t('common.signOut') }}
              </button>
            </div>
          </template>
          <template v-else>
            <router-link to="/login" class="block px-3 py-2 rounded-lg text-sm text-vault42-text hover:bg-vault42-border/50" @click="closeMobile">{{ t('common.signIn') }}</router-link>
            <router-link v-if="registrationEnabled" to="/register" class="block px-3 py-2 rounded-lg text-sm text-vault42-accent hover:bg-vault42-primary/10" @click="closeMobile">{{ t('common.createAccount') }}</router-link>
          </template>
        </div>
      </div>
    </nav>

    <!-- Page content -->
    <main class="flex-1">
      <router-view />
    </main>

    <!-- Footer -->
    <footer class="border-t border-vault42-border py-6 mt-auto">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-vault42-muted">
        <span>{{ t('brand.name') }} &mdash; {{ t('brand.tagline') }}</span>
        <div class="flex items-center gap-4">
          <LanguageSwitcher />
          <a href="/.well-known/jwks.json" class="hover:text-vault42-text transition-colors">JWKS</a>
          <a href="/.well-known/openid-configuration" class="hover:text-vault42-text transition-colors">OIDC</a>
          <a href="/healthz" class="hover:text-vault42-text transition-colors">Status</a>
        </div>
      </div>
    </footer>
  </div>
</template>
