import { createRouter, createWebHistory } from 'vue-router'
import { watch } from 'vue'
import { getAuthState } from '@vault42/vue'

const routes = [
  {
    path: '/',
    name: 'home',
    component: () => import('./views/HomeView.vue'),
    meta: { title: 'Dashboard' },
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('./views/LoginView.vue'),
    meta: { title: 'Sign In' },
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('./views/RegisterView.vue'),
    meta: { title: 'Create Account' },
  },
  {
    path: '/forgot-password',
    name: 'forgot-password',
    component: () => import('./views/ForgotPasswordView.vue'),
    meta: { title: 'Reset Password' },
  },
  {
    path: '/reset-password',
    name: 'reset-password',
    component: () => import('./views/ResetPasswordView.vue'),
    meta: { title: 'Set New Password' },
  },
  {
    path: '/profile',
    name: 'profile',
    component: () => import('./views/ProfileView.vue'),
    meta: { title: 'Profile', requiresAuth: true },
  },
  {
    path: '/sessions',
    name: 'sessions',
    component: () => import('./views/SessionsView.vue'),
    meta: { title: 'Sessions & Devices', requiresAuth: true },
  },
  {
    path: '/2fa',
    name: '2fa',
    component: () => import('./views/TwoFactorView.vue'),
    meta: { title: 'Two-Factor Authentication', requiresAuth: true },
  },
  {
    path: '/mfa-onboarding',
    name: 'mfa-onboarding',
    component: () => import('./views/MFAOnboardingView.vue'),
    meta: { title: 'Set Up MFA', requiresAuth: true },
  },
  {
    path: '/password',
    name: 'password',
    component: () => import('./views/PasswordView.vue'),
    meta: { title: 'Change Password', requiresAuth: true },
  },
  {
    path: '/identity',
    name: 'identity',
    component: () => import('./views/IdentityView.vue'),
    meta: { title: 'Personal Information', requiresAuth: true },
  },
  {
    path: '/storage',
    name: 'storage',
    component: () => import('./views/BlobsView.vue'),
    meta: { title: 'Encrypted Storage', requiresAuth: true },
  },
  {
    path: '/verify-email',
    name: 'verify-email',
    component: () => import('./views/VerifyEmailView.vue'),
    meta: { title: 'Verify Email' },
  },
  {
    path: '/oauth/callback',
    name: 'oauth-callback',
    component: () => import('./views/OAuthCallbackView.vue'),
    meta: { title: 'Signing In...' },
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('./views/NotFoundView.vue'),
    meta: { title: 'Not Found' },
  },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior() {
    return { top: 0 }
  },
})

router.beforeEach(async (to) => {
  document.title = to.meta.title
    ? `${to.meta.title} — Vault42`
    : 'Vault42'

  if (to.meta.requiresAuth) {
    const { isAuthenticated, initialized, init } = getAuthState()

    // Wait for auth init if not done yet
    if (!initialized.value) {
      try {
        await init()
      } catch {
        // Client not yet initialized — redirect to login
        return { path: '/login', query: { redirect: to.fullPath } }
      }
    }

    if (!isAuthenticated.value) {
      return { path: '/login', query: { redirect: to.fullPath } }
    }
  }

  // Block register route when registration is disabled
  if (to.name === 'register') {
    const { registrationEnabled, init } = getAuthState()
    // init() is idempotent and returns the in-flight promise, so this is safe to
    // await unconditionally, and awaiting it unconditionally is simply cheaper
    // to read than a guard that has to be re-argued every time this file moves.
    //
    // It is NOT load-bearing. `initialized` cannot be true before the
    // capabilities fetch has settled: runInit awaits it in its finally block
    // before flipping the flag, and the fetch carries its own catch so it always
    // settles rather than rejecting (useAuth.ts). This comment used to claim the
    // opposite -- that `initialized` could be true while capabilities was still
    // in flight -- which would have made the unconditional await the only thing
    // standing between a visitor and a /register page the server has disabled.
    // It is not; the watch below is.
    try { await init() } catch { /* offline: fall through, the server still enforces */ }
    if (!registrationEnabled.value) {
      return { path: '/login' }
    }
  }

  // Explicit, not implicit. vue-router reads `undefined` as "allow this
  // navigation", which is the same thing falling off the end of the guard meant,
  // but only one of the two says so — and only one of them satisfies
  // noImplicitReturns, which is what stops the next branch added above from
  // forgetting its own return.
  return undefined
})

// Second line of defence for the registration toggle.
//
// `registrationEnabled` starts optimistic (true) and only becomes authoritative
// once GET /auth/capabilities has answered. The guard above reads it at
// navigation time, which cannot be the whole story: the answer may land after
// init() resolves, and a visitor already sitting on /register was never guarded
// at all. Watching the flag closes both holes without depending on init()
// settling capabilities first, so the guard never has to win a race.
//
// Fail-open on the way in, fail-closed the moment the server actually says no:
// blocking sign up because capabilities could not be fetched would be worse than
// briefly showing a form the server would reject anyway.
const { registrationEnabled } = getAuthState()

watch(registrationEnabled, (enabled) => {
  if (!enabled && router.currentRoute.value.name === 'register') {
    void router.replace('/login')
  }
}, { flush: 'sync' })
