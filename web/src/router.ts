import { createRouter, createWebHistory } from 'vue-router'
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
    const { registrationEnabled, initialized, init } = getAuthState()
    if (!initialized.value) {
      try { await init() } catch { /* ignore */ }
    }
    if (!registrationEnabled.value) {
      return { path: '/login' }
    }
  }
})
