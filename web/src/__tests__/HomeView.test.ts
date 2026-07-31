import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, defineComponent } from 'vue'
import { createRouter, createWebHistory, type Router } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import en from '../locales/en.json'

const mockFetchProfile = vi.fn()
const mockFetchMFAStatus = vi.fn()

const mockUser = ref<Record<string, unknown> | null>(null)
const mockProfile = ref<Record<string, unknown> | null>(null)
const mockMfaStatus = ref<Record<string, unknown> | null>(null)

// Drives the VaultAuthGuard mock below. Mirrors the real guard's slot selection:
// authenticated -> default, (isLoading || !initialized) -> loading, else -> fallback.
const mockIsAuthenticated = ref(true)
const mockAuthIsLoading = ref(false)
const mockInitialized = ref(true)

const formatDate = (d: Date) => d.toLocaleDateString()

vi.mock('@vault42/vue', () => ({
  useAuth: () => ({
    user: mockUser,
    isAuthenticated: mockIsAuthenticated,
    isLoading: mockAuthIsLoading,
    initialized: mockInitialized,
  }),
  useProfile: () => ({
    profile: mockProfile,
    fetchProfile: mockFetchProfile,
  }),
  use2FA: () => ({
    mfaStatus: mockMfaStatus,
    fetchMFAStatus: mockFetchMFAStatus,
  }),
  useT: () => ({
    t: (key: string, params?: Record<string, string | number>) => {
      const val = (en as Record<string, string>)[key] ?? key
      if (!params) return val
      return val.replace(/\{(\w+)\}/g, (_, name: string) => params[name] != null ? String(params[name]) : `{${name}}`)
    },
    formatDate,
    formatNumber: (n: number) => n.toString(),
  }),
  VaultAuthGuard: defineComponent({
    setup(_, { slots }) {
      return () => {
        if (mockIsAuthenticated.value) return slots.default ? slots.default() : []
        if (mockAuthIsLoading.value || !mockInitialized.value) return slots.loading ? slots.loading() : []
        return slots.fallback ? slots.fallback() : []
      }
    },
  }),
}))

const stub = { template: '<div />' }

function createTestRouter(): Router {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: stub },
      { path: '/profile', component: stub },
      { path: '/sessions', component: stub },
      { path: '/2fa', component: stub },
      { path: '/password', component: stub },
      { path: '/identity', component: stub },
      { path: '/storage', component: stub },
      { path: '/login', component: stub },
      { path: '/register', component: stub },
    ],
  })
}

async function mountView() {
  const router = createTestRouter()
  await router.push('/')
  await router.isReady()
  return mount(HomeView, { global: { plugins: [router] } })
}

describe('HomeView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUser.value = { email: 'v@example.com' }
    mockProfile.value = null
    mockMfaStatus.value = null
    mockIsAuthenticated.value = true
    mockAuthIsLoading.value = false
    mockInitialized.value = true
    mockFetchProfile.mockResolvedValue(undefined)
    mockFetchMFAStatus.mockResolvedValue(undefined)
  })

  // --- authenticated dashboard ---------------------------------------------

  it('greets the signed-in user by display name', async () => {
    mockUser.value = { email: 'v@example.com', display_name: 'Vee' }
    const wrapper = await mountView()

    expect(wrapper.find('h1').text()).toBe('Welcome back, Vee')
  })

  it('greets without a trailing comma when the account has no display name', async () => {
    mockUser.value = { email: 'v@example.com' }
    const wrapper = await mountView()

    expect(wrapper.find('h1').text()).toBe('Welcome back')
  })

  it('loads the profile and the MFA status exactly once on mount', async () => {
    await mountView()
    await flushPromises()

    expect(mockFetchProfile).toHaveBeenCalledOnce()
    expect(mockFetchMFAStatus).toHaveBeenCalledOnce()
  })

  it('shows the account email with a Verified badge once the profile confirms it', async () => {
    mockProfile.value = { email_verified: true, created_at: '2026-01-15T09:00:00Z' }
    const wrapper = await mountView()

    expect(wrapper.text()).toContain('v@example.com')
    expect(wrapper.find('.vault42-badge-success').text()).toBe('Verified')
    expect(wrapper.find('.vault42-badge-error').exists()).toBe(false)
  })

  it('shows an Unverified badge when the profile says the email is not verified', async () => {
    mockProfile.value = { email_verified: false, created_at: '2026-01-15T09:00:00Z' }
    const wrapper = await mountView()

    expect(wrapper.find('.vault42-badge-error').text()).toBe('Unverified')
    expect(wrapper.find('.vault42-badge-success').exists()).toBe(false)
  })

  it('reports two-factor as Enabled and drops the enable prompt when TOTP is on', async () => {
    mockMfaStatus.value = { totp_enabled: true, webauthn_enabled: false }
    const wrapper = await mountView()

    expect(wrapper.text()).toContain('Enabled')
    expect(wrapper.text()).not.toContain('Enable now')
  })

  it('reports two-factor as Enabled when only a security key is registered', async () => {
    mockMfaStatus.value = { totp_enabled: false, webauthn_enabled: true }
    const wrapper = await mountView()

    expect(wrapper.text()).toContain('Enabled')
    expect(wrapper.text()).not.toContain('Enable now')
  })

  it('offers an Enable now shortcut to /2fa when no second factor is configured', async () => {
    mockMfaStatus.value = { totp_enabled: false, webauthn_enabled: false }
    const wrapper = await mountView()

    expect(wrapper.text()).toContain('Disabled')
    const enableLink = wrapper.findAll('a').find(a => a.text() === 'Enable now')
    expect(enableLink).toBeDefined()
    expect(enableLink!.attributes('href')).toBe('/2fa')
  })

  it('says security keys are Registered and offers Manage keys when WebAuthn is on', async () => {
    mockMfaStatus.value = { totp_enabled: false, webauthn_enabled: true }
    const wrapper = await mountView()

    expect(wrapper.text()).toContain('Registered')
    expect(wrapper.text()).not.toContain('Not Configured')
    const manageLink = wrapper.findAll('a').find(a => a.text() === 'Manage keys')
    expect(manageLink!.attributes('href')).toBe('/2fa')
  })

  it('says security keys are Not Configured and offers Set up when WebAuthn is off', async () => {
    mockMfaStatus.value = { totp_enabled: true, webauthn_enabled: false }
    const wrapper = await mountView()

    expect(wrapper.text()).toContain('Not Configured')
    expect(wrapper.text()).not.toContain('Registered')
    const setUpLink = wrapper.findAll('a').find(a => a.text() === 'Set up')
    expect(setUpLink!.attributes('href')).toBe('/2fa')
  })

  it('formats the member-since date from the profile', async () => {
    mockProfile.value = { email_verified: true, created_at: '2026-01-15T09:00:00Z' }
    const wrapper = await mountView()

    expect(wrapper.text()).toContain(formatDate(new Date('2026-01-15T09:00:00Z')))
  })

  it('links every security-settings card at its route', async () => {
    const wrapper = await mountView()

    const hrefs = wrapper.findAll('a').map(a => a.attributes('href'))
    expect(hrefs).toEqual(expect.arrayContaining([
      '/profile', '/sessions', '/2fa', '/password', '/identity', '/storage',
    ]))
  })

  // --- loading state --------------------------------------------------------

  it('shows only a spinner while auth is still initialising', async () => {
    mockIsAuthenticated.value = false
    mockInitialized.value = false
    const wrapper = await mountView()

    expect(wrapper.find('.vault42-spinner').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('Welcome back')
    expect(wrapper.text()).not.toContain('Security Settings')
  })

  it('keeps the spinner from co-existing with dashboard content', async () => {
    mockIsAuthenticated.value = false
    mockInitialized.value = false
    mockProfile.value = { email_verified: true, created_at: '2026-01-15T09:00:00Z' }
    mockMfaStatus.value = { totp_enabled: true, webauthn_enabled: true }
    const wrapper = await mountView()

    expect(wrapper.findAll('.vault42-spinner')).toHaveLength(1)
    expect(wrapper.text()).not.toContain('v@example.com')
    expect(wrapper.text()).not.toContain('Enabled')
  })

  // --- signed-out hero ------------------------------------------------------

  it('shows the marketing hero with sign-in and register links when signed out', async () => {
    mockIsAuthenticated.value = false
    mockInitialized.value = true
    const wrapper = await mountView()

    expect(wrapper.find('h1').text()).toBe('Vault42')
    expect(wrapper.text()).toContain('Production-grade JWT authentication.')

    const signIn = wrapper.findAll('a').find(a => a.text() === 'Sign In')
    const register = wrapper.findAll('a').find(a => a.text() === 'Create Account')
    expect(signIn!.attributes('href')).toBe('/login')
    expect(register!.attributes('href')).toBe('/register')
  })

  it('never leaks the account email into the signed-out hero', async () => {
    mockUser.value = { email: 'v@example.com', display_name: 'Vee' }
    mockProfile.value = { email_verified: true, created_at: '2026-01-15T09:00:00Z' }
    mockIsAuthenticated.value = false
    mockInitialized.value = true
    const wrapper = await mountView()

    expect(wrapper.text()).not.toContain('v@example.com')
    expect(wrapper.text()).not.toContain('Vee')
    expect(wrapper.text()).not.toContain('Welcome back')
  })

  it('renders the three feature cards on the signed-out hero', async () => {
    mockIsAuthenticated.value = false
    mockInitialized.value = true
    const wrapper = await mountView()

    expect(wrapper.text()).toContain('Security First')
    expect(wrapper.text()).toContain('RS256 JWTs')
    expect(wrapper.text()).toContain('Zero Dependencies')
  })

  // --- failed data fetch ----------------------------------------------------
  // useProfile/use2FA swallow transport errors and leave their refs null, so a
  // failed fetch reaches HomeView as "no data" rather than as an error.

  it('does not claim the email is verified when the profile fetch failed', async () => {
    mockProfile.value = null
    const wrapper = await mountView()
    await flushPromises()

    expect(wrapper.find('.vault42-badge-success').exists()).toBe(false)
    // The email itself comes from useAuth, so it must still render.
    expect(wrapper.text()).toContain('v@example.com')
  })

  it('does not claim security keys are registered when the MFA fetch failed', async () => {
    mockMfaStatus.value = null
    const wrapper = await mountView()
    await flushPromises()

    expect(wrapper.text()).not.toContain('Registered')
    expect(wrapper.text()).toContain('Not Configured')
  })

  it('renders a placeholder rather than an invalid date when created_at is absent', async () => {
    mockProfile.value = { email_verified: true }
    const wrapper = await mountView()

    expect(wrapper.text()).toContain('...')
    expect(wrapper.text()).not.toContain('Invalid Date')
    expect(wrapper.text()).not.toContain('NaN')
  })

  it('keeps the dashboard usable when both fetches come back empty', async () => {
    mockProfile.value = null
    mockMfaStatus.value = null
    const wrapper = await mountView()
    await flushPromises()

    // No permanent spinner, and every quick action is still reachable.
    expect(wrapper.find('.vault42-spinner').exists()).toBe(false)
    expect(wrapper.find('h1').text()).toBe('Welcome back')
    const hrefs = wrapper.findAll('a').map(a => a.attributes('href'))
    expect(hrefs).toEqual(expect.arrayContaining([
      '/profile', '/sessions', '/2fa', '/password', '/identity', '/storage',
    ]))
  })
})
