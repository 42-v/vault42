import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from '../App.vue'
import en from '../locales/en.json'

const mockIsAuthenticated = ref(true)
const mockInitialized = ref(true)
const mockIsLoading = ref(false)
const mockUser = ref({ email: 'test@example.com' })
const mockRegistrationEnabled = ref(true)
const mockInit = vi.fn()
const mockLogout = vi.fn()

const mockT = (key: string) => (en as Record<string, string>)[key] ?? key

vi.mock('@vault42/vue', () => ({
  useAuth: () => ({
    isAuthenticated: mockIsAuthenticated,
    initialized: mockInitialized,
    isLoading: mockIsLoading,
    user: mockUser,
    registrationEnabled: mockRegistrationEnabled,
    init: mockInit,
    logout: mockLogout,
  }),
  useT: () => ({
    t: mockT,
    locale: ref('en'),
    setLocale: vi.fn(),
    availableLocales: ['en'],
    formatDate: (d: Date) => d.toLocaleDateString(),
    formatNumber: (n: number) => n.toString(),
  }),
}))

const stub = { template: '<div />' }

function createTestRouter() {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: stub },
      { path: '/identity', component: stub },
      { path: '/storage', component: stub },
      { path: '/profile', component: stub },
      { path: '/sessions', component: stub },
      { path: '/2fa', component: stub },
      { path: '/password', component: stub },
      { path: '/login', component: stub },
      { path: '/register', component: stub },
    ],
  })
}

describe('App Navigation', () => {
  beforeEach(() => {
    mockIsAuthenticated.value = true
    mockInitialized.value = true
    mockIsLoading.value = false
    mockUser.value = { email: 'test@example.com' }
    mockRegistrationEnabled.value = true
  })

  it('renders Identity link in desktop nav when authenticated', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const navLinks = wrapper.findAll('a')
    const labels = navLinks.map(a => a.text())
    expect(labels).toContain('Identity')
  })

  it('renders Storage link in desktop nav when authenticated', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const navLinks = wrapper.findAll('a')
    const labels = navLinks.map(a => a.text())
    expect(labels).toContain('Storage')
  })

  it('renders all expected nav links when authenticated', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const text = wrapper.text()
    expect(text).toContain('Dashboard')
    expect(text).toContain('Profile')
    expect(text).toContain('Sessions')
    expect(text).toContain('2FA')
    expect(text).toContain('Password')
    expect(text).toContain('Identity')
    expect(text).toContain('Storage')
  })

  it('does not show nav links when not authenticated', async () => {
    mockIsAuthenticated.value = false
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const text = wrapper.text()
    expect(text).not.toContain('Identity')
    expect(text).not.toContain('Storage')
    expect(text).toContain('Sign In')
  })

  it('Identity link points to /identity', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const identityLink = wrapper.findAll('a').find(a => a.text() === 'Identity')
    expect(identityLink).toBeDefined()
    expect(identityLink!.attributes('href')).toBe('/identity')
  })

  it('Storage link points to /storage', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const storageLink = wrapper.findAll('a').find(a => a.text() === 'Storage')
    expect(storageLink).toBeDefined()
    expect(storageLink!.attributes('href')).toBe('/storage')
  })

  it('shows user email when authenticated', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    expect(wrapper.text()).toContain('test@example.com')
  })

  it('calls logout and navigates to /login on Sign Out click', async () => {
    mockLogout.mockResolvedValue(undefined)
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const signOutBtn = wrapper.findAll('button').find(b => b.text() === 'Sign Out')
    expect(signOutBtn).toBeDefined()
    await signOutBtn!.trigger('click')
    await flushPromises()

    expect(mockLogout).toHaveBeenCalledOnce()
    expect(router.currentRoute.value.path).toBe('/login')
  })

  it('highlights active route', async () => {
    const router = createTestRouter()
    await router.push('/identity')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const identityLink = wrapper.findAll('a').find(a => a.text() === 'Identity')
    expect(identityLink?.classes().some(c => c.includes('text-vault42-primary'))).toBe(true)
  })

  it('does not highlight non-active routes', async () => {
    const router = createTestRouter()
    await router.push('/identity')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    const profileLink = wrapper.findAll('a').find(a => a.text() === 'Profile')
    expect(profileLink?.classes().some(c => c.includes('text-vault42-muted'))).toBe(true)
  })

  it('renders footer links', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    expect(wrapper.text()).toContain('JWKS')
    expect(wrapper.text()).toContain('OIDC')
    expect(wrapper.text()).toContain('Status')
  })

  it('calls init on mount', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    mount(App, {
      global: {
        plugins: [router],
      },
    })

    expect(mockInit).toHaveBeenCalled()
  })

  it('shows hamburger menu button', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    // The hamburger button has md:hidden class
    const hamburgerBtn = wrapper.findAll('button').find(b => b.classes().includes('md:hidden'))
    expect(hamburgerBtn).toBeDefined()
  })

  it('toggles mobile menu on hamburger click', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    // Mobile menu should not be visible initially
    expect(wrapper.text()).not.toContain('Account')

    // Click hamburger
    const hamburgerBtn = wrapper.findAll('button').find(b => b.classes().includes('md:hidden'))
    await hamburgerBtn!.trigger('click')

    // Mobile menu should now show
    expect(wrapper.text()).toContain('Account')
    expect(wrapper.text()).toContain('Personal Info')
    expect(wrapper.text()).toContain('Encrypted Storage')
  })

  it('shows Sign In and Create Account when not authenticated', async () => {
    mockIsAuthenticated.value = false
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: {
        plugins: [router],
      },
    })

    expect(wrapper.text()).toContain('Sign In')
    expect(wrapper.text()).toContain('Get Started')
  })
})
