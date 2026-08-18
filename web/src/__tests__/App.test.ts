import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import { createRouter, createWebHistory, type Router } from 'vue-router'
import App from '../App.vue'
import { loadLocale } from '../i18n'
import en from '../locales/en.json'
import sk from '../locales/sk.json'

// NOTE: src/__tests__/AppNav.test.ts already covers the navigation links, the
// active-route highlight, the user email, the happy-path sign-out, the footer
// links and init()-on-mount. This file covers the rest of the shell: the
// pre-init gate, registration gating, the routed outlet, mobile-menu dismissal,
// locale re-rendering through the footer switcher, and sign-out failure.

const localeMessages: Record<string, Record<string, string>> = {
  en: en as Record<string, string>,
  sk: sk as Record<string, string>,
}

const mockIsAuthenticated = ref(true)
const mockInitialized = ref(true)
const mockIsLoading = ref(false)
const mockUser = ref<{ email: string } | null>({ email: 'v@example.com' })
const mockRegistrationEnabled = ref(true)
const mockInit = vi.fn()
const mockLogout = vi.fn()

const mockLocale = ref('en')
const mockSetLocale = vi.fn((loc: string) => {
  if (localeMessages[loc]) mockLocale.value = loc
})

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
    // Locale-reactive on purpose: reading mockLocale during render is what lets
    // the "switching locale re-renders copy" test mean anything.
    t: (key: string) => {
      const msgs = localeMessages[mockLocale.value] ?? localeMessages.en
      return msgs[key] ?? localeMessages.en[key] ?? key
    },
    locale: mockLocale,
    setLocale: mockSetLocale,
    availableLocales: ['en', 'sk'],
    formatDate: (d: Date) => d.toLocaleDateString(),
    formatNumber: (n: number) => n.toString(),
  }),
}))

const stub = { template: '<div />' }
const homeStub = { template: '<p>routed home content</p>' }

function createTestRouter(): Router {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: homeStub },
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

async function mountApp(path = '/') {
  const router = createTestRouter()
  await router.push(path)
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, router }
}

function hamburger(wrapper: Awaited<ReturnType<typeof mountApp>>['wrapper']) {
  return wrapper.findAll('button').find(b => b.classes().includes('md:hidden'))!
}

describe('App shell', () => {
  // LanguageSwitcher.select awaits the locale's catalogue chunk before it
  // switches. Warming them puts it on the already-loaded fast path, so one
  // flushPromises settles the click instead of racing a cold dynamic import.
  beforeAll(async () => {
    await Promise.all(['en', 'sk'].map(loadLocale))
  })

  beforeEach(() => {
    vi.clearAllMocks()
    mockIsAuthenticated.value = true
    mockInitialized.value = true
    mockIsLoading.value = false
    mockUser.value = { email: 'v@example.com' }
    mockRegistrationEnabled.value = true
    mockLocale.value = 'en'
    mockLogout.mockResolvedValue(undefined)
  })

  // --- layout ---------------------------------------------------------------

  it('renders a single nav / main / footer skeleton', async () => {
    const { wrapper } = await mountApp()

    expect(wrapper.findAll('nav')).toHaveLength(1)
    expect(wrapper.findAll('main')).toHaveLength(1)
    expect(wrapper.findAll('footer')).toHaveLength(1)
  })

  it('renders the routed view inside main', async () => {
    const { wrapper } = await mountApp()

    expect(wrapper.find('main').text()).toContain('routed home content')
  })

  it('swaps the routed view without remounting the shell', async () => {
    const { wrapper, router } = await mountApp()
    expect(wrapper.find('main').text()).toContain('routed home content')

    await router.push('/profile')
    await flushPromises()

    expect(wrapper.find('main').text()).not.toContain('routed home content')
    expect(mockInit).toHaveBeenCalledOnce()
  })

  it('renders the brand link back to the dashboard', async () => {
    const { wrapper } = await mountApp('/profile')

    const brand = wrapper.findAll('a').find(a => a.text().includes('Vault42'))
    expect(brand!.attributes('href')).toBe('/')
  })

  it('mounts the language switcher inside the footer', async () => {
    const { wrapper } = await mountApp()

    expect(wrapper.find('footer').text()).toContain('English')
  })

  // --- pre-init gate --------------------------------------------------------

  it('hides the desktop nav entirely until auth has initialised', async () => {
    mockInitialized.value = false
    const { wrapper } = await mountApp()

    const labels = wrapper.findAll('a').map(a => a.text())
    expect(labels).not.toContain('Dashboard')
    expect(labels).not.toContain('Identity')
    expect(labels).not.toContain('Sign In')
    expect(wrapper.text()).not.toContain('v@example.com')
  })

  it('reveals the nav once auth initialises', async () => {
    mockInitialized.value = false
    const { wrapper } = await mountApp()
    expect(wrapper.findAll('a').map(a => a.text())).not.toContain('Dashboard')

    mockInitialized.value = true
    await flushPromises()

    expect(wrapper.findAll('a').map(a => a.text())).toContain('Dashboard')
  })

  // --- registration gating --------------------------------------------------

  it('hides the desktop register CTA when registration is disabled', async () => {
    mockIsAuthenticated.value = false
    mockRegistrationEnabled.value = false
    const { wrapper } = await mountApp()

    expect(wrapper.text()).toContain('Sign In')
    expect(wrapper.text()).not.toContain('Get Started')
    expect(wrapper.findAll('a').map(a => a.attributes('href'))).not.toContain('/register')
  })

  it('hides the mobile register link when registration is disabled', async () => {
    mockIsAuthenticated.value = false
    mockRegistrationEnabled.value = false
    const { wrapper } = await mountApp()

    await hamburger(wrapper).trigger('click')

    expect(wrapper.text()).not.toContain('Create Account')
    expect(wrapper.findAll('a').map(a => a.attributes('href'))).not.toContain('/register')
  })

  it('offers the mobile register link when registration is enabled', async () => {
    mockIsAuthenticated.value = false
    mockRegistrationEnabled.value = true
    const { wrapper } = await mountApp()

    await hamburger(wrapper).trigger('click')

    const createLink = wrapper.findAll('a').find(a => a.text() === 'Create Account')
    expect(createLink!.attributes('href')).toBe('/register')
  })

  // --- mobile menu dismissal ------------------------------------------------

  it('reports the mobile menu state through aria-expanded', async () => {
    const { wrapper } = await mountApp()
    expect(hamburger(wrapper).attributes('aria-expanded')).toBe('false')

    await hamburger(wrapper).trigger('click')
    expect(hamburger(wrapper).attributes('aria-expanded')).toBe('true')

    await hamburger(wrapper).trigger('click')
    expect(hamburger(wrapper).attributes('aria-expanded')).toBe('false')
  })

  it('closes the mobile menu after following one of its links', async () => {
    const { wrapper, router } = await mountApp()
    await hamburger(wrapper).trigger('click')
    expect(wrapper.text()).toContain('Account')

    const storageLink = wrapper.findAll('a').find(a => a.text() === 'Encrypted Storage')
    await storageLink!.trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.path).toBe('/storage')
    expect(wrapper.text()).not.toContain('Account')
    expect(hamburger(wrapper).attributes('aria-expanded')).toBe('false')
  })

  it('closes the mobile menu when the brand link is used', async () => {
    const { wrapper } = await mountApp('/profile')
    await hamburger(wrapper).trigger('click')
    expect(wrapper.text()).toContain('Account')

    const brand = wrapper.findAll('a').find(a => a.text().includes('Vault42'))
    await brand!.trigger('click')
    await flushPromises()

    expect(wrapper.text()).not.toContain('Account')
  })

  it('closes the mobile menu after a successful sign-out', async () => {
    const { wrapper, router } = await mountApp()
    await hamburger(wrapper).trigger('click')

    const signOut = wrapper.findAll('button').filter(b => b.text() === 'Sign Out')
    await signOut[signOut.length - 1].trigger('click')
    await flushPromises()

    expect(mockLogout).toHaveBeenCalledOnce()
    expect(router.currentRoute.value.path).toBe('/login')
    expect(hamburger(wrapper).attributes('aria-expanded')).toBe('false')
  })

  // --- sign-out failure -----------------------------------------------------

  it('does not pretend the user is signed out when logout fails', async () => {
    const errors: unknown[] = []
    mockLogout.mockRejectedValue(new Error('network down'))

    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mount(App, {
      global: {
        plugins: [router],
        config: { errorHandler: (e: unknown) => { errors.push(e) } },
      },
    })

    const signOut = wrapper.findAll('button').find(b => b.text() === 'Sign Out')
    await signOut!.trigger('click')
    await flushPromises()

    expect(mockLogout).toHaveBeenCalledOnce()
    // The redirect must not fire on a failed logout, or the user would be shown
    // a login page while their session is in fact still alive server-side.
    expect(router.currentRoute.value.path).toBe('/')
    expect(errors).toHaveLength(1)
  })

  // --- locale ---------------------------------------------------------------

  it('re-renders shell copy in the locale picked from the footer switcher', async () => {
    const { wrapper } = await mountApp()
    expect(wrapper.text()).toContain('Zero-trust authentication')
    expect(wrapper.findAll('a').map(a => a.text())).toContain('Dashboard')

    const switcherTrigger = wrapper.find('footer').findAll('button')[0]
    await switcherTrigger.trigger('click')
    const slovak = wrapper.find('footer').findAll('button').find(b => b.text().includes('Slovencina'))
    await slovak!.trigger('click')
    await flushPromises()

    expect(mockSetLocale).toHaveBeenCalledExactlyOnceWith('sk')
    expect(wrapper.text()).toContain('Autentifikácia s nulovou dôverou')
    expect(wrapper.text()).not.toContain('Zero-trust authentication')
    expect(wrapper.findAll('a').map(a => a.text())).toContain('Prehľad')
    expect(wrapper.findAll('button').map(b => b.text())).toContain('Odhlásiť sa')
  })

  it('re-renders the mobile menu copy after a locale change', async () => {
    const { wrapper } = await mountApp()

    const switcherTrigger = wrapper.find('footer').findAll('button')[0]
    await switcherTrigger.trigger('click')
    await wrapper.find('footer').findAll('button').find(b => b.text().includes('Slovencina'))!.trigger('click')
    await flushPromises()

    await hamburger(wrapper).trigger('click')

    expect(wrapper.text()).not.toContain('Encrypted Storage')
    expect(wrapper.text()).toContain((sk as Record<string, string>)['nav.encryptedStorage'])
  })
})
