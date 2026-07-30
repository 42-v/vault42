import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ref, computed } from 'vue'
import { safeRedirect } from '../utils/safeRedirect'

const mockAccessToken = ref<string | null>(null)
const mockInitialized = ref(true)
const mockRegistrationEnabled = ref(true)
const mockInit = vi.fn()

vi.mock('@vault42/vue', () => ({
  getAuthState: () => ({
    isAuthenticated: computed(() => !!mockAccessToken.value),
    initialized: mockInitialized,
    registrationEnabled: mockRegistrationEnabled,
    init: mockInit,
  }),
}))

// Every view is stubbed so the guard is exercised without dragging real view
// modules (and their composables) into the test. The lazy import in each route
// definition still runs, which is the point.
const stub = { default: { template: '<div />' } }
vi.mock('../views/HomeView.vue', () => stub)
vi.mock('../views/LoginView.vue', () => stub)
vi.mock('../views/RegisterView.vue', () => stub)
vi.mock('../views/ForgotPasswordView.vue', () => stub)
vi.mock('../views/ResetPasswordView.vue', () => stub)
vi.mock('../views/ProfileView.vue', () => stub)
vi.mock('../views/SessionsView.vue', () => stub)
vi.mock('../views/TwoFactorView.vue', () => stub)
vi.mock('../views/MFAOnboardingView.vue', () => stub)
vi.mock('../views/PasswordView.vue', () => stub)
vi.mock('../views/IdentityView.vue', () => stub)
vi.mock('../views/BlobsView.vue', () => stub)
vi.mock('../views/VerifyEmailView.vue', () => stub)
vi.mock('../views/OAuthCallbackView.vue', () => stub)
vi.mock('../views/NotFoundView.vue', () => stub)

const { router } = await import('../router')

function signedIn() {
  mockAccessToken.value = 'token'
}

// Lets a navigation the router started outside a push() await run to completion.
const flushPromises = () => new Promise(resolve => setTimeout(resolve, 0))

describe('router guard', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    mockAccessToken.value = null
    mockInitialized.value = true
    mockRegistrationEnabled.value = true
    mockInit.mockResolvedValue(undefined)
    await router.replace('/')
    await router.isReady()
  })

  describe('requiresAuth', () => {
    it('sends an anonymous visitor to /login and remembers where they were going', async () => {
      await router.push('/storage')

      expect(router.currentRoute.value.path).toBe('/login')
      expect(router.currentRoute.value.query).toEqual({ redirect: '/storage' })
    })

    it('preserves the full path, including query and hash, in the redirect', async () => {
      await router.push('/2fa?tab=totp#webauthn')

      expect(router.currentRoute.value.path).toBe('/login')
      expect(router.currentRoute.value.query.redirect).toBe('/2fa?tab=totp#webauthn')
    })

    it('round trips: the redirect the guard writes is accepted verbatim by safeRedirect', async () => {
      for (const target of ['/profile', '/sessions', '/2fa?tab=totp#webauthn', '/identity']) {
        await router.replace('/')
        await router.push(target)

        const redirect = router.currentRoute.value.query.redirect as string
        expect(redirect).toBe(target)
        // This is exactly what LoginView does after a successful sign in.
        expect(safeRedirect(redirect)).toBe(target)
      }
    })

    it('lets an authenticated visitor through without touching /login', async () => {
      signedIn()
      await router.push('/profile')

      expect(router.currentRoute.value.path).toBe('/profile')
      expect(router.currentRoute.value.query.redirect).toBeUndefined()
    })

    it('does not guard public routes', async () => {
      await router.push('/forgot-password')
      expect(router.currentRoute.value.path).toBe('/forgot-password')
    })

    it('awaits auth init before deciding, and admits a session it restores', async () => {
      mockInitialized.value = false
      mockInit.mockImplementation(async () => {
        mockAccessToken.value = 'restored'
        mockInitialized.value = true
      })

      await router.push('/profile')

      expect(mockInit).toHaveBeenCalledOnce()
      expect(router.currentRoute.value.path).toBe('/profile')
    })

    it('redirects to /login when auth init throws instead of leaving the guard hanging', async () => {
      mockInitialized.value = false
      mockInit.mockRejectedValue(new Error('client not initialized'))

      await router.push('/sessions')

      expect(router.currentRoute.value.path).toBe('/login')
      expect(router.currentRoute.value.query.redirect).toBe('/sessions')
    })

    it('does not re-run init when auth is already initialized', async () => {
      signedIn()
      mockInitialized.value = true

      await router.push('/password')

      expect(mockInit).not.toHaveBeenCalled()
      expect(router.currentRoute.value.path).toBe('/password')
    })

    it('still blocks when init resolves without a session', async () => {
      mockInitialized.value = false
      mockInit.mockImplementation(async () => {
        mockInitialized.value = true
      })

      await router.push('/identity')

      expect(mockInit).toHaveBeenCalledOnce()
      expect(router.currentRoute.value.path).toBe('/login')
      expect(router.currentRoute.value.query.redirect).toBe('/identity')
    })
  })

  describe('registration toggle', () => {
    it('allows /register while registration is enabled', async () => {
      await router.push('/register')
      expect(router.currentRoute.value.path).toBe('/register')
    })

    it('blocks /register when registration is disabled', async () => {
      mockRegistrationEnabled.value = false

      await router.push('/register')

      expect(router.currentRoute.value.path).toBe('/login')
    })

    it('does not hand the blocked /register back as a redirect target', async () => {
      mockRegistrationEnabled.value = false

      await router.push('/register')

      expect(router.currentRoute.value.query.redirect).toBeUndefined()
    })

    it('initializes auth before reading the flag', async () => {
      mockInitialized.value = false
      mockInit.mockImplementation(async () => {
        mockRegistrationEnabled.value = false
        mockInitialized.value = true
      })

      await router.push('/register')

      expect(mockInit).toHaveBeenCalledOnce()
      expect(router.currentRoute.value.path).toBe('/login')
    })

    it('asks init for capabilities even when auth is already initialized', async () => {
      // `initialized` flips as soon as the refresh call settles, which says
      // nothing about whether GET /auth/capabilities has answered. Gating the
      // init() call on it reads the optimistic default and lets the visitor
      // through on a server that has registration switched off.
      mockInitialized.value = true
      mockInit.mockImplementation(async () => {
        mockRegistrationEnabled.value = false
      })

      await router.push('/register')

      expect(mockInit).toHaveBeenCalledOnce()
      expect(router.currentRoute.value.path).toBe('/login')
    })

    it('falls through to the route when init fails rather than blocking sign up', async () => {
      mockInitialized.value = false
      mockInit.mockRejectedValue(new Error('offline'))

      await router.push('/register')

      expect(router.currentRoute.value.path).toBe('/register')
    })

    it('evicts a visitor from /register when capabilities land after the guard ran', async () => {
      // The race the guard cannot win on its own: init() resolves on the refresh
      // call while the capabilities fetch is still in flight, so the guard reads
      // the default `true` and admits the visitor. When the real answer arrives
      // they must not be left sitting on a form the server will reject.
      mockInitialized.value = false
      mockInit.mockImplementation(async () => {
        mockInitialized.value = true
      })

      await router.push('/register')
      expect(router.currentRoute.value.path).toBe('/register')

      mockRegistrationEnabled.value = false
      await flushPromises()

      expect(router.currentRoute.value.path).toBe('/login')
    })

    it('does not hand /register back as a redirect target when it evicts', async () => {
      await router.push('/register')

      mockRegistrationEnabled.value = false
      await flushPromises()

      expect(router.currentRoute.value.path).toBe('/login')
      expect(router.currentRoute.value.query.redirect).toBeUndefined()
    })

    it('leaves visitors on other routes alone when the flag turns off', async () => {
      await router.push('/forgot-password')

      mockRegistrationEnabled.value = false
      await flushPromises()

      expect(router.currentRoute.value.path).toBe('/forgot-password')
    })

    it('does not bounce anyone when capabilities confirm registration is open', async () => {
      mockRegistrationEnabled.value = false
      await router.push('/login')

      mockRegistrationEnabled.value = true
      await flushPromises()

      expect(router.currentRoute.value.path).toBe('/login')
    })
  })

  describe('document title', () => {
    it('sets the title from route meta', async () => {
      await router.push('/login')
      expect(document.title).toBe('Sign In — Vault42')
    })

    it('updates the title on every navigation', async () => {
      await router.push('/forgot-password')
      expect(document.title).toBe('Reset Password — Vault42')

      await router.push('/verify-email')
      expect(document.title).toBe('Verify Email — Vault42')
    })

    it('titles the redirect target, not the blocked route', async () => {
      await router.push('/storage')
      expect(document.title).toBe('Sign In — Vault42')
    })

    it('titles the 404 route', async () => {
      await router.push('/no/such/page')
      expect(document.title).toBe('Not Found — Vault42')
    })

    it('falls back to the bare product name for a route that carries no meta title', async () => {
      // Every route in the table sets meta.title today, so this guards the next one
      // that does not: without the fallback the tab reads "undefined — Vault42".
      const remove = router.addRoute({
        path: '/untitled-route',
        name: 'untitled-route',
        component: { template: '<div />' },
      })

      try {
        await router.push('/untitled-route')

        expect(router.currentRoute.value.name).toBe('untitled-route')
        expect(document.title).toBe('Vault42')
      } finally {
        remove()
      }
    })

    it('gives every shipped route a title, so none of them relies on that fallback', async () => {
      signedIn()
      for (const path of ['/', '/login', '/register', '/forgot-password', '/reset-password', '/profile', '/sessions', '/2fa', '/mfa-onboarding', '/password', '/identity', '/storage', '/verify-email', '/oauth/callback', '/no/such/page']) {
        await router.push(path)
        expect(document.title, `${path} has no meta.title`).not.toBe('Vault42')
        expect(document.title).toMatch(/ — Vault42$/)
      }
    })
  })

  describe('catch-all', () => {
    it('resolves an unknown path to the not-found route without redirecting', async () => {
      await router.push('/no/such/page')

      expect(router.currentRoute.value.name).toBe('not-found')
      expect(router.currentRoute.value.path).toBe('/no/such/page')
    })

    it('does not require auth for the 404 route', async () => {
      mockAccessToken.value = null
      await router.push('/no/such/page')

      expect(router.currentRoute.value.name).toBe('not-found')
    })
  })

  describe('route table', () => {
    const ROUTES: Array<[string, string]> = [
      ['/', 'home'],
      ['/login', 'login'],
      ['/register', 'register'],
      ['/forgot-password', 'forgot-password'],
      ['/reset-password', 'reset-password'],
      ['/profile', 'profile'],
      ['/sessions', 'sessions'],
      ['/2fa', '2fa'],
      ['/mfa-onboarding', 'mfa-onboarding'],
      ['/password', 'password'],
      ['/identity', 'identity'],
      ['/storage', 'storage'],
      ['/verify-email', 'verify-email'],
      ['/oauth/callback', 'oauth-callback'],
      ['/no/such/page', 'not-found'],
    ]

    it.each(ROUTES)('serves %s as the %s route with a loadable component', async (path, name) => {
      signedIn()
      await router.push(path)

      expect(router.currentRoute.value.name).toBe(name)
      expect(router.currentRoute.value.matched[0].components?.default).toBeDefined()
    })

    it('scrolls to the top on navigation', () => {
      const scrollBehavior = router.options.scrollBehavior as () => { top: number }
      expect(scrollBehavior()).toEqual({ top: 0 })
    })
  })

  describe('an already authenticated visitor on /login', () => {
    it('is left on /login with the redirect query intact for the view to consume', async () => {
      signedIn()
      await router.push('/login?redirect=/profile')

      expect(router.currentRoute.value.path).toBe('/login')
      expect(router.currentRoute.value.query.redirect).toBe('/profile')
    })

    it('carries a hostile redirect query no further than the query string', async () => {
      signedIn()
      await router.push('/login?redirect=//evil.com')

      expect(router.currentRoute.value.path).toBe('/login')
      // The guard does not act on it; the consuming view must sanitize it.
      expect(safeRedirect(router.currentRoute.value.query.redirect as string)).toBe('/')
    })
  })
})
