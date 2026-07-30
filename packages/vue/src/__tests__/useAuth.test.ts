import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h, nextTick } from 'vue'
import type { VaultClient } from '../client'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

const BASE = 'https://vault42.example.com'

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function errorResponse(error: string, status: number) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function emptyResponse(status = 204) {
  return new Response('', { status })
}

type Handler = Response | Error | (() => Response | Promise<Response>)

/**
 * Routes fetch by pathname. init() fires several requests, so ordering-based
 * mocks would silently pin the wrong response to the wrong endpoint.
 * An unrouted path is a hard failure: a test must know every call it provokes.
 */
function routeFetch(routes: Record<string, Handler>) {
  mockFetch.mockImplementation(async (url: string) => {
    const path = new URL(url).pathname
    const handler = routes[path]
    if (handler === undefined) throw new Error(`unrouted fetch: ${path}`)
    if (handler instanceof Error) throw handler
    if (typeof handler === 'function') return handler()
    return handler.clone()
  })
}

function callsTo(path: string) {
  return mockFetch.mock.calls.filter(([url]) => new URL(url as string).pathname === path)
}

const sampleProfile = {
  id: 'u1',
  email: 'a@b.com',
  email_verified: true,
  display_name: 'Jane',
  avatar_url: '',
  locale: 'en',
  mfa_required: false,
  mfa_enabled: false,
  mfa_methods: [],
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

function b64url(obj: object) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function makeJWT(payload: object, header: object = { alg: 'RS256', typ: 'JWT', kid: 'k1' }) {
  return `${b64url(header)}.${b64url(payload)}.c2ln`
}

type AuthModule = typeof import('../composables/useAuth')
type PluginModule = typeof import('../plugin')

let useAuth: AuthModule['useAuth']
let getAuthState: AuthModule['getAuthState']
let createVaultPlugin: PluginModule['createVaultPlugin']
let useVaultClient: PluginModule['useVaultClient']

/**
 * useAuth keeps its state in module-level refs, so every test needs a virgin
 * module graph or the previous test's token leaks into this one. The plugin is
 * re-imported from the same generation so the injection key symbols match.
 */
beforeEach(async () => {
  mockFetch.mockReset()
  vi.resetModules()
  const auth = await import('../composables/useAuth')
  const plugin = await import('../plugin')
  useAuth = auth.useAuth
  getAuthState = auth.getAuthState
  createVaultPlugin = plugin.createVaultPlugin
  useVaultClient = plugin.useVaultClient
})

afterEach(() => {
  vi.restoreAllMocks()
})

function mountAuth() {
  let composable!: ReturnType<AuthModule['useAuth']>
  let client!: VaultClient

  const TestComponent = defineComponent({
    setup() {
      composable = useAuth()
      client = useVaultClient()
      return () => h('div')
    },
  })

  const wrapper = mount(TestComponent, {
    global: { plugins: [createVaultPlugin({ baseURL: BASE })] },
  })

  return { wrapper, composable, client }
}

/** Asserts the composable holds no credential and no half-finished login. */
function expectLoggedOut(composable: ReturnType<AuthModule['useAuth']>, client: VaultClient) {
  expect(composable.accessToken.value).toBeNull()
  expect(composable.isAuthenticated.value).toBe(false)
  expect(composable.user.value).toBeNull()
  expect(composable.requires2FA.value).toBe(false)
  expect(composable.challengeToken.value).toBeNull()
  expect(composable.availableMethods.value).toEqual([])
  expect(client.accessToken).toBeNull()
}

describe('useAuth', () => {
  it('starts logged out with no credential in any ref', () => {
    const { composable, client } = mountAuth()

    expectLoggedOut(composable, client)
    expect(composable.error.value).toBeNull()
    expect(composable.initialized.value).toBe(false)
    expect(composable.registrationEnabled.value).toBe(true)
    expect(composable.isLoading.value).toBe(false)
    expect(composable.decodedToken.value).toBeNull()
  })

  describe('login', () => {
    it('posts credentials and adopts the returned token and profile', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable, client } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      const [url, init] = callsTo('/auth/login')[0] as [string, RequestInit]
      expect(url).toBe(`${BASE}/auth/login`)
      expect(init.method).toBe('POST')
      expect(init.credentials).toBe('include')
      expect(JSON.parse(init.body as string)).toEqual({
        email: 'a@b.com',
        password: 'correct horse battery staple',
      })
      expect(composable.accessToken.value).toBe('tok1')
      expect(client.accessToken).toBe('tok1')
      expect(composable.isAuthenticated.value).toBe(true)
      expect(composable.user.value).toEqual(sampleProfile)
      expect(composable.error.value).toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('forwards remember_me and sends the token as bearer on the profile call', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple', true)

      expect(JSON.parse((callsTo('/auth/login')[0][1] as RequestInit).body as string).remember_me).toBe(true)
      const profileInit = callsTo('/user/profile')[0][1] as RequestInit
      expect((profileInit.headers as Record<string, string>).Authorization).toBe('Bearer tok1')
    })

    it('rejects on bad credentials and holds no token', async () => {
      routeFetch({ '/auth/login': errorResponse('invalid_credentials', 401) })
      const { composable, client } = mountAuth()

      await expect(composable.login('a@b.com', 'wrong password here')).rejects.toMatchObject({
        code: 'invalid_credentials',
        status: 401,
      })

      expect(composable.error.value!.code).toBe('invalid_credentials')
      expectLoggedOut(composable, client)
      expect(composable.isLoading.value).toBe(false)
      expect(callsTo('/user/profile')).toHaveLength(0)
    })

    it('rejects when the server returns a non-JSON body', async () => {
      routeFetch({ '/auth/login': new Response('<html>502 Bad Gateway</html>', { status: 502 }) })
      const { composable, client } = mountAuth()

      await expect(composable.login('a@b.com', 'correct horse battery staple')).rejects.toMatchObject({
        code: 'unknown_error',
        status: 502,
      })
      expectLoggedOut(composable, client)
    })

    it('rejects when the network throws and leaves loading unwound', async () => {
      routeFetch({ '/auth/login': new TypeError('Failed to fetch') })
      const { composable, client } = mountAuth()

      await expect(composable.login('a@b.com', 'correct horse battery staple')).rejects.toThrow('Failed to fetch')

      expectLoggedOut(composable, client)
      expect(composable.isLoading.value).toBe(false)
    })

    it('rejects when a 200 login body is not JSON', async () => {
      routeFetch({ '/auth/login': new Response('not json at all', { status: 200 }) })
      const { composable, client } = mountAuth()

      await expect(composable.login('a@b.com', 'correct horse battery staple')).rejects.toBeInstanceOf(Error)
      expectLoggedOut(composable, client)
    })

    it('is loading while in flight and not authenticated until it resolves', async () => {
      let release!: (r: Response) => void
      routeFetch({
        '/auth/login': () => new Promise<Response>((r) => { release = r }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      const p = composable.login('a@b.com', 'correct horse battery staple')
      expect(composable.isLoading.value).toBe(true)
      expect(composable.isAuthenticated.value).toBe(false)

      release(jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }))
      await p

      expect(composable.isLoading.value).toBe(false)
    })

    it('keeps the token when the profile fetch fails (profile is non-critical)', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': errorResponse('internal_error', 500),
      })
      const { composable, client } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(composable.accessToken.value).toBe('tok1')
      expect(client.accessToken).toBe('tok1')
      expect(composable.user.value).toBeNull()
      expect(composable.error.value).toBeNull()
    })

    it('clears stale 2FA challenge state when a new login starts', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ requires_2fa: true, challenge_token: 'ch1', available_methods: ['totp'] }),
      })
      const { composable } = mountAuth()
      await composable.login('a@b.com', 'correct horse battery staple')
      expect(composable.challengeToken.value).toBe('ch1')

      routeFetch({ '/auth/login': errorResponse('invalid_credentials', 401) })
      await expect(composable.login('c@d.com', 'another password here')).rejects.toBeTruthy()

      expect(composable.requires2FA.value).toBe(false)
      expect(composable.challengeToken.value).toBeNull()
      expect(composable.availableMethods.value).toEqual([])
    })
  })

  describe('login — MFA required branch', () => {
    it('hands off to 2FA without authenticating or fetching the profile', async () => {
      routeFetch({
        '/auth/login': jsonResponse({
          requires_2fa: true,
          challenge_token: 'ch1',
          available_methods: ['totp', 'webauthn'],
        }),
      })
      const { composable } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(composable.requires2FA.value).toBe(true)
      expect(composable.challengeToken.value).toBe('ch1')
      expect(composable.availableMethods.value).toEqual(['totp', 'webauthn'])
      expect(composable.accessToken.value).toBeNull()
      expect(composable.isAuthenticated.value).toBe(false)
      expect(composable.user.value).toBeNull()
      expect(callsTo('/user/profile')).toHaveLength(0)
      expect(composable.isLoading.value).toBe(false)
    })

    it('normalises a challenge that omits challenge_token and available_methods', async () => {
      routeFetch({ '/auth/login': jsonResponse({ requires_2fa: true }) })
      const { composable } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(composable.requires2FA.value).toBe(true)
      expect(composable.challengeToken.value).toBeNull()
      expect(composable.availableMethods.value).toEqual([])
      expect(composable.isAuthenticated.value).toBe(false)
    })

    it('disarms an access_token smuggled into the 2FA challenge', async () => {
      // A malicious or broken server answers the password step with BOTH
      // requires_2fa and a usable access_token. VaultClient.login() stores any
      // access_token it sees, so the 2FA branch has to null it: otherwise the
      // second factor is never presented and every later request still carries
      // a working bearer.
      routeFetch({
        '/auth/login': jsonResponse({
          requires_2fa: true,
          challenge_token: 'ch1',
          available_methods: ['totp'],
          access_token: 'mfa-bypass-token',
          token_type: 'Bearer',
          expires_in: 900,
        }),
        '/auth/capabilities': jsonResponse({ registration_enabled: true, mfa_required: true, oauth_providers: [] }),
      })
      const { composable, client } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(composable.requires2FA.value).toBe(true)
      expect(composable.challengeToken.value).toBe('ch1')
      expect(composable.isAuthenticated.value).toBe(false)
      expect(composable.accessToken.value).toBeNull()
      expect(client.accessToken).toBeNull()

      // The bearer is gone from the wire, not just from the refs.
      await client.getCapabilities()
      const headers = (callsTo('/auth/capabilities')[0][1] as RequestInit).headers as Record<string, string>
      expect(headers.Authorization).toBeUndefined()
    })
  })

  describe('register', () => {
    it('posts the registration and grants no session', async () => {
      routeFetch({ '/auth/register': jsonResponse({ user_id: 'u1', email: 'a@b.com' }) })
      const { composable, client } = mountAuth()

      await composable.register('a@b.com', 'correct horse battery staple', 'Jane')

      const init = callsTo('/auth/register')[0][1] as RequestInit
      expect(init.method).toBe('POST')
      expect(JSON.parse(init.body as string)).toEqual({
        email: 'a@b.com',
        password: 'correct horse battery staple',
        display_name: 'Jane',
      })
      expectLoggedOut(composable, client)
    })

    it('rejects and records the error when registration is disabled', async () => {
      routeFetch({ '/auth/register': errorResponse('registration_disabled', 403) })
      const { composable, client } = mountAuth()

      await expect(composable.register('a@b.com', 'correct horse battery staple')).rejects.toMatchObject({
        code: 'registration_disabled',
        status: 403,
      })
      expect(composable.error.value!.code).toBe('registration_disabled')
      expect(composable.isLoading.value).toBe(false)
      expectLoggedOut(composable, client)
    })
  })

  describe('logout', () => {
    async function loginThenRoute(routes: Record<string, Handler>) {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const mounted = mountAuth()
      await mounted.composable.login('a@b.com', 'correct horse battery staple')
      mounted.composable.requires2FA.value = true
      mounted.composable.challengeToken.value = 'ch-left-over'
      mounted.composable.availableMethods.value = ['totp']
      mounted.composable.initialized.value = true
      routeFetch(routes)
      return mounted
    }

    it('clears every reactive ref and the client token', async () => {
      const { composable, client } = await loginThenRoute({ '/auth/logout': emptyResponse() })

      await composable.logout()

      expect(composable.accessToken.value).toBeNull()
      expect(client.accessToken).toBeNull()
      expect(composable.user.value).toBeNull()
      expect(composable.requires2FA.value).toBe(false)
      expect(composable.challengeToken.value).toBeNull()
      expect(composable.availableMethods.value).toEqual([])
      expect(composable.initialized.value).toBe(false)
      expect(composable.error.value).toBeNull()
      expect(composable.isAuthenticated.value).toBe(false)
      expect(composable.isLoading.value).toBe(false)
      expect(composable.decodedToken.value).toBeNull()
      expect((callsTo('/auth/logout')[0][1] as RequestInit).method).toBe('POST')
    })

    it('clears local state even when the server rejects the logout', async () => {
      const { composable, client } = await loginThenRoute({ '/auth/logout': errorResponse('internal_error', 500) })
      expect(composable.accessToken.value).toBe('tok1')

      await expect(composable.logout()).resolves.toBeUndefined()

      expect(composable.challengeToken.value).toBeNull()
      expect(composable.requires2FA.value).toBe(false)
      expect(composable.accessToken.value).toBeNull()
      expect(client.accessToken).toBeNull()
      expect(composable.user.value).toBeNull()
      expect(composable.isAuthenticated.value).toBe(false)
    })

    it('clears local state even when the network is down', async () => {
      const { composable, client } = await loginThenRoute({ '/auth/logout': new TypeError('Failed to fetch') })
      expect(composable.accessToken.value).toBe('tok1')

      await composable.logout()

      expect(composable.challengeToken.value).toBeNull()
      expect(composable.accessToken.value).toBeNull()
      expect(client.accessToken).toBeNull()
      expect(composable.user.value).toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('releases the init latch so a later init() re-checks the session', async () => {
      const { composable } = await loginThenRoute({ '/auth/logout': emptyResponse() })
      await composable.logout()

      routeFetch({
        '/auth/capabilities': jsonResponse({ registration_enabled: true, mfa_required: false, oauth_providers: [] }),
        '/auth/refresh': errorResponse('invalid_refresh_token', 401),
      })
      await composable.init()

      expect(callsTo('/auth/refresh')).toHaveLength(1)
      expect(composable.initialized.value).toBe(true)
      expect(composable.isAuthenticated.value).toBe(false)
    })
  })

  describe('refresh', () => {
    it('adopts the rotated token', async () => {
      routeFetch({ '/auth/refresh': jsonResponse({ access_token: 'tok2', token_type: 'Bearer', expires_in: 900 }) })
      const { composable, client } = mountAuth()

      await composable.refresh()

      expect(composable.accessToken.value).toBe('tok2')
      expect(client.accessToken).toBe('tok2')
      expect((callsTo('/auth/refresh')[0][1] as RequestInit).credentials).toBe('include')
    })

    it('drops the session without throwing when the refresh is rejected', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable, client } = mountAuth()
      await composable.login('a@b.com', 'correct horse battery staple')

      routeFetch({ '/auth/refresh': errorResponse('refresh_token_reused', 401) })
      await expect(composable.refresh()).resolves.toBeUndefined()

      expect(composable.accessToken.value).toBeNull()
      expect(client.accessToken).toBeNull()
      expect(composable.user.value).toBeNull()
      expect(composable.isAuthenticated.value).toBe(false)
      expect(composable.error.value!.code).toBe('refresh_token_reused')
    })
  })

  describe('init', () => {
    const caps = { registration_enabled: true, mfa_required: false, oauth_providers: ['github'] }

    it('restores a live session on a cold start', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable, client } = mountAuth()

      await composable.init()

      expect(composable.accessToken.value).toBe('tok1')
      expect(client.accessToken).toBe('tok1')
      expect(composable.user.value).toEqual(sampleProfile)
      expect(composable.isAuthenticated.value).toBe(true)
      expect(composable.initialized.value).toBe(true)
      expect(composable.isLoading.value).toBe(false)
      expect((callsTo('/auth/refresh')[0][1] as RequestInit).method).toBe('POST')
    })

    it('finishes logged out when there is no session', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': errorResponse('invalid_refresh_token', 401),
      })
      const { composable, client } = mountAuth()

      await expect(composable.init()).resolves.toBeUndefined()

      expectLoggedOut(composable, client)
      expect(composable.initialized.value).toBe(true)
      expect(composable.isLoading.value).toBe(false)
      expect(callsTo('/user/profile')).toHaveLength(0)
    })

    it('finishes logged out when the refresh call throws', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': new TypeError('Failed to fetch'),
      })
      const { composable, client } = mountAuth()

      await composable.init()

      expectLoggedOut(composable, client)
      expect(composable.initialized.value).toBe(true)
    })

    it('finishes logged out when the refresh body is not JSON', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': new Response('<html>proxy error</html>', { status: 200 }),
      })
      const { composable, client } = mountAuth()

      await composable.init()

      expectLoggedOut(composable, client)
      expect(composable.initialized.value).toBe(true)
    })

    it('is a no-op once initialized', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': errorResponse('invalid_refresh_token', 401),
      })
      const { composable } = mountAuth()
      await composable.init()
      const callCount = mockFetch.mock.calls.length
      expect(callCount).toBeGreaterThan(0)
      expect(composable.initialized.value).toBe(true)

      await composable.init()

      expect(mockFetch.mock.calls.length).toBe(callCount)
    })

    it('does not double-fetch when two init() calls race', async () => {
      let release!: (r: Response) => void
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': () => new Promise<Response>((r) => { release = r }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      const a = composable.init()
      const b = composable.init()

      release(jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }))
      await Promise.all([a, b])

      expect(callsTo('/auth/refresh')).toHaveLength(1)
      expect(callsTo('/auth/capabilities')).toHaveLength(1)
      expect(callsTo('/user/profile')).toHaveLength(1)
      expect(composable.isLoading.value).toBe(false)
    })

    it('does not double-fetch when useAuth().init() races getAuthState().init()', async () => {
      let release!: (r: Response) => void
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': () => new Promise<Response>((r) => { release = r }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      const a = composable.init()
      const b = getAuthState().init()

      release(jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }))
      await Promise.all([a, b])

      expect(callsTo('/auth/refresh')).toHaveLength(1)
      expect(callsTo('/auth/capabilities')).toHaveLength(1)
    })

    it('finishes logged out when the session expires during the profile fetch', async () => {
      // refresh() succeeds, then getProfile() 401s and the client's own retry
      // refresh fails, so VaultClient nulls its token and throws session_expired.
      // That is not a "non-critical" profile failure: keeping the ref would
      // render the app as signed in while every request goes out anonymous.
      let refreshCalls = 0
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': () => {
          refreshCalls++
          return refreshCalls === 1
            ? jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 })
            : errorResponse('refresh_token_reused', 401)
        },
        '/user/profile': errorResponse('token_expired', 401),
      })
      const { composable, client } = mountAuth()

      await composable.init()

      expect(client.accessToken).toBeNull()
      expect(composable.accessToken.value).toBeNull()
      expect(composable.isAuthenticated.value).toBe(false)
      expect(composable.user.value).toBeNull()
      expect(composable.initialized.value).toBe(true)
      expect(composable.error.value!.code).toBe('session_expired')
      expect(composable.isLoading.value).toBe(false)
    })

    it('keeps the session when the profile call fails without expiring it', async () => {
      // The client still holds the token, so this really is non-critical.
      routeFetch({
        '/auth/capabilities': jsonResponse(caps),
        '/auth/refresh': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': errorResponse('internal_error', 500),
      })
      const { composable, client } = mountAuth()

      await composable.init()

      expect(composable.accessToken.value).toBe('tok1')
      expect(client.accessToken).toBe('tok1')
      expect(composable.isAuthenticated.value).toBe(true)
      expect(composable.user.value).toBeNull()
      expect(composable.error.value).toBeNull()
    })
  })

  describe('capabilities', () => {
    it('turns registration off when the server disables it', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse({ registration_enabled: false, mfa_required: true, oauth_providers: [] }),
        '/auth/refresh': errorResponse('invalid_refresh_token', 401),
      })
      const { composable } = mountAuth()

      await composable.init()
      await nextTick()

      expect(composable.registrationEnabled.value).toBe(false)
      const init = callsTo('/auth/capabilities')[0][1] as RequestInit
      expect(init.method).toBe('GET')
      expect((init.headers as Record<string, string>).Authorization).toBeUndefined()
    })

    it('leaves registration enabled and init successful when capabilities fail', async () => {
      routeFetch({
        '/auth/capabilities': errorResponse('internal_error', 500),
        '/auth/refresh': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      await expect(composable.init()).resolves.toBeUndefined()
      await nextTick()

      expect(composable.registrationEnabled.value).toBe(true)
      expect(composable.isAuthenticated.value).toBe(true)
    })

    it('does not resolve until capabilities have settled', async () => {
      // A route guard reads registrationEnabled the moment `await init()`
      // returns, so init() must not resolve while the capabilities call is
      // still in flight or the guard decides on the default.
      let releaseCaps!: (r: Response) => void
      routeFetch({
        '/auth/capabilities': () => new Promise<Response>((r) => { releaseCaps = r }),
        '/auth/refresh': errorResponse('invalid_refresh_token', 401),
      })
      const { composable } = mountAuth()

      let settled = false
      const pending = composable.init().then(() => { settled = true })
      await new Promise((r) => setTimeout(r, 0))
      expect(settled).toBe(false)
      expect(composable.initialized.value).toBe(false)

      releaseCaps(jsonResponse({ registration_enabled: false, mfa_required: false, oauth_providers: [] }))
      await pending

      expect(settled).toBe(true)
      expect(composable.initialized.value).toBe(true)
      expect(composable.registrationEnabled.value).toBe(false)
      expect(composable.isLoading.value).toBe(false)
    })
  })

  describe('getAuthState', () => {
    it('throws a named error before useAuth() has run', async () => {
      await expect(getAuthState().init()).rejects.toThrow(
        '[@vault42/vue] Auth not initialized. Call useAuth() from a component first.',
      )
    })

    it('exposes the same refs as useAuth, not copies', () => {
      const { composable } = mountAuth()
      const state = getAuthState()

      expect(state.user).toBe(composable.user)
      expect(state.initialized).toBe(composable.initialized)
      expect(state.registrationEnabled).toBe(composable.registrationEnabled)
      expect(state.isLoading).toBe(composable.isLoading)
    })

    it('sees a login performed through useAuth', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()
      const state = getAuthState()
      expect(state.isAuthenticated.value).toBe(false)

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(state.isAuthenticated.value).toBe(true)
      expect(state.user.value).toEqual(sampleProfile)
    })

    it('is restored to logged-out defaults by logout', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse({ registration_enabled: true, mfa_required: false, oauth_providers: [] }),
        '/auth/refresh': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
        '/auth/logout': emptyResponse(),
      })
      const { composable } = mountAuth()
      await composable.init()
      const state = getAuthState()
      expect(state.isAuthenticated.value).toBe(true)
      expect(state.initialized.value).toBe(true)

      await composable.logout()

      expect(state.isAuthenticated.value).toBe(false)
      expect(state.user.value).toBeNull()
      expect(state.initialized.value).toBe(false)

      await state.init()
      expect(callsTo('/auth/refresh')).toHaveLength(2)
      expect(state.isAuthenticated.value).toBe(true)
    })

    it('restores a session through its own init()', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse({ registration_enabled: true, mfa_required: false, oauth_providers: [] }),
        '/auth/refresh': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      const state = getAuthState()
      await state.init()

      expect(state.isAuthenticated.value).toBe(true)
      expect(composable.accessToken.value).toBe('tok1')
      expect(state.initialized.value).toBe(true)
    })

    it('finishes logged out through its own init() when there is no session', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse({ registration_enabled: true, mfa_required: false, oauth_providers: [] }),
        '/auth/refresh': errorResponse('invalid_refresh_token', 401),
      })
      const { composable, client } = mountAuth()

      const state = getAuthState()
      await state.init()

      expect(state.isAuthenticated.value).toBe(false)
      expectLoggedOut(composable, client)
      expect(state.initialized.value).toBe(true)
      expect(state.isLoading.value).toBe(false)
    })

    it('short-circuits its own init() once initialized instead of re-refreshing', async () => {
      routeFetch({
        '/auth/capabilities': jsonResponse({ registration_enabled: true, mfa_required: false, oauth_providers: [] }),
        '/auth/refresh': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()
      await composable.init()
      expect(callsTo('/auth/refresh')).toHaveLength(1)

      const state = getAuthState()
      await state.init()
      await state.init()

      expect(callsTo('/auth/refresh')).toHaveLength(1)
      expect(state.isAuthenticated.value).toBe(true)
      expect(state.isLoading.value).toBe(false)
    })

    it('still restores the session through its own init() when the capabilities probe fails', async () => {
      routeFetch({
        '/auth/capabilities': new Error('offline'),
        '/auth/refresh': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable, client } = mountAuth()

      const state = getAuthState()
      await state.init()
      await new Promise((r) => setTimeout(r, 0))

      expect(state.isAuthenticated.value).toBe(true)
      expect(composable.accessToken.value).toBe('tok1')
      expect(client.accessToken).toBe('tok1')
      expect(state.registrationEnabled.value).toBe(true)
      expect(state.initialized.value).toBe(true)
      expect(state.isLoading.value).toBe(false)
    })
  })

  describe('2FA verification', () => {
    async function challenged() {
      routeFetch({
        '/auth/login': jsonResponse({ requires_2fa: true, challenge_token: 'ch1', available_methods: ['totp'] }),
      })
      const mounted = mountAuth()
      await mounted.composable.login('a@b.com', 'correct horse battery staple')
      return mounted
    }

    it('sends the challenge token as bearer and swaps in the real token', async () => {
      const { composable, client } = await challenged()
      routeFetch({
        '/auth/2fa/totp/verify': jsonResponse({ access_token: 'tok-full', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })

      await composable.verify2FA('123456')

      const [url, init] = callsTo('/auth/2fa/totp/verify')[0] as [string, RequestInit]
      expect(url).toBe(`${BASE}/auth/2fa/totp/verify`)
      expect((init.headers as Record<string, string>).Authorization).toBe('Bearer ch1')
      expect(JSON.parse(init.body as string)).toEqual({ code: '123456' })
      expect(composable.accessToken.value).toBe('tok-full')
      expect(client.accessToken).toBe('tok-full')
      expect(composable.requires2FA.value).toBe(false)
      expect(composable.challengeToken.value).toBeNull()
      expect(composable.availableMethods.value).toEqual([])
      expect(composable.user.value).toEqual(sampleProfile)
    })

    it('keeps the user on the 2FA step when the code is wrong', async () => {
      const { composable } = await challenged()
      routeFetch({ '/auth/2fa/totp/verify': errorResponse('invalid_code', 401) })

      await expect(composable.verify2FA('000000')).rejects.toMatchObject({ code: 'invalid_code' })

      expect(composable.error.value!.code).toBe('invalid_code')
      expect(composable.isAuthenticated.value).toBe(false)
      expect(composable.accessToken.value).toBeNull()
      expect(composable.requires2FA.value).toBe(true)
      expect(composable.challengeToken.value).toBe('ch1')
      expect(composable.isLoading.value).toBe(false)
    })

    it('keeps the 2FA gate up when the verify answers 200 with no access_token', async () => {
      // Dismissing the 2FA screen with nobody signed in, while the client keeps
      // the challenge token as its standing bearer, is the worst of both. The
      // challenge state survives for a retry and the bearer is dropped.
      const { composable, client } = await challenged()
      routeFetch({ '/auth/2fa/totp/verify': jsonResponse({}) })

      await expect(composable.verify2FA('123456')).rejects.toMatchObject({ code: 'mfa_incomplete' })

      expect(composable.requires2FA.value).toBe(true)
      expect(composable.challengeToken.value).toBe('ch1')
      expect(composable.availableMethods.value).toEqual(['totp'])
      expect(composable.accessToken.value).toBeNull()
      expect(composable.isAuthenticated.value).toBe(false)
      expect(client.accessToken).toBeNull()
      expect(composable.error.value!.code).toBe('mfa_incomplete')
      expect(callsTo('/user/profile')).toHaveLength(0)
      expect(composable.isLoading.value).toBe(false)
    })

    it('re-arms the challenge bearer on a retry after a failed verify', async () => {
      const { composable, client } = await challenged()
      routeFetch({ '/auth/2fa/totp/verify': jsonResponse({}) })
      await expect(composable.verify2FA('123456')).rejects.toBeTruthy()
      expect(client.accessToken).toBeNull()

      routeFetch({
        '/auth/2fa/totp/verify': jsonResponse({ access_token: 'tok-full', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      await composable.verify2FA('654321')

      const retryInit = callsTo('/auth/2fa/totp/verify')[1][1] as RequestInit
      expect((retryInit.headers as Record<string, string>).Authorization).toBe('Bearer ch1')
      expect(composable.isAuthenticated.value).toBe(true)
      expect(client.accessToken).toBe('tok-full')
    })

    it('drops the challenge bearer when the flow is abandoned', async () => {
      // A failed verify deliberately leaves the challenge token on the client
      // for a retry, so walking away needs an explicit exit or it stays armed.
      const { composable, client } = await challenged()
      routeFetch({ '/auth/2fa/totp/verify': errorResponse('invalid_code', 401) })
      await expect(composable.verify2FA('000000')).rejects.toBeTruthy()
      expect(client.accessToken).toBe('ch1')

      composable.cancel2FA()

      expect(composable.requires2FA.value).toBe(false)
      expect(composable.challengeToken.value).toBeNull()
      expect(composable.availableMethods.value).toEqual([])
      expect(composable.error.value).toBeNull()
      expect(composable.isAuthenticated.value).toBe(false)
      expect(client.accessToken).toBeNull()
    })

    it('leaves a real session alone when a re-auth challenge is abandoned', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable, client } = mountAuth()
      await composable.login('a@b.com', 'correct horse battery staple')
      composable.requires2FA.value = true
      composable.challengeToken.value = 'ch-reauth'

      composable.cancel2FA()

      expect(composable.accessToken.value).toBe('tok1')
      expect(client.accessToken).toBe('tok1')
      expect(composable.requires2FA.value).toBe(false)
    })

    it('verifies with no bearer when there is no challenge token to send', async () => {
      // Some deployments track the challenge server-side, so the verify goes
      // out unauthenticated and must still be able to complete the login.
      routeFetch({
        '/auth/2fa/totp/verify': jsonResponse({ access_token: 'tok-full', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable, client } = mountAuth()
      expect(composable.challengeToken.value).toBeNull()

      await composable.verify2FA('123456')

      const init = callsTo('/auth/2fa/totp/verify')[0][1] as RequestInit
      expect((init.headers as Record<string, string>).Authorization).toBeUndefined()
      expect(composable.accessToken.value).toBe('tok-full')
      expect(client.accessToken).toBe('tok-full')
      expect(composable.user.value).toEqual(sampleProfile)
    })

    it('verifies a backup code against its own endpoint', async () => {
      const { composable } = await challenged()
      routeFetch({
        '/auth/2fa/backup-code/verify': jsonResponse({ access_token: 'tok-full', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })

      await composable.verify2FABackupCode('abcd-efgh')

      const init = callsTo('/auth/2fa/backup-code/verify')[0][1] as RequestInit
      expect(JSON.parse(init.body as string)).toEqual({ code: 'abcd-efgh' })
      expect(composable.isAuthenticated.value).toBe(true)
    })

    it('verifies an email OTP against its own endpoint', async () => {
      const { composable } = await challenged()
      routeFetch({
        '/auth/2fa/email-otp/verify': jsonResponse({ access_token: 'tok-full', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })

      await composable.verify2FAEmailOTP('998877')

      const init = callsTo('/auth/2fa/email-otp/verify')[0][1] as RequestInit
      expect(JSON.parse(init.body as string)).toEqual({ code: '998877' })
      expect(composable.accessToken.value).toBe('tok-full')
    })

    it('adopts the token useWebAuthn already put on the client', async () => {
      const { composable, client } = await challenged()
      client.accessToken = 'tok-webauthn'
      routeFetch({ '/user/profile': jsonResponse(sampleProfile) })

      await composable.verify2FAWebAuthn()

      expect(composable.accessToken.value).toBe('tok-webauthn')
      expect(composable.requires2FA.value).toBe(false)
      expect(composable.challengeToken.value).toBeNull()
      expect(composable.user.value).toEqual(sampleProfile)
    })

    it('keeps the 2FA gate up when verify2FAWebAuthn finds no token', async () => {
      // The function trusts that useWebAuthn().verify() already succeeded. If
      // it did not, client.accessToken is still null and nothing was proven.
      const { composable, client } = await challenged()
      expect(composable.requires2FA.value).toBe(true)
      expect(client.accessToken).toBeNull()

      await expect(composable.verify2FAWebAuthn()).rejects.toMatchObject({ code: 'mfa_incomplete' })

      expect(composable.accessToken.value).toBeNull()
      expect(composable.isAuthenticated.value).toBe(false)
      expect(composable.requires2FA.value).toBe(true)
      expect(composable.challengeToken.value).toBe('ch1')
      expect(composable.availableMethods.value).toEqual(['totp'])
      expect(client.accessToken).toBeNull()
      expect(callsTo('/user/profile')).toHaveLength(0)
      expect(composable.isLoading.value).toBe(false)
    })

    it('keeps the 2FA gate up when the WebAuthn finish left the challenge token in place', async () => {
      // useWebAuthn().verify() only overwrites the bearer when the finish call
      // returned an access_token, so the challenge token still being the
      // bearer means the assertion produced no session.
      const { composable, client } = await challenged()
      client.accessToken = 'ch1'

      await expect(composable.verify2FAWebAuthn()).rejects.toMatchObject({ code: 'mfa_incomplete' })

      expect(composable.accessToken.value).toBeNull()
      expect(composable.requires2FA.value).toBe(true)
      expect(composable.challengeToken.value).toBe('ch1')
      expect(client.accessToken).toBeNull()
      expect(callsTo('/user/profile')).toHaveLength(0)
    })
  })

  describe('token introspection', () => {
    it('decodes a base64url JWT into header and payload', async () => {
      const exp = Math.floor(Date.now() / 1000) + 600
      const token = makeJWT({ sub: 'u1', exp }, { alg: 'RS256', typ: 'JWT', kid: 'k1' })
      routeFetch({
        '/auth/login': jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(composable.decodedToken.value!.header).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'k1' })
      expect(composable.decodedToken.value!.payload).toEqual({ sub: 'u1', exp })
      expect(composable.tokenExpiresIn.value).toBeGreaterThan(590)
      expect(composable.tokenExpiresIn.value).toBeLessThanOrEqual(600)
      expect(composable.isTokenExpired.value).toBe(false)
    })

    it('reports an expired token as expired with zero remaining', async () => {
      const token = makeJWT({ sub: 'u1', exp: Math.floor(Date.now() / 1000) - 60 })
      routeFetch({
        '/auth/login': jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(composable.accessToken.value).toBe(token)
      expect(composable.decodedToken.value!.payload.sub).toBe('u1')
      expect(composable.tokenExpiresIn.value).toBe(0)
      expect(composable.isTokenExpired.value).toBe(true)
    })

    it('returns null for a token that is not a well-formed JWT', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'not-a-jwt', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      // The opaque token is adopted and used, it just cannot be introspected.
      expect(composable.accessToken.value).toBe('not-a-jwt')
      expect(composable.isAuthenticated.value).toBe(true)
      expect(composable.decodedToken.value).toBeNull()
      expect(composable.tokenExpiresIn.value).toBe(0)
      expect(composable.isTokenExpired.value).toBe(true)
    })

    it('returns null when the JWT segments are not valid base64 JSON', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: '!!!.???.sig', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(composable.accessToken.value).toBe('!!!.???.sig')
      expect(composable.decodedToken.value).toBeNull()
    })

    it('treats a token without exp as expired', async () => {
      const token = makeJWT({ sub: 'u1' })
      routeFetch({
        '/auth/login': jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()

      await composable.login('a@b.com', 'correct horse battery staple')

      expect(composable.decodedToken.value).not.toBeNull()
      expect(composable.tokenExpiresIn.value).toBe(0)
      expect(composable.isTokenExpired.value).toBe(true)
    })
  })

  describe('cross-tab logout', () => {
    it('drops the session when another tab broadcasts a logout', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable, client } = mountAuth()
      await composable.login('a@b.com', 'correct horse battery staple')
      composable.initialized.value = true
      expect(composable.accessToken.value).toBe('tok1')
      expect(client.accessToken).toBe('tok1')
      expect(composable.user.value).toEqual(sampleProfile)

      const other = new BroadcastChannel('vault42-auth')
      other.postMessage({ type: 'logout' })
      await new Promise((r) => setTimeout(r, 10))
      other.close()

      expect(composable.accessToken.value).toBeNull()
      expect(client.accessToken).toBeNull()
      expect(composable.user.value).toBeNull()
      expect(composable.initialized.value).toBe(false)
      expect(composable.isAuthenticated.value).toBe(false)
    })

    it('ignores broadcast messages that are not a logout', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { composable } = mountAuth()
      await composable.login('a@b.com', 'correct horse battery staple')

      const other = new BroadcastChannel('vault42-auth')
      other.postMessage({ type: 'login' })
      await new Promise((r) => setTimeout(r, 10))
      other.close()

      expect(composable.accessToken.value).toBe('tok1')
      expect(composable.isAuthenticated.value).toBe(true)
    })

    it('stops listening after the component unmounts', async () => {
      routeFetch({
        '/auth/login': jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }),
        '/user/profile': jsonResponse(sampleProfile),
      })
      const { wrapper, composable } = mountAuth()
      await composable.login('a@b.com', 'correct horse battery staple')

      wrapper.unmount()

      const other = new BroadcastChannel('vault42-auth')
      other.postMessage({ type: 'logout' })
      await new Promise((r) => setTimeout(r, 10))
      other.close()

      expect(composable.accessToken.value).toBe('tok1')
    })
  })
})
