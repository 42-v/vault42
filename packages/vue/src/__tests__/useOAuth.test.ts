import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { useOAuth } from '../composables/useOAuth'
import { createVaultPlugin, useVaultClient } from '../plugin'
import type { VaultClient } from '../client'
import type { OAuthProvider } from '../types'

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

function mountComposable() {
  let composable!: ReturnType<typeof useOAuth>
  let client!: VaultClient

  const TestComponent = defineComponent({
    setup() {
      composable = useOAuth()
      client = useVaultClient()
      return () => h('div')
    },
  })

  const plugin = createVaultPlugin({ baseURL: BASE })
  const wrapper = mount(TestComponent, {
    global: { plugins: [plugin] },
  })

  return { wrapper, composable, client }
}

/** Replace window.location with a plain object so href assignment is observable. */
let realLocation: Location
function stubLocation(): { href: string } {
  const fake = { href: '' }
  Object.defineProperty(window, 'location', { value: fake, writable: true, configurable: true })
  return fake
}

describe('useOAuth', () => {
  beforeEach(() => {
    mockFetch.mockReset()
    realLocation = window.location
  })

  afterEach(() => {
    Object.defineProperty(window, 'location', { value: realLocation, writable: true, configurable: true })
    vi.restoreAllMocks()
  })

  describe('authorize', () => {
    it('navigates to the server-side authorize endpoint for the provider', () => {
      const location = stubLocation()
      const { composable } = mountComposable()

      composable.authorize('github')

      expect(location.href).toBe(`${BASE}/auth/oauth2/authorize?provider=github`)
    })

    it('never mints client-side PKCE or state parameters', () => {
      // PKCE S256 + the signed state nonce are generated and verified server-side
      // (GET /auth/oauth2/authorize). A client that started emitting its own
      // code_challenge would be able to negotiate method=plain, which the project
      // forbids on every OAuth2 flow. Pin that the SDK contributes nothing here.
      const location = stubLocation()
      const { composable } = mountComposable()

      composable.authorize('google')

      const url = new URL(location.href)
      expect(url.origin + url.pathname).toBe(`${BASE}/auth/oauth2/authorize`)
      expect([...url.searchParams.keys()]).toEqual(['provider'])
      expect(url.searchParams.get('code_challenge')).toBeNull()
      expect(url.searchParams.get('code_challenge_method')).toBeNull()
      expect(url.searchParams.get('state')).toBeNull()
      expect(url.searchParams.get('redirect_uri')).toBeNull()
    })

    it('hands the flow to the browser rather than fetching the authorize endpoint', () => {
      // The authorize step must be a top-level navigation: an XHR/fetch would
      // never carry the user to the provider and would strip the redirect.
      const location = stubLocation()
      const { composable } = mountComposable()

      composable.authorize('facebook')

      expect(location.href).toBe(`${BASE}/auth/oauth2/authorize?provider=facebook`)
      expect(mockFetch).not.toHaveBeenCalled()
    })

    it('interpolates the provider into the query string without encoding it', () => {
      // DEFECT (reported): client.getOAuthAuthorizeURL builds the URL by string
      // concatenation, so a provider value that is not one of the three union
      // members smuggles extra query parameters into the authorize request.
      const location = stubLocation()
      const { composable } = mountComposable()

      composable.authorize('github&redirect_uri=https://evil.example' as OAuthProvider)

      const params = new URL(location.href).searchParams
      expect(params.get('provider')).toBe('github')
      expect(params.get('redirect_uri')).toBe('https://evil.example')
    })
  })

  describe('parseCallback', () => {
    it('returns null for an empty fragment', () => {
      const { composable } = mountComposable()
      expect(composable.parseCallback('')).toBeNull()
    })

    it('returns null for a bare hash', () => {
      const { composable } = mountComposable()
      expect(composable.parseCallback('#')).toBeNull()
    })

    it('returns null for an ordinary SPA route fragment', () => {
      const { composable } = mountComposable()
      expect(composable.parseCallback('#/dashboard/settings')).toBeNull()
    })

    it('parses the success fragment into a code', () => {
      const { composable } = mountComposable()
      expect(composable.parseCallback('#code=9f8e7d6c')).toEqual({ code: '9f8e7d6c' })
    })

    it('parses the 2FA continuation fragment', () => {
      const { composable } = mountComposable()
      expect(composable.parseCallback('#requires_2fa=true&challenge_token=ch-1')).toEqual({
        requires_2fa: true,
        challenge_token: 'ch-1',
      })
    })

    it('parses a provider denial fragment without a code', () => {
      const { composable } = mountComposable()
      const result = composable.parseCallback('#error=access_denied')

      expect(result).toEqual({ error: 'access_denied' })
      expect(result!.code).toBeUndefined()
    })

    it('returns only the four known fields, dropping attacker-supplied extras', () => {
      const { composable } = mountComposable()
      const result = composable.parseCallback(
        '#code=good&access_token=injected&refresh_token=injected&admin=true&scope=all',
      )

      expect(Object.keys(result!)).toEqual(['code'])
      expect(result).toEqual({ code: 'good' })
    })

    it('takes the first value when a key is duplicated', () => {
      // Fragment parameter pollution: an attacker appending a second code must
      // not be able to override the one the server minted.
      const { composable } = mountComposable()
      expect(composable.parseCallback('#code=server-minted&code=attacker')).toEqual({
        code: 'server-minted',
      })
    })

    it('percent-decodes values', () => {
      const { composable } = mountComposable()
      expect(composable.parseCallback('#challenge_token=a%2Bb%2Fc%3D')).toEqual({
        challenge_token: 'a+b/c=',
      })
    })

    it('treats requires_2fa as true only for the exact string "true"', () => {
      // DEFECT (reported): any other truthy encoding degrades to false, so a
      // fragment carrying a challenge_token but requires_2fa=1 is reported as a
      // completed sign-in with no code — the caller falls through to
      // exchangeCode(undefined) rather than into the 2FA step.
      const { composable } = mountComposable()
      expect(composable.parseCallback('#requires_2fa=1&challenge_token=ch-1')).toEqual({
        requires_2fa: false,
        challenge_token: 'ch-1',
      })
    })

    it('returns both code and error when the fragment carries the two together', () => {
      // DEFECT (reported): the parse does not fail closed on a contradictory
      // fragment. A caller that checks `code` first signs in on a fragment that
      // also says the provider denied the request.
      const { composable } = mountComposable()
      expect(composable.parseCallback('#error=access_denied&code=attacker-supplied')).toEqual({
        error: 'access_denied',
        code: 'attacker-supplied',
      })
    })

    it('discards the first character, so a fragment without the leading hash is lost', () => {
      // DEFECT (reported): the function unconditionally does hash.substring(1).
      // Passing location.hash.slice(1) — a very natural call site — silently eats
      // the leading "c" of "code" and the callback is read as "no result".
      const { composable } = mountComposable()
      expect(composable.parseCallback('code=9f8e7d6c')).toBeNull()
    })
  })

  describe('exchangeCode', () => {
    it('posts the one-time code and stores the returned access token', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ access_token: 'oauth-tok', token_type: 'Bearer', expires_in: 900 }),
      )
      const { composable, client } = mountComposable()

      const result = await composable.exchangeCode('one-time-code')

      expect(result.access_token).toBe('oauth-tok')
      expect(client.accessToken).toBe('oauth-tok')
      expect(mockFetch).toHaveBeenCalledOnce()
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe(`${BASE}/auth/oauth2/exchange`)
      expect(init.method).toBe('POST')
      expect(init.credentials).toBe('include')
      expect(init.headers['X-Requested-With']).toBe('XMLHttpRequest')
      expect(JSON.parse(init.body)).toEqual({ code: 'one-time-code' })
    })

    it('throws and leaves no token behind when the code is rejected', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_or_expired_code', 400))
      const { composable, client } = mountComposable()

      await expect(composable.exchangeCode('spent-code')).rejects.toMatchObject({
        code: 'invalid_or_expired_code',
        status: 400,
      })
      expect(client.accessToken).toBeNull()
    })

    it('throws with the status intact when the error body is not JSON', async () => {
      mockFetch.mockResolvedValueOnce(new Response('<html>502 Bad Gateway</html>', { status: 502 }))
      const { composable, client } = mountComposable()

      await expect(composable.exchangeCode('code')).rejects.toMatchObject({
        code: 'unknown_error',
        status: 502,
      })
      expect(client.accessToken).toBeNull()
    })

    it('propagates a network failure without storing a token', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))
      const { composable, client } = mountComposable()

      await expect(composable.exchangeCode('code')).rejects.toThrow('Failed to fetch')
      expect(client.accessToken).toBeNull()
    })

    it('propagates an abort without storing a token', async () => {
      mockFetch.mockRejectedValueOnce(new DOMException('The operation was aborted.', 'AbortError'))
      const { composable, client } = mountComposable()

      await expect(composable.exchangeCode('code')).rejects.toMatchObject({ name: 'AbortError' })
      expect(client.accessToken).toBeNull()
    })

    it('rejects a 200 whose body is not JSON', async () => {
      mockFetch.mockResolvedValueOnce(new Response('not json at all', { status: 200 }))
      const { composable, client } = mountComposable()

      await expect(composable.exchangeCode('code')).rejects.toMatchObject({
        code: 'invalid_response',
        status: 200,
      })
      expect(client.accessToken).toBeNull()
    })

    it('keeps the previous token when the response carries no access_token', async () => {
      // DEFECT (reported): a response without access_token (2FA continuation, or a
      // hostile empty object) leaves whatever token was already in memory in place
      // instead of clearing it. The caller sees a resolved exchange and a client
      // that is still authenticated as the old principal.
      mockFetch.mockResolvedValueOnce(jsonResponse({ requires_2fa: true, challenge_token: 'ch-1' }))
      const { composable, client } = mountComposable()
      client.accessToken = 'previous-session-token'

      const result = await composable.exchangeCode('code')

      expect(result.access_token).toBeUndefined()
      expect(client.accessToken).toBe('previous-session-token')
    })

    it('re-sends the one-time code after a 401 triggers a refresh', async () => {
      // DEFECT (reported): exchangeOAuthCode goes through the default retry path,
      // unlike every other pre-authentication call (login, verifyTOTP,
      // webauthnVerifyFinish all pass retry=false). With a stale token in memory
      // the single-use exchange code is spent twice.
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_or_expired_code', 401))
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 900 }),
      )
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ access_token: 'oauth-tok', token_type: 'Bearer', expires_in: 900 }),
      )
      const { composable, client } = mountComposable()
      client.accessToken = 'stale-token'

      await composable.exchangeCode('single-use-code')

      expect(mockFetch).toHaveBeenCalledTimes(3)
      expect(mockFetch.mock.calls[0][0]).toBe(`${BASE}/auth/oauth2/exchange`)
      expect(mockFetch.mock.calls[1][0]).toBe(`${BASE}/auth/refresh`)
      expect(mockFetch.mock.calls[2][0]).toBe(`${BASE}/auth/oauth2/exchange`)
      expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({ code: 'single-use-code' })
      expect(JSON.parse(mockFetch.mock.calls[2][1].body)).toEqual({ code: 'single-use-code' })
    })

    it('clears the stale token and reports session_expired when that refresh also fails', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_or_expired_code', 401))
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_refresh_token', 401))
      const { composable, client } = mountComposable()
      client.accessToken = 'stale-token'

      await expect(composable.exchangeCode('code')).rejects.toMatchObject({
        code: 'session_expired',
        status: 401,
      })
      expect(client.accessToken).toBeNull()
    })

    it('shares a single refresh between two exchanges racing the same expired token', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 900 }),
      )
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ access_token: 'tok-a', token_type: 'Bearer', expires_in: 900 }),
      )
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ access_token: 'tok-b', token_type: 'Bearer', expires_in: 900 }),
      )
      const { composable, client } = mountComposable()
      client.accessToken = 'expired'

      await Promise.all([composable.exchangeCode('code-a'), composable.exchangeCode('code-b')])

      const refreshCalls = mockFetch.mock.calls.filter((c) => c[0] === `${BASE}/auth/refresh`)
      expect(refreshCalls).toHaveLength(1)
      expect(mockFetch).toHaveBeenCalledTimes(5)
    })
  })
})
