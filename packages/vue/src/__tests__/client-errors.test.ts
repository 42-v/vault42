import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { VaultClient, VaultAPIError } from '../client'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

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

function rawResponse(body: string, status: number) {
  return new Response(body, { status })
}

function tokenResponse(token: string) {
  return jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 900 })
}

function tick(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0))
}

/** Route by URL so concurrent flows are order-independent; a Response body may only be read once. */
function route(handlers: Array<[string, () => Response | Promise<Response>]>) {
  const counts: Record<string, number> = {}
  mockFetch.mockImplementation(async (url: string) => {
    for (const [suffix, handler] of handlers) {
      if (url.endsWith(suffix)) {
        counts[suffix] = (counts[suffix] || 0) + 1
        return handler()
      }
    }
    throw new Error(`unexpected fetch to ${url}`)
  })
  return counts
}

describe('VaultClient — Errors', () => {
  let client: VaultClient

  beforeEach(() => {
    client = new VaultClient('https://vault42.example.com')
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('401 refresh and retry', () => {
    it('retries with the refreshed token, not the expired one', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(tokenResponse('new-tok'))
        .mockResolvedValueOnce(jsonResponse({ id: 'u1', email: 'a@b.com' }))

      const result = await client.getProfile()

      expect(result.id).toBe('u1')
      expect(mockFetch).toHaveBeenCalledTimes(3)
      const [refreshURL, refreshInit] = mockFetch.mock.calls[1]
      expect(refreshURL).toBe('https://vault42.example.com/auth/refresh')
      expect(refreshInit.method).toBe('POST')
      expect(refreshInit.credentials).toBe('include')
      expect(Object.prototype.hasOwnProperty.call(refreshInit, 'body')).toBe(false)
      const [retryURL, retryInit] = mockFetch.mock.calls[2]
      expect(retryURL).toBe('https://vault42.example.com/user/profile')
      expect(retryInit.headers.Authorization).toBe('Bearer new-tok')
      expect(client.accessToken).toBe('new-tok')
    })

    it('replays the original method and body on the retried request', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(tokenResponse('new-tok'))
        .mockResolvedValueOnce(jsonResponse({ status: 'updated' }))

      await client.putIdentity({ given_name: 'Jane', country: 'SK' })

      const [firstURL, firstInit] = mockFetch.mock.calls[0]
      const [retryURL, retryInit] = mockFetch.mock.calls[2]
      expect(retryURL).toBe(firstURL)
      expect(retryInit.method).toBe('PUT')
      expect(retryInit.body).toBe(firstInit.body)
      expect(JSON.parse(retryInit.body)).toEqual({ given_name: 'Jane', country: 'SK' })
    })

    it('does not refresh a second time when the retry is also rejected', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(tokenResponse('new-tok'))
        .mockResolvedValueOnce(errorResponse('token_expired', 401))

      await expect(client.getProfile()).rejects.toMatchObject({ code: 'token_expired', status: 401 })
      expect(mockFetch).toHaveBeenCalledTimes(3)
      const refreshCalls = (mockFetch.mock.calls as unknown as string[][]).filter((c) => c[0].endsWith('/auth/refresh'))
      expect(refreshCalls).toHaveLength(1)
    })

    it('drops the freshly refreshed token when the server rejects it too', async () => {
      // The refresh succeeded, so the token is not "expired" from the client's
      // point of view, but the server just refused it: keeping it would send a
      // known-dead bearer on every later call.
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(tokenResponse('new-tok'))
        .mockResolvedValueOnce(errorResponse('token_expired', 401))

      await expect(client.getProfile()).rejects.toMatchObject({ code: 'token_expired', status: 401 })
      expect(client.accessToken).toBeNull()

      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))
      await client.getProfile()
      expect(mockFetch.mock.calls[3][1].headers.Authorization).toBeUndefined()
    })

    it('keeps a non-401 failure of the retried request intact and holds the token', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(tokenResponse('new-tok'))
        .mockResolvedValueOnce(errorResponse('server_busy', 503))

      await expect(client.getProfile()).rejects.toMatchObject({ code: 'server_busy', status: 503 })
      expect(client.accessToken).toBe('new-tok')
    })

    it('never refreshes the public capabilities probe', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))

      await expect(client.getCapabilities()).rejects.toMatchObject({ code: 'unauthorized', status: 401 })
      expect(mockFetch).toHaveBeenCalledOnce()
      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/auth/capabilities')
    })

    it('never refreshes on a 401 from a no-retry endpoint even with a token set', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_code', 401))

      await expect(client.verifyTOTP('123456')).rejects.toMatchObject({ code: 'invalid_code', status: 401 })
      expect(mockFetch).toHaveBeenCalledOnce()
      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/auth/2fa/totp/verify')
      expect(client.accessToken).toBe('tok-abc')
    })
  })

  describe('failing refresh', () => {
    it('clears the token and reports session_expired when the refresh request throws', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockRejectedValueOnce(new TypeError('Failed to fetch'))

      await expect(client.getProfile()).rejects.toMatchObject({ code: 'session_expired', status: 401 })
      expect(client.accessToken).toBeNull()
      expect(mockFetch).toHaveBeenCalledTimes(2)
    })

    it('clears the token when the refresh returns 200 with a non-JSON body', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(rawResponse('<html>login</html>', 200))

      await expect(client.getProfile()).rejects.toMatchObject({ code: 'session_expired', status: 401 })
      expect(client.accessToken).toBeNull()
    })

    it('releases the in-flight refresh slot so a later refresh is attempted again', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockRejectedValueOnce(new TypeError('Failed to fetch'))

      await expect(client.getProfile()).rejects.toMatchObject({ code: 'session_expired' })

      client.accessToken = 'second-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(tokenResponse('fresh-tok'))
        .mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

      const result = await client.getProfile()

      expect(result.id).toBe('u1')
      expect(client.accessToken).toBe('fresh-tok')
      expect(mockFetch).toHaveBeenCalledTimes(5)
    })

    it('rejects and clears the token when a refresh response omits access_token', async () => {
      // A 200 without a token is not a successful refresh. Assigning it would
      // put undefined behind the `string | null` getter.
      client.accessToken = 'old-tok'
      mockFetch.mockResolvedValueOnce(jsonResponse({ token_type: 'Bearer', expires_in: 900 }))

      const err = await client.refresh().catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'invalid_refresh_response', status: 200 })
      expect(client.accessToken).toBeNull()

      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))
      await client.getProfile()
      expect(mockFetch.mock.calls[1][1].headers.Authorization).toBeUndefined()
    })

    it('rejects a refresh whose access_token is not a usable string', async () => {
      for (const token of [null, 42, '', { v: 1 }]) {
        client.accessToken = 'old-tok'
        mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 900 }))

        await expect(client.refresh()).rejects.toMatchObject({ code: 'invalid_refresh_response' })
        expect(client.accessToken).toBeNull()
      }
    })

    it('turns a token-less refresh into session_expired on the 401 retry path', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(jsonResponse({ token_type: 'Bearer', expires_in: 900 }))

      await expect(client.getProfile()).rejects.toMatchObject({ code: 'session_expired', status: 401 })
      expect(client.accessToken).toBeNull()
      expect(mockFetch).toHaveBeenCalledTimes(2)
    })
  })

  describe('concurrent 401s', () => {
    it('fires one refresh for two requests that race a 401 and resolves both', async () => {
      client.accessToken = 'expired-tok'
      let profileHits = 0
      let mfaHits = 0
      const counts = route([
        ['/auth/refresh', async () => { await tick(); return tokenResponse('new-tok') }],
        ['/user/profile', async () => {
          await tick()
          profileHits++
          return profileHits === 1 ? errorResponse('token_expired', 401) : jsonResponse({ id: 'u1' })
        }],
        ['/auth/2fa/status', async () => {
          await tick()
          mfaHits++
          return mfaHits === 1
            ? errorResponse('token_expired', 401)
            : jsonResponse({ totp_enabled: true, webauthn_enabled: false, backup_codes_remaining: 3, available_methods: ['totp'], mfa_required: true })
        }],
      ])

      const [profile, mfa] = await Promise.all([client.getProfile(), client.getMFAStatus()])

      expect(profile.id).toBe('u1')
      expect(mfa.totp_enabled).toBe(true)
      expect(counts['/auth/refresh']).toBe(1)
      expect(profileHits).toBe(2)
      expect(mfaHits).toBe(2)
      expect(client.accessToken).toBe('new-tok')
    })

    it('fails both racing requests closed when the shared refresh fails', async () => {
      client.accessToken = 'expired-tok'
      const counts = route([
        ['/auth/refresh', async () => { await tick(); return errorResponse('invalid_refresh_token', 401) }],
        ['/user/profile', async () => { await tick(); return errorResponse('token_expired', 401) }],
        ['/user/sessions', async () => { await tick(); return errorResponse('token_expired', 401) }],
      ])

      const results = await Promise.allSettled([client.getProfile(), client.getSessions()])

      expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected'])
      for (const r of results) {
        expect((r as PromiseRejectedResult).reason).toMatchObject({ code: 'session_expired', status: 401 })
      }
      expect(counts['/auth/refresh']).toBe(1)
      expect(client.accessToken).toBeNull()
    })
  })

  describe('server misbehaviour', () => {
    it('surfaces the code and status of a 5xx without touching the token', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(errorResponse('server_busy', 503))

      const err = await client.getProfile().catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'server_busy', status: 503 })
      expect(mockFetch).toHaveBeenCalledOnce()
      expect(client.accessToken).toBe('tok-abc')
    })

    it('falls back to unknown_error for error bodies that are not an object with error/code', async () => {
      const bodies = ['null', '"boom"', '[]', '{}', '{"detail":"nope"}', 'not json at all', '']

      for (const body of bodies) {
        mockFetch.mockResolvedValueOnce(rawResponse(body, 500))
        await expect(client.getProfile()).rejects.toMatchObject({ code: 'unknown_error', status: 500 })
      }
      expect(mockFetch).toHaveBeenCalledTimes(bodies.length)
    })

    it('prefers error over code and accepts a bare code field', async () => {
      mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'rate_limited', code: 'other' }), { status: 429 }))
      await expect(client.getProfile()).rejects.toMatchObject({ code: 'rate_limited', status: 429 })

      mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ code: 'forbidden' }), { status: 403 }))
      await expect(client.getProfile()).rejects.toMatchObject({ code: 'forbidden', status: 403 })
    })

    it('rejects login with the SDK error type when the server answers 200 with an empty body', async () => {
      mockFetch.mockResolvedValueOnce(rawResponse('', 200))

      const err = await client.login('a@b.com', 'password123456789').catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'invalid_response', status: 200 })
      expect(client.accessToken).toBeNull()
    })

    it('leaves no token after a failed login', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_credentials', 401))

      await expect(client.login('a@b.com', 'wrong-password-here')).rejects.toMatchObject({
        code: 'invalid_credentials',
        status: 401,
      })
      expect(client.accessToken).toBeNull()
      expect(mockFetch).toHaveBeenCalledOnce()
    })
  })

  describe('network faults', () => {
    it('propagates a fetch throw without retrying or storing a token', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))

      await expect(client.login('a@b.com', 'password123456789')).rejects.toBeInstanceOf(TypeError)
      expect(mockFetch).toHaveBeenCalledOnce()
      expect(client.accessToken).toBeNull()
    })

    it('passes a caller-supplied abort signal to fetch and propagates AbortError unwrapped', async () => {
      const controller = new AbortController()
      const onRequest = vi.fn((init: RequestInit) => ({ ...init, signal: controller.signal }))
      const hooked = new VaultClient('https://vault42.example.com', { onRequest })
      hooked.accessToken = 'tok-abc'
      mockFetch.mockRejectedValueOnce(new DOMException('The operation was aborted.', 'AbortError'))

      const err = await hooked.getProfile().catch((e: unknown) => e)

      expect((err as DOMException).name).toBe('AbortError')
      expect(mockFetch.mock.calls[0][1].signal).toBe(controller.signal)
      expect(mockFetch).toHaveBeenCalledOnce()
      expect(hooked.accessToken).toBe('tok-abc')
    })
  })

  describe('logout', () => {
    it('surfaces a server failure instead of reporting a clean logout', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      await expect(client.logout()).rejects.toMatchObject({ code: 'internal_error', status: 500 })
    })

    it('de-authenticates locally even when the server refuses the logout', async () => {
      // The caller has been told the session is over; the bearer must not
      // survive in memory just because the server answered 500.
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      await expect(client.logout()).rejects.toMatchObject({ code: 'internal_error' })
      expect(client.accessToken).toBeNull()

      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))
      await client.getProfile()
      expect(mockFetch.mock.calls[1][1].headers.Authorization).toBeUndefined()
    })

    it('de-authenticates locally when the logout request never reaches the server', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))

      await expect(client.logout()).rejects.toBeInstanceOf(TypeError)
      expect(client.accessToken).toBeNull()
    })

    it('drops the token when logout hits a 401 and the refresh fails', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(errorResponse('token_expired', 401))
        .mockResolvedValueOnce(errorResponse('invalid_refresh_token', 401))

      await expect(client.logout()).rejects.toMatchObject({ code: 'session_expired', status: 401 })
      expect(client.accessToken).toBeNull()
    })
  })

  describe('binary endpoints', () => {
    it('maps a non-JSON upload failure to unknown_error', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(rawResponse('<html>502 Bad Gateway</html>', 502))

      await expect(client.uploadBlob(new ArrayBuffer(64), 'doc.bin')).rejects.toMatchObject({
        code: 'unknown_error',
        status: 502,
      })
    })

    it('maps a non-JSON download failure to unknown_error', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(rawResponse('gateway timeout', 504))

      await expect(client.downloadBlob('blob-1')).rejects.toMatchObject({
        code: 'unknown_error',
        status: 504,
      })
    })

    it('maps a named upload failure to the server error code', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(errorResponse('quota_exceeded', 409))

      await expect(client.uploadNamedBlob('avatar', new Uint8Array([1, 2]))).rejects.toMatchObject({
        code: 'quota_exceeded',
        status: 409,
      })
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('does not return partial data when a named download fails', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))

      const err = await client.downloadNamedBlob('avatar').catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'blob_not_found', status: 404 })
    })
  })
})
