import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { usePasswordReset } from '../composables/usePasswordReset'
import { createVaultPlugin, useVaultClient } from '../plugin'
import type { VaultClient } from '../client'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

const BASE = 'https://vault42.example.com'

/**
 * The exact body POST /auth/password/reset returns. The handler writes it from a
 * deferred block that runs on both the found-user and no-such-user paths, so the
 * two branches are byte-identical on the wire.
 */
const ENUMERATION_SAFE_BODY = { status: 'If that email exists, a reset link has been sent.' }

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
  let composable!: ReturnType<typeof usePasswordReset>
  let client!: VaultClient

  const TestComponent = defineComponent({
    setup() {
      composable = usePasswordReset()
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

function snapshot(c: ReturnType<typeof usePasswordReset>) {
  return {
    isLoading: c.isLoading.value,
    error: c.error.value,
    requested: c.requested.value,
    confirmed: c.confirmed.value,
  }
}

describe('usePasswordReset', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('starts idle with nothing requested or confirmed', () => {
    const { composable } = mountComposable()
    expect(snapshot(composable)).toEqual({
      isLoading: false,
      error: null,
      requested: false,
      confirmed: false,
    })
  })

  describe('requestReset', () => {
    it('posts exactly the address to the reset endpoint', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(ENUMERATION_SAFE_BODY))
      const { composable } = mountComposable()

      await composable.requestReset('user@example.com')

      expect(mockFetch).toHaveBeenCalledOnce()
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe(`${BASE}/auth/password/reset`)
      expect(init.method).toBe('POST')
      expect(init.credentials).toBe('include')
      expect(init.headers['Content-Type']).toBe('application/json')
      expect(init.headers['X-Requested-With']).toBe('XMLHttpRequest')
      expect(JSON.parse(init.body)).toEqual({ email: 'user@example.com' })
    })

    it('is indistinguishable for a registered and an unknown address', async () => {
      // User-enumeration prevention is a server invariant, but the SDK is the half
      // that a caller observes. Given the server's identical 200, the composable
      // must leave identical state and must have sent an identically shaped
      // request — no extra probe, no different code path, nothing to branch on.
      mockFetch.mockResolvedValueOnce(jsonResponse(ENUMERATION_SAFE_BODY))
      const registered = mountComposable()
      const registeredReturn = await registered.composable.requestReset('exists@example.com')
      const registeredState = snapshot(registered.composable)
      const registeredCall = mockFetch.mock.calls[0]

      mockFetch.mockReset()
      mockFetch.mockResolvedValueOnce(jsonResponse(ENUMERATION_SAFE_BODY))
      const unknown = mountComposable()
      const unknownReturn = await unknown.composable.requestReset('nobody@example.com')
      const unknownState = snapshot(unknown.composable)
      const unknownCall = mockFetch.mock.calls[0]

      expect(unknownState).toEqual(registeredState)
      expect(registeredState).toEqual({
        isLoading: false,
        error: null,
        requested: true,
        confirmed: false,
      })

      expect(unknownCall[0]).toBe(registeredCall[0])
      expect(unknownCall[1].method).toBe(registeredCall[1].method)
      expect(unknownCall[1].headers).toEqual(registeredCall[1].headers)
      expect(Object.keys(JSON.parse(unknownCall[1].body))).toEqual(
        Object.keys(JSON.parse(registeredCall[1].body)),
      )

      // Nothing is handed back either, so a caller cannot branch on the response.
      expect(registeredReturn).toBeUndefined()
      expect(unknownReturn).toBeUndefined()
    })

    it('does not expose the server status message to the caller', async () => {
      // The message is the only field the endpoint returns; surfacing it verbatim
      // would be the obvious place for a future per-branch wording to leak out.
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'user u-42 will receive a link' }))
      const { composable } = mountComposable()

      await composable.requestReset('user@example.com')

      expect(composable.requested.value).toBe(true)
      expect(Object.keys(composable).sort()).toEqual([
        'changePassword',
        'confirmReset',
        'confirmed',
        'error',
        'isLoading',
        'requestReset',
        'requested',
      ])
      expect(JSON.stringify(snapshot(composable))).not.toContain('u-42')
    })

    it('leaves requested false and swallows the rejection on a server error', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_request', 400))
      const { composable } = mountComposable()

      await expect(composable.requestReset('')).resolves.toBeUndefined()

      expect(composable.requested.value).toBe(false)
      expect(composable.error.value).toMatchObject({ code: 'invalid_request', status: 400 })
      expect(composable.isLoading.value).toBe(false)
    })

    it('leaves requested false when the request is rate limited', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('rate_limited', 429))
      const { composable } = mountComposable()

      await composable.requestReset('user@example.com')

      expect(composable.requested.value).toBe(false)
      expect(composable.error.value).toMatchObject({ code: 'rate_limited', status: 429 })
    })

    it('preserves the status when the error body is not JSON', async () => {
      mockFetch.mockResolvedValueOnce(new Response('<html>503</html>', { status: 503 }))
      const { composable } = mountComposable()

      await composable.requestReset('user@example.com')

      expect(composable.error.value).toMatchObject({ code: 'unknown_error', status: 503 })
      expect(composable.requested.value).toBe(false)
    })

    it('leaves requested false when the network throws', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))
      const { composable } = mountComposable()

      await composable.requestReset('user@example.com')

      expect(composable.requested.value).toBe(false)
      expect(composable.error.value).toMatchObject({ message: 'Failed to fetch' })
      expect(composable.isLoading.value).toBe(false)
    })

    it('clears a stale success flag and a stale error when retried', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(ENUMERATION_SAFE_BODY))
      const { composable } = mountComposable()
      await composable.requestReset('user@example.com')
      expect(composable.requested.value).toBe(true)

      mockFetch.mockResolvedValueOnce(errorResponse('rate_limited', 429))
      await composable.requestReset('user@example.com')

      expect(composable.requested.value).toBe(false)
      expect(composable.error.value).toMatchObject({ code: 'rate_limited' })

      mockFetch.mockResolvedValueOnce(jsonResponse(ENUMERATION_SAFE_BODY))
      await composable.requestReset('user@example.com')

      expect(composable.error.value).toBeNull()
      expect(composable.requested.value).toBe(true)
    })

    it('flags isLoading only while the request is in flight', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))
      const { composable } = mountComposable()

      const promise = composable.requestReset('user@example.com')
      expect(composable.isLoading.value).toBe(true)

      resolvePromise(jsonResponse(ENUMERATION_SAFE_BODY))
      await promise

      expect(composable.isLoading.value).toBe(false)
    })

    it('reports both success and failure when two requests overlap', async () => {
      // DEFECT (reported): requested/error/isLoading are per-composable, not
      // per-call. A slow failing request and a fast succeeding one leave the
      // composable claiming the mail was sent *and* carrying an error, so a UI
      // bound to both refs renders a contradiction.
      let rejectSlow!: (reason: unknown) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((_, rej) => { rejectSlow = rej }))
      const { composable } = mountComposable()

      const slow = composable.requestReset('user@example.com')

      mockFetch.mockResolvedValueOnce(jsonResponse(ENUMERATION_SAFE_BODY))
      await composable.requestReset('user@example.com')
      expect(composable.requested.value).toBe(true)

      rejectSlow(new TypeError('Failed to fetch'))
      await slow

      expect(composable.requested.value).toBe(true)
      expect(composable.error.value).not.toBeNull()
    })

    it('drops isLoading while a second operation is still in flight', async () => {
      // DEFECT (reported): the shared isLoading is cleared by whichever call
      // finishes first, so a spinner disappears with a request still open.
      let resolveSlow!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolveSlow = r }))
      const { composable } = mountComposable()

      const slow = composable.requestReset('user@example.com')
      expect(composable.isLoading.value).toBe(true)

      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'ok' }))
      await composable.changePassword('old-password-12345', 'new-password-12345')

      // The reset request is still open, yet the shared flag has already dropped.
      expect(composable.isLoading.value).toBe(false)
      expect(composable.requested.value).toBe(false)

      resolveSlow(jsonResponse(ENUMERATION_SAFE_BODY))
      await slow
      expect(composable.requested.value).toBe(true)
    })
  })

  describe('confirmReset', () => {
    it('posts exactly the token and the new password', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'password_reset_complete' }))
      const { composable } = mountComposable()

      await composable.confirmReset('reset-token', 'a-brand-new-password')

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe(`${BASE}/auth/password/reset/confirm`)
      expect(init.method).toBe('POST')
      expect(JSON.parse(init.body)).toEqual({
        token: 'reset-token',
        password: 'a-brand-new-password',
      })
      expect(composable.confirmed.value).toBe(true)
      expect(composable.error.value).toBeNull()
    })

    it('rejects an expired or already-spent token without confirming', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_or_expired_token', 400))
      const { composable } = mountComposable()

      await expect(composable.confirmReset('spent-token', 'a-brand-new-password')).rejects.toMatchObject({
        code: 'invalid_or_expired_token',
        status: 400,
      })

      expect(composable.confirmed.value).toBe(false)
      expect(composable.error.value).toMatchObject({ code: 'invalid_or_expired_token' })
      expect(composable.isLoading.value).toBe(false)
    })

    it('rejects a password the server refuses without confirming', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('password_too_short', 400))
      const { composable } = mountComposable()

      await expect(composable.confirmReset('reset-token', 'short')).rejects.toMatchObject({
        code: 'password_too_short',
      })
      expect(composable.confirmed.value).toBe(false)
    })

    it('rejects a breached password without confirming', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('password_breached', 400))
      const { composable } = mountComposable()

      await expect(composable.confirmReset('reset-token', 'correcthorsebattery')).rejects.toMatchObject({
        code: 'password_breached',
      })
      expect(composable.confirmed.value).toBe(false)
    })

    it('clears a previous success before a retry can fail', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'password_reset_complete' }))
      const { composable } = mountComposable()
      await composable.confirmReset('reset-token', 'a-brand-new-password')
      expect(composable.confirmed.value).toBe(true)

      mockFetch.mockResolvedValueOnce(errorResponse('invalid_or_expired_token', 400))
      await expect(composable.confirmReset('reset-token', 'another-new-password')).rejects.toThrow()

      expect(composable.confirmed.value).toBe(false)
    })

    it('rethrows a network failure without confirming', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))
      const { composable } = mountComposable()

      await expect(composable.confirmReset('reset-token', 'a-brand-new-password')).rejects.toThrow(
        'Failed to fetch',
      )
      expect(composable.confirmed.value).toBe(false)
      expect(composable.isLoading.value).toBe(false)
    })

    it('sends no Authorization header when no session is in memory', async () => {
      // The confirm endpoint is unauthenticated: the reset token is the only
      // credential it may see.
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'password_reset_complete' }))
      const { composable } = mountComposable()

      await composable.confirmReset('reset-token', 'a-brand-new-password')

      expect(mockFetch.mock.calls[0][1].headers.Authorization).toBeUndefined()
    })

    it('keeps the in-memory access token after a successful reset', async () => {
      // DEFECT (reported): resetting the password is the canonical account-recovery
      // action and the server drops the refresh-token family, but the SDK holds on
      // to the access token minted for the old credential.
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'password_reset_complete' }))
      const { composable, client } = mountComposable()
      client.accessToken = 'token-from-old-password'

      await composable.confirmReset('reset-token', 'a-brand-new-password')

      // The reset really happened...
      expect(composable.confirmed.value).toBe(true)
      expect(mockFetch.mock.calls[0][0]).toBe(`${BASE}/auth/password/reset/confirm`)
      // ...and the token minted for the superseded credential is still armed.
      expect(client.accessToken).toBe('token-from-old-password')
    })
  })

  describe('changePassword', () => {
    it('posts exactly the current and the new password', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'password_changed' }))
      const { composable } = mountComposable()

      await composable.changePassword('current-password-1', 'brand-new-password-1')

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe(`${BASE}/user/password`)
      expect(init.method).toBe('POST')
      expect(JSON.parse(init.body)).toEqual({
        current_password: 'current-password-1',
        new_password: 'brand-new-password-1',
      })
      expect(composable.error.value).toBeNull()
    })

    it('rethrows when the current password is wrong', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_credentials', 401))
      const { composable, client } = mountComposable()
      client.accessToken = 'session-token'
      // Refresh succeeds, the retried change still fails: the 401 is about the
      // submitted password, not the session.
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 900 }),
      )
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_credentials', 401))

      await expect(
        composable.changePassword('wrong-password-000', 'brand-new-password-1'),
      ).rejects.toMatchObject({ code: 'invalid_credentials', status: 401 })

      expect(mockFetch).toHaveBeenCalledTimes(3)
      expect(mockFetch.mock.calls[1][0]).toBe(`${BASE}/auth/refresh`)
      expect(composable.error.value).toMatchObject({ code: 'invalid_credentials' })
      expect(composable.isLoading.value).toBe(false)
    })

    it('rethrows server_busy when the argon2 semaphore is full', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('server_busy', 503))
      const { composable } = mountComposable()

      await expect(
        composable.changePassword('current-password-1', 'brand-new-password-1'),
      ).rejects.toMatchObject({ code: 'server_busy', status: 503 })
      expect(composable.error.value).toMatchObject({ status: 503 })
    })

    it('leaves confirmed asserting success after a failed change', async () => {
      // DEFECT (reported): changePassword never resets `confirmed`, so a screen
      // that reuses one composable for both flows still shows the earlier reset's
      // success banner while the change it just attempted failed.
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'password_reset_complete' }))
      const { composable } = mountComposable()
      await composable.confirmReset('reset-token', 'a-brand-new-password')

      mockFetch.mockResolvedValueOnce(errorResponse('invalid_credentials', 401))
      await expect(
        composable.changePassword('wrong-password-000', 'brand-new-password-1'),
      ).rejects.toThrow()

      expect(composable.confirmed.value).toBe(true)
      expect(composable.error.value).not.toBeNull()
    })

    it('does not clear the access token after a successful change', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'password_changed' }))
      const { composable, client } = mountComposable()
      client.accessToken = 'session-token'

      await composable.changePassword('current-password-1', 'brand-new-password-1')

      expect(client.accessToken).toBe('session-token')
      expect(mockFetch.mock.calls[0][1].headers.Authorization).toBe('Bearer session-token')
    })
  })
})
