import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { use2FA } from '../composables/use2FA'
import { createVaultPlugin, useVaultClient } from '../plugin'
import type { VaultClient } from '../client'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function emptyResponse(status = 204) {
  return new Response('', { status })
}

function errorResponse(error: string, status: number) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const enrolment = { secret: 'JBSWY3DPEHPK3PXP', otp_url: 'otpauth://totp/Vault42:a@b.com?secret=JBSWY3DPEHPK3PXP&issuer=Vault42' }
const statusEnabled = {
  totp_enabled: true,
  webauthn_enabled: false,
  backup_codes_remaining: 10,
  available_methods: ['totp'],
  mfa_required: false,
}
const statusDisabled = { ...statusEnabled, totp_enabled: false, backup_codes_remaining: 0, available_methods: [] }

function mountComposable() {
  let composable!: ReturnType<typeof use2FA>
  let client!: VaultClient

  const TestComponent = defineComponent({
    setup() {
      composable = use2FA()
      client = useVaultClient()
      return () => h('div')
    },
  })

  const plugin = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
  const wrapper = mount(TestComponent, {
    global: { plugins: [plugin] },
  })

  return { wrapper, composable, client }
}

/** Enrol + verify so the composable is in the "TOTP active" state. */
async function enrolAndVerify(composable: ReturnType<typeof use2FA>) {
  mockFetch.mockResolvedValueOnce(jsonResponse(enrolment))
  await composable.setupTOTP()
  mockFetch.mockResolvedValueOnce(emptyResponse())
  mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))
  await composable.verifyTOTP('123456')
  mockFetch.mockClear()
}

describe('use2FA', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('initializes with no enrolment, no codes and no verification', () => {
    const { composable } = mountComposable()

    expect(composable.totpSetup.value).toBeNull()
    expect(composable.backupCodes.value).toEqual([])
    expect(composable.mfaStatus.value).toBeNull()
    expect(composable.isVerified.value).toBe(false)
    expect(composable.isLoading.value).toBe(false)
    expect(composable.error.value).toBeNull()
  })

  describe('setupTOTP', () => {
    it('POSTs to the setup endpoint and stores the secret and otpauth URL', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(enrolment))

      const { composable } = mountComposable()
      await composable.setupTOTP()

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/auth/2fa/totp/setup')
      expect(init.method).toBe('POST')
      expect(init.body).toBeUndefined()
      expect(init.credentials).toBe('include')
      expect(composable.totpSetup.value).toEqual(enrolment)
      expect(composable.error.value).toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('clears a previous verification so a re-enrolment cannot inherit it', async () => {
      const { composable } = mountComposable()
      await enrolAndVerify(composable)
      expect(composable.isVerified.value).toBe(true)

      mockFetch.mockResolvedValueOnce(jsonResponse({ secret: 'NEWSECRET', otp_url: 'otpauth://totp/new' }))
      await composable.setupTOTP()

      expect(composable.isVerified.value).toBe(false)
      expect(composable.totpSetup.value!.secret).toBe('NEWSECRET')
    })

    it('leaves no enrolment behind when the server rejects the request', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('password_confirmation_required', 403))

      const { composable } = mountComposable()
      await composable.setupTOTP()

      expect(composable.totpSetup.value).toBeNull()
      expect(composable.isVerified.value).toBe(false)
      expect(composable.error.value!.code).toBe('password_confirmation_required')
      expect(composable.error.value!.status).toBe(403)
      expect(composable.isLoading.value).toBe(false)
    })

    it('reports unknown_error when the body is not JSON', async () => {
      mockFetch.mockResolvedValueOnce(new Response('<html>502 Bad Gateway</html>', { status: 502 }))

      const { composable } = mountComposable()
      await composable.setupTOTP()

      expect(composable.totpSetup.value).toBeNull()
      expect(composable.error.value!.code).toBe('unknown_error')
      expect(composable.error.value!.status).toBe(502)
    })

    it('surfaces a network failure and stops loading', async () => {
      const netErr = new TypeError('Failed to fetch')
      mockFetch.mockRejectedValueOnce(netErr)

      const { composable } = mountComposable()
      await composable.setupTOTP()

      expect(composable.error.value).toBe(netErr)
      expect(composable.totpSetup.value).toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('holds isLoading until the request settles', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))

      const { composable } = mountComposable()
      const promise = composable.setupTOTP()

      expect(composable.isLoading.value).toBe(true)

      resolvePromise(jsonResponse(enrolment))
      await promise

      expect(composable.isLoading.value).toBe(false)
    })
  })

  describe('verifyTOTP', () => {
    it('sends the code and refreshes MFA status on success', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))

      const { composable } = mountComposable()
      await composable.verifyTOTP('123456')

      const [verifyURL, verifyInit] = mockFetch.mock.calls[0]
      expect(verifyURL).toBe('https://vault42.example.com/auth/2fa/totp/verify')
      expect(verifyInit.method).toBe('POST')
      expect(JSON.parse(verifyInit.body)).toEqual({ code: '123456' })

      const [statusURL, statusInit] = mockFetch.mock.calls[1]
      expect(statusURL).toBe('https://vault42.example.com/auth/2fa/status')
      expect(statusInit.method).toBe('GET')

      expect(composable.isVerified.value).toBe(true)
      expect(composable.mfaStatus.value).toEqual(statusEnabled)
      expect(composable.error.value).toBeNull()
    })

    it('rejects a wrong code without marking the enrolment verified', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_code', 400))

      const { composable } = mountComposable()

      await expect(composable.verifyTOTP('000000')).rejects.toMatchObject({
        code: 'invalid_code',
        status: 400,
      })

      expect(composable.isVerified.value).toBe(false)
      expect(composable.mfaStatus.value).toBeNull()
      expect(composable.error.value!.code).toBe('invalid_code')
      expect(composable.isLoading.value).toBe(false)
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('rejects a replayed code and does not re-query status', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('code_already_used', 400))

      const { composable } = mountComposable()

      await expect(composable.verifyTOTP('123456')).rejects.toMatchObject({
        code: 'code_already_used',
        status: 400,
      })

      expect(composable.isVerified.value).toBe(false)
      expect(composable.error.value!.code).toBe('code_already_used')
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('does not attempt a token refresh when the challenge is rejected with 401', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_challenge', 401))

      const { composable, client } = mountComposable()
      client.accessToken = 'challenge-token'

      await expect(composable.verifyTOTP('123456')).rejects.toMatchObject({
        code: 'invalid_challenge',
        status: 401,
      })

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(composable.isVerified.value).toBe(false)
    })

    it('surfaces a network failure without verifying', async () => {
      const netErr = new TypeError('Failed to fetch')
      mockFetch.mockRejectedValueOnce(netErr)

      const { composable } = mountComposable()

      await expect(composable.verifyTOTP('123456')).rejects.toBe(netErr)

      expect(composable.isVerified.value).toBe(false)
      expect(composable.error.value).toBe(netErr)
      expect(composable.isLoading.value).toBe(false)
    })

    it('aborts cleanly when the request is cancelled mid-flight', async () => {
      const aborted = new DOMException('The operation was aborted.', 'AbortError')
      mockFetch.mockRejectedValueOnce(aborted)

      const { composable } = mountComposable()

      await expect(composable.verifyTOTP('123456')).rejects.toBe(aborted)

      expect(composable.isVerified.value).toBe(false)
      expect(composable.isLoading.value).toBe(false)
    })

    it('keeps the verification when the follow-up status call fails', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      const { composable } = mountComposable()
      await composable.verifyTOTP('123456')

      expect(composable.isVerified.value).toBe(true)
      expect(composable.mfaStatus.value).toBeNull()
      expect(composable.error.value).toBeNull()
    })
  })

  describe('disableTOTP', () => {
    it('DELETEs the enrolment, drops the verified flag and refreshes status', async () => {
      const { composable } = mountComposable()
      await enrolAndVerify(composable)

      mockFetch.mockResolvedValueOnce(emptyResponse())
      mockFetch.mockResolvedValueOnce(jsonResponse(statusDisabled))
      await composable.disableTOTP()

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/auth/2fa/totp')
      expect(init.method).toBe('DELETE')
      expect(mockFetch.mock.calls[1][0]).toBe('https://vault42.example.com/auth/2fa/status')

      expect(composable.isVerified.value).toBe(false)
      expect(composable.mfaStatus.value).toEqual(statusDisabled)
      expect(composable.error.value).toBeNull()
    })

    it('keeps TOTP active when the server demands re-authentication', async () => {
      const { composable } = mountComposable()
      await enrolAndVerify(composable)

      mockFetch.mockResolvedValueOnce(errorResponse('password_confirmation_required', 403))
      await composable.disableTOTP()

      expect(composable.error.value!.code).toBe('password_confirmation_required')
      expect(composable.error.value!.status).toBe(403)
      expect(composable.isVerified.value).toBe(true)
      expect(composable.mfaStatus.value).toEqual(statusEnabled)
      expect(mockFetch).toHaveBeenCalledOnce()
      expect(composable.isLoading.value).toBe(false)
    })
  })

  describe('generateBackupCodes', () => {
    it('stores the issued codes and refreshes status', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ codes: ['aaaa-1111', 'bbbb-2222'] }))
      mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))

      const { composable } = mountComposable()
      await composable.generateBackupCodes()

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/auth/2fa/backup-codes')
      expect(init.method).toBe('POST')
      expect(composable.backupCodes.value).toEqual(['aaaa-1111', 'bbbb-2222'])
      expect(composable.mfaStatus.value).toEqual(statusEnabled)
    })

    it('replaces the previous set on regeneration instead of appending', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ codes: ['old-1', 'old-2'] }))
      mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))

      const { composable } = mountComposable()
      await composable.generateBackupCodes()

      mockFetch.mockResolvedValueOnce(jsonResponse({ codes: ['new-1', 'new-2'] }))
      mockFetch.mockResolvedValueOnce(jsonResponse({ ...statusEnabled, backup_codes_remaining: 2 }))
      await composable.generateBackupCodes()

      expect(composable.backupCodes.value).toEqual(['new-1', 'new-2'])
      expect(composable.backupCodes.value).toHaveLength(2)
      expect(composable.mfaStatus.value!.backup_codes_remaining).toBe(2)
    })

    it('keeps the codes already issued when regeneration fails', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ codes: ['old-1', 'old-2'] }))
      mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))

      const { composable } = mountComposable()
      await composable.generateBackupCodes()

      mockFetch.mockResolvedValueOnce(errorResponse('rate_limited', 429))
      await composable.generateBackupCodes()

      expect(composable.backupCodes.value).toEqual(['old-1', 'old-2'])
      expect(composable.error.value!.code).toBe('rate_limited')
      expect(composable.error.value!.status).toBe(429)
      expect(composable.isLoading.value).toBe(false)
    })

    it('discards the old set when the server answers 200 with no codes', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ codes: ['old-1', 'old-2'] }))
      mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))

      const { composable } = mountComposable()
      await composable.generateBackupCodes()

      mockFetch.mockResolvedValueOnce(jsonResponse({}))
      mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))
      await composable.generateBackupCodes()

      // The old set is gone, and what replaces it is the server's absent `codes`
      // field verbatim — not an empty array, so a `.length` in a template throws.
      expect(composable.backupCodes.value).toBeUndefined()
      expect(composable.error.value).toBeNull()
    })
  })

  describe('fetchMFAStatus', () => {
    it('stores the status', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))

      const { composable } = mountComposable()
      await composable.fetchMFAStatus()

      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/auth/2fa/status')
      expect(composable.mfaStatus.value).toEqual(statusEnabled)
    })

    it('swallows failures and leaves the last known status untouched', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(statusEnabled))
      const { composable } = mountComposable()
      await composable.fetchMFAStatus()

      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))
      await expect(composable.fetchMFAStatus()).resolves.toBeUndefined()

      expect(composable.mfaStatus.value).toEqual(statusEnabled)
      expect(composable.error.value).toBeNull()
    })
  })

  describe('expired access token', () => {
    it('shares a single refresh between two calls racing a 401', async () => {
      const { composable, client } = mountComposable()
      client.accessToken = 'expired-token'

      const seen: Array<{ url: string; method: string; auth?: string }> = []
      let firstSetup = true
      let firstCodes = true
      mockFetch.mockImplementation((url: string, init: RequestInit) => {
        const headers = init.headers as Record<string, string>
        seen.push({ url, method: init.method as string, auth: headers.Authorization })
        if (url.endsWith('/auth/refresh')) {
          return Promise.resolve(jsonResponse({ access_token: 'fresh-token', token_type: 'Bearer', expires_in: 900 }))
        }
        if (url.endsWith('/auth/2fa/totp/setup')) {
          if (firstSetup) { firstSetup = false; return Promise.resolve(errorResponse('unauthorized', 401)) }
          return Promise.resolve(jsonResponse(enrolment))
        }
        if (url.endsWith('/auth/2fa/backup-codes')) {
          if (firstCodes) { firstCodes = false; return Promise.resolve(errorResponse('unauthorized', 401)) }
          return Promise.resolve(jsonResponse({ codes: ['aaaa-1111'] }))
        }
        return Promise.resolve(jsonResponse(statusEnabled))
      })

      await Promise.all([composable.setupTOTP(), composable.generateBackupCodes()])

      expect(seen.filter((c) => c.url.endsWith('/auth/refresh'))).toHaveLength(1)
      expect(client.accessToken).toBe('fresh-token')
      expect(composable.totpSetup.value).toEqual(enrolment)
      expect(composable.backupCodes.value).toEqual(['aaaa-1111'])
      expect(composable.error.value).toBeNull()

      const retries = seen.filter((c) => c.auth === 'Bearer fresh-token')
      expect(retries.map((c) => c.url).sort()).toEqual([
        'https://vault42.example.com/auth/2fa/backup-codes',
        'https://vault42.example.com/auth/2fa/status',
        'https://vault42.example.com/auth/2fa/totp/setup',
      ])
    })

    it('clears the token and reports session_expired when the refresh also fails', async () => {
      const { composable, client } = mountComposable()
      client.accessToken = 'expired-token'

      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_refresh_token', 401))

      await composable.setupTOTP()

      expect(client.accessToken).toBeNull()
      expect(composable.totpSetup.value).toBeNull()
      expect(composable.error.value!.code).toBe('session_expired')
      expect(composable.error.value!.status).toBe(401)
    })
  })
})
