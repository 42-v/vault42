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

function emptyResponse(status = 204) {
  return new Response('', { status })
}

function errorResponse(error: string, status: number) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('VaultClient — Core', () => {
  let client: VaultClient

  beforeEach(() => {
    client = new VaultClient('https://vault42.example.com/')
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('strips trailing slash from baseURL', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'ok' }))
    await client.getProfile()
    expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/user/profile')
  })

  it('get/set accessToken', () => {
    expect(client.accessToken).toBeNull()
    client.accessToken = 'abc'
    expect(client.accessToken).toBe('abc')
  })

  describe('register', () => {
    it('registers a user', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: 'u1', email: 'a@b.com' }))
      const result = await client.register('a@b.com', 'password123456789')
      expect(result.user_id).toBe('u1')
      const [, init] = mockFetch.mock.calls[0]
      expect(JSON.parse(init.body)).toMatchObject({ email: 'a@b.com', password: 'password123456789' })
    })

    it('sends display_name when provided', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: 'u1', email: 'a@b.com' }))
      await client.register('a@b.com', 'password123456789', 'Jane')
      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.display_name).toBe('Jane')
    })
  })

  describe('login', () => {
    it('logs in and sets accessToken', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }))
      const result = await client.login('a@b.com', 'password123456789')
      expect(result.access_token).toBe('tok1')
      expect(client.accessToken).toBe('tok1')
    })

    it('sends remember_me', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'tok1', token_type: 'Bearer', expires_in: 900 }))
      await client.login('a@b.com', 'password123456789', true)
      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.remember_me).toBe(true)
    })

    it('handles 2FA challenge (no access_token)', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ requires_2fa: true, challenge_token: 'ch1', available_methods: ['totp'] }))
      const result = await client.login('a@b.com', 'password123456789')
      expect(result.requires_2fa).toBe(true)
      expect(client.accessToken).toBeNull()
    })
  })

  describe('refresh', () => {
    it('refreshes and updates token', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'new-tok', token_type: 'Bearer', expires_in: 900 }))
      const result = await client.refresh()
      expect(result.access_token).toBe('new-tok')
      expect(client.accessToken).toBe('new-tok')
    })

    it('deduplicates concurrent calls', async () => {
      mockFetch.mockResolvedValue(jsonResponse({ access_token: 'new-tok', token_type: 'Bearer', expires_in: 900 }))
      const [r1, r2] = await Promise.all([client.refresh(), client.refresh()])
      expect(r1).toBe(r2)
      expect(mockFetch).toHaveBeenCalledOnce()
    })
  })

  describe('logout', () => {
    it('logs out and clears token', async () => {
      client.accessToken = 'tok1'
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.logout()
      expect(client.accessToken).toBeNull()
    })
  })

  describe('verifyEmail', () => {
    it('calls verify-email endpoint', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.verifyEmail('my-token')
      expect(mockFetch.mock.calls[0][0]).toContain('/auth/verify-email?token=my-token')
    })

    it('encodes token', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.verifyEmail('a+b&c')
      expect(mockFetch.mock.calls[0][0]).toContain(encodeURIComponent('a+b&c'))
    })
  })

  describe('getProfile', () => {
    it('fetches user profile', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1', email: 'a@b.com', email_verified: true }))
      const result = await client.getProfile()
      expect(result.id).toBe('u1')
    })
  })

  describe('sessions', () => {
    it('getSessions returns session array', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: [{ id: 's1', ip: '1.2.3.4', user_agent: 'test', trusted: false, first_seen_at: '2026-01-01' }] }))
      const result = await client.getSessions()
      expect(result).toHaveLength(1)
      expect(result[0].id).toBe('s1')
    })

    it('getSessions handles empty', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: null }))
      const result = await client.getSessions()
      expect(result).toEqual([])
    })

    it('revokeSession', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.revokeSession('s1')
      expect(mockFetch.mock.calls[0][0]).toContain('/user/sessions/s1')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
    })

    it('revokeAllSessions', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.revokeAllSessions()
      expect(mockFetch.mock.calls[0][0]).toContain('/user/sessions')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
    })
  })

  describe('devices', () => {
    it('getDevices returns array', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ devices: [{ id: 'd1', fingerprint_hash: 'abc' }] }))
      const result = await client.getDevices()
      expect(result).toHaveLength(1)
    })

    it('getDevices handles null', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ devices: null }))
      const result = await client.getDevices()
      expect(result).toEqual([])
    })

    it('renameDevice', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.renameDevice('d1', 'My Laptop')
      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.friendly_name).toBe('My Laptop')
    })

    it('removeDevice', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.removeDevice('d1')
      expect(mockFetch.mock.calls[0][0]).toContain('/user/devices/d1')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
    })
  })

  describe('password', () => {
    it('changePassword', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.changePassword('old-pass', 'new-pass-12345678')
      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.current_password).toBe('old-pass')
      expect(body.new_password).toBe('new-pass-12345678')
    })

    it('requestPasswordReset', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.requestPasswordReset('a@b.com')
      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.email).toBe('a@b.com')
    })

    it('confirmPasswordReset', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.confirmPasswordReset('reset-token', 'new-password-12345')
      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.token).toBe('reset-token')
      expect(body.password).toBe('new-password-12345')
    })
  })

  describe('2FA', () => {
    it('setupTOTP', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ secret: 'abc', otp_url: 'otpauth://...' }))
      const result = await client.setupTOTP()
      expect(result.secret).toBe('abc')
    })

    it('verifyTOTP (no auto-refresh)', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'tok2', token_type: 'Bearer', expires_in: 900 }))
      const result = await client.verifyTOTP('123456')
      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.code).toBe('123456')
      expect(result.access_token).toBe('tok2')
    })

    it('generateBackupCodes', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ codes: ['abc', 'def', 'ghi'] }))
      const codes = await client.generateBackupCodes()
      expect(codes).toEqual(['abc', 'def', 'ghi'])
    })

    it('getMFAStatus', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ totp_enabled: true, webauthn_enabled: false, backup_codes_remaining: 8, available_methods: ['totp'], mfa_required: false }))
      const status = await client.getMFAStatus()
      expect(status.totp_enabled).toBe(true)
    })

    it('disableTOTP', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.disableTOTP()
      expect(mockFetch.mock.calls[0][0]).toContain('/auth/2fa/totp')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
    })
  })

  describe('confirmPassword', () => {
    it('confirms password', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 300 }))
      const result = await client.confirmPassword('mypassword')
      expect(result.confirmed).toBe(true)
    })
  })

  describe('WebAuthn', () => {
    it('webauthnRegisterBegin', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ publicKey: { challenge: 'ch1', rp: { name: 'Vault42', id: 'example.com' } } }))
      const result = await client.webauthnRegisterBegin()
      expect(result.publicKey.challenge).toBe('ch1')
    })

    it('webauthnRegisterFinish', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.webauthnRegisterFinish({ id: 'cred1', response: {} })
      expect(mockFetch.mock.calls[0][1].method).toBe('POST')
    })

    it('webauthnVerifyBegin (no auto-refresh)', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ publicKey: { challenge: 'ch2' } }))
      const result = await client.webauthnVerifyBegin()
      expect(result.publicKey.challenge).toBe('ch2')
    })

    it('webauthnVerifyFinish (no auto-refresh)', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'tok3', token_type: 'Bearer', expires_in: 900 }))
      const result = await client.webauthnVerifyFinish({ id: 'cred1', response: {} })
      expect(result.access_token).toBe('tok3')
    })

    it('webauthnListCredentials', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ credentials: [{ id: 'c1', sign_count: 5, created_at: '2026-01-01' }] }))
      const creds = await client.webauthnListCredentials()
      expect(creds).toHaveLength(1)
    })

    it('webauthnListCredentials handles null', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ credentials: null }))
      const creds = await client.webauthnListCredentials()
      expect(creds).toEqual([])
    })

    it('webauthnDeleteCredential', async () => {
      mockFetch.mockResolvedValueOnce(emptyResponse())
      await client.webauthnDeleteCredential('c1')
      expect(mockFetch.mock.calls[0][0]).toContain('/auth/2fa/webauthn/credentials/c1')
    })
  })

  describe('OAuth', () => {
    it('getOAuthAuthorizeURL', () => {
      const url = client.getOAuthAuthorizeURL('github')
      expect(url).toBe('https://vault42.example.com/auth/oauth2/authorize?provider=github')
    })

    it('exchangeOAuthCode', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'oauth-tok', token_type: 'Bearer', expires_in: 900 }))
      const result = await client.exchangeOAuthCode('mycode')
      expect(result.access_token).toBe('oauth-tok')
      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.code).toBe('mycode')
    })
  })

  describe('well-known', () => {
    it('getJWKS', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ keys: [{ kty: 'RSA', kid: 'k1', alg: 'RS256' }] }))
      const jwks = await client.getJWKS()
      expect(jwks.keys).toHaveLength(1)
    })

    it('getOIDCConfig', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ issuer: 'https://vault42.example.com', jwks_uri: 'https://vault42.example.com/.well-known/jwks.json' }))
      const config = await client.getOIDCConfig()
      expect(config.issuer).toBe('https://vault42.example.com')
    })
  })

  describe('request internals', () => {
    it('auto-refreshes on 401 and retries', async () => {
      client.accessToken = 'expired-tok'
      // First call returns 401
      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      // Refresh call succeeds
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'new-tok', token_type: 'Bearer', expires_in: 900 }))
      // Retry call succeeds
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1', email: 'a@b.com' }))

      const result = await client.getProfile()
      expect(result.id).toBe('u1')
      expect(client.accessToken).toBe('new-tok')
      expect(mockFetch).toHaveBeenCalledTimes(3)
    })

    it('throws session_expired when refresh fails', async () => {
      client.accessToken = 'expired-tok'
      // First call returns 401
      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      // Refresh also fails
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_refresh', 401))

      await expect(client.getProfile()).rejects.toMatchObject({
        code: 'session_expired',
        status: 401,
      })
      expect(client.accessToken).toBeNull()
    })

    it('does not auto-refresh without access token', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      await expect(client.getProfile()).rejects.toMatchObject({
        code: 'unauthorized',
        status: 401,
      })
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('includes Authorization header when token is set', async () => {
      client.accessToken = 'my-token'
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))
      await client.getProfile()
      expect(mockFetch.mock.calls[0][1].headers.Authorization).toBe('Bearer my-token')
    })

    it('omits Authorization header when no token', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: 'u1', email: 'a@b.com' }))
      await client.register('a@b.com', 'password123456789')
      expect(mockFetch.mock.calls[0][1].headers.Authorization).toBeUndefined()
    })

    it('calls onRequest hook', async () => {
      const onRequest = vi.fn((init: RequestInit) => {
        (init.headers as Record<string, string>)['X-Custom'] = 'value'
        return init
      })
      const customClient = new VaultClient('https://vault42.example.com', { onRequest })
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'ok' }))
      await customClient.getProfile()
      expect(onRequest).toHaveBeenCalledOnce()
      expect(mockFetch.mock.calls[0][1].headers['X-Custom']).toBe('value')
    })

    it('handles non-JSON error body gracefully', async () => {
      mockFetch.mockResolvedValueOnce(new Response('Not Found', { status: 404 }))
      await expect(client.getProfile()).rejects.toMatchObject({
        code: 'unknown_error',
        status: 404,
      })
    })

    it('VaultAPIError has correct properties', () => {
      const err = new VaultAPIError('test_error', 400, 'Test message')
      expect(err.code).toBe('test_error')
      expect(err.status).toBe(400)
      expect(err.message).toBe('Test message')
      expect(err.name).toBe('VaultAPIError')
      expect(err instanceof Error).toBe(true)
    })

    it('VaultAPIError defaults message to code', () => {
      const err = new VaultAPIError('test_error', 400)
      expect(err.message).toBe('test_error')
    })

    it('sets credentials: include on all requests', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({}))
      await client.getProfile()
      expect(mockFetch.mock.calls[0][1].credentials).toBe('include')
    })

    it('sets Content-Type for POST with body', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: 'u1', email: 'a@b.com' }))
      await client.register('a@b.com', 'pass123456789012')
      expect(mockFetch.mock.calls[0][1].headers['Content-Type']).toBe('application/json')
    })

    it('omits Content-Type for GET', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))
      await client.getProfile()
      expect(mockFetch.mock.calls[0][1].headers['Content-Type']).toBeUndefined()
    })
  })
})
