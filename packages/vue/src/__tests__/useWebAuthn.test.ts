import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { useWebAuthn } from '../composables/useWebAuthn'
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

function buf(...b: number[]): ArrayBuffer {
  return new Uint8Array(b).buffer
}

/**
 * base64url fixtures, hand-computed so the test pins the encoding rather than
 * re-deriving it with the code under test:
 *   '-_8'  -> [0xfb, 0xff]        (both substituted chars + missing padding)
 *   [0xfb, 0xff, 0x00] -> '-_8A'  (no '=' padding on the way out)
 *   'AQIDBA' -> [1, 2, 3, 4]
 */
const CHALLENGE_B64 = '-_8'
const CHALLENGE_BYTES = new Uint8Array([0xfb, 0xff])
const RAW_ID_BYTES = [0xfb, 0xff, 0x00]
const RAW_ID_B64 = '-_8A'
const USER_ID_B64 = 'AQIDBA'
const USER_ID_BYTES = new Uint8Array([1, 2, 3, 4])

const creationOptions = {
  publicKey: {
    challenge: CHALLENGE_B64,
    rp: { name: 'Vault42', id: 'vault42.example.com' },
    user: { id: USER_ID_B64, name: 'a@b.com', displayName: 'Jane' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60000,
    excludeCredentials: [{ type: 'public-key', id: 'AQID', transports: ['usb', 'nfc'] }],
    authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
    attestation: 'none',
  },
}

const assertionOptions = {
  publicKey: {
    challenge: CHALLENGE_B64,
    timeout: 60000,
    rpId: 'vault42.example.com',
    allowCredentials: [{ type: 'public-key', id: 'AQID', transports: ['internal'] }],
    userVerification: 'required',
  },
}

function attestationCredential() {
  return {
    id: 'cred-id-1',
    type: 'public-key',
    rawId: buf(...RAW_ID_BYTES),
    response: {
      attestationObject: buf(1, 2, 3),
      clientDataJSON: buf(0x7b, 0x7d),
    },
  }
}

function assertionCredential(userHandle: ArrayBuffer | null = null) {
  return {
    id: 'cred-id-1',
    type: 'public-key',
    rawId: buf(...RAW_ID_BYTES),
    response: {
      authenticatorData: buf(1, 2, 3),
      clientDataJSON: buf(0x7b, 0x7d),
      signature: buf(0xff, 0xff, 0xff),
      userHandle,
    },
  }
}

const originalNavigator = navigator

function stubCredentials(impl: unknown) {
  Object.defineProperty(originalNavigator, 'credentials', {
    value: impl,
    configurable: true,
    writable: true,
  })
}

function mountComposable() {
  let composable!: ReturnType<typeof useWebAuthn>
  let client!: VaultClient

  const TestComponent = defineComponent({
    setup() {
      composable = useWebAuthn()
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

describe('useWebAuthn', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    delete (originalNavigator as unknown as Record<string, unknown>).credentials
    delete (globalThis as unknown as Record<string, unknown>).PublicKeyCredential
  })

  describe('isSupported', () => {
    it('is false when the browser has no PublicKeyCredential', () => {
      const { composable } = mountComposable()
      expect(composable.isSupported.value).toBe(false)
    })

    it('is true when the browser exposes PublicKeyCredential', () => {
      ;(globalThis as unknown as Record<string, unknown>).PublicKeyCredential = class {}
      const { composable } = mountComposable()
      expect(composable.isSupported.value).toBe(true)
    })
  })

  describe('register', () => {
    it('decodes the server challenge and posts the attested credential back', async () => {
      const create = vi.fn().mockResolvedValue(attestationCredential())
      stubCredentials({ create })
      mockFetch.mockResolvedValueOnce(jsonResponse(creationOptions))
      mockFetch.mockResolvedValueOnce(emptyResponse())

      const { composable } = mountComposable()
      await composable.register()

      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/auth/2fa/webauthn/register/begin')
      expect(mockFetch.mock.calls[0][1].method).toBe('POST')

      const pk = create.mock.calls[0][0].publicKey
      expect(new Uint8Array(pk.challenge)).toEqual(CHALLENGE_BYTES)
      expect(new Uint8Array(pk.user.id)).toEqual(USER_ID_BYTES)
      expect(pk.user.name).toBe('a@b.com')
      expect(pk.user.displayName).toBe('Jane')
      expect(pk.rp).toEqual({ name: 'Vault42', id: 'vault42.example.com' })
      expect(pk.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -7 }])
      expect(pk.timeout).toBe(60000)
      expect(pk.attestation).toBe('none')
      expect(pk.authenticatorSelection).toEqual({ userVerification: 'required', residentKey: 'preferred' })
      expect(pk.excludeCredentials).toHaveLength(1)
      expect(new Uint8Array(pk.excludeCredentials[0].id)).toEqual(new Uint8Array([1, 2, 3]))
      expect(pk.excludeCredentials[0].transports).toEqual(['usb', 'nfc'])

      const [finishURL, finishInit] = mockFetch.mock.calls[1]
      expect(finishURL).toBe('https://vault42.example.com/auth/2fa/webauthn/register/finish')
      expect(JSON.parse(finishInit.body)).toEqual({
        id: 'cred-id-1',
        rawId: RAW_ID_B64,
        type: 'public-key',
        response: {
          attestationObject: 'AQID',
          clientDataJSON: 'e30',
        },
      })

      expect(composable.isRegistered.value).toBe(true)
      expect(composable.error.value).toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('reports webauthn_cancelled when the user dismisses the prompt', async () => {
      const cancel = new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')
      const create = vi.fn().mockRejectedValue(cancel)
      stubCredentials({ create })
      mockFetch.mockResolvedValueOnce(jsonResponse(creationOptions))

      const { composable } = mountComposable()

      await expect(composable.register()).rejects.toBe(cancel)

      expect(composable.error.value).toEqual({ code: 'webauthn_cancelled', status: 0 })
      expect(composable.isRegistered.value).toBe(false)
      expect(composable.isLoading.value).toBe(false)
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('does not register when the authenticator times out', async () => {
      const timeout = new DOMException('Operation timed out.', 'TimeoutError')
      const create = vi.fn().mockRejectedValue(timeout)
      stubCredentials({ create })
      mockFetch.mockResolvedValueOnce(jsonResponse(creationOptions))

      const { composable } = mountComposable()

      await expect(composable.register()).rejects.toBe(timeout)

      expect(composable.error.value).toBe(timeout)
      expect(composable.isRegistered.value).toBe(false)
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('treats a null credential as a cancellation and never calls finish', async () => {
      const create = vi.fn().mockResolvedValue(null)
      stubCredentials({ create })
      mockFetch.mockResolvedValueOnce(jsonResponse(creationOptions))

      const { composable } = mountComposable()

      await expect(composable.register()).rejects.toEqual({ code: 'webauthn_cancelled', status: 0 })

      expect(composable.error.value).toEqual({ code: 'webauthn_cancelled', status: 0 })
      expect(composable.isRegistered.value).toBe(false)
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('throws instead of degrading when navigator.credentials is unavailable', async () => {
      stubCredentials(undefined)
      mockFetch.mockResolvedValueOnce(jsonResponse(creationOptions))

      const { composable } = mountComposable()

      await expect(composable.register()).rejects.toBeInstanceOf(TypeError)

      expect(composable.isSupported.value).toBe(false)
      expect(composable.isRegistered.value).toBe(false)
      expect(composable.isLoading.value).toBe(false)
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('never prompts the authenticator when begin fails', async () => {
      const create = vi.fn()
      stubCredentials({ create })
      mockFetch.mockResolvedValueOnce(errorResponse('password_confirmation_required', 403))

      const { composable } = mountComposable()

      await expect(composable.register()).rejects.toMatchObject({
        code: 'password_confirmation_required',
        status: 403,
      })

      expect(create).not.toHaveBeenCalled()
      expect(composable.isRegistered.value).toBe(false)
    })

    it('stays unregistered when the server rejects the attestation', async () => {
      const create = vi.fn().mockResolvedValue(attestationCredential())
      stubCredentials({ create })
      mockFetch.mockResolvedValueOnce(jsonResponse(creationOptions))
      mockFetch.mockResolvedValueOnce(errorResponse('attestation_verification_failed', 400))

      const { composable } = mountComposable()

      await expect(composable.register()).rejects.toMatchObject({
        code: 'attestation_verification_failed',
        status: 400,
      })

      expect(composable.isRegistered.value).toBe(false)
      expect(composable.error.value!.code).toBe('attestation_verification_failed')
      expect(composable.isLoading.value).toBe(false)
    })

    it('reports a non-JSON error body as unknown_error', async () => {
      const create = vi.fn()
      stubCredentials({ create })
      mockFetch.mockResolvedValueOnce(new Response('<html>502</html>', { status: 502 }))

      const { composable } = mountComposable()

      await expect(composable.register()).rejects.toMatchObject({
        code: 'unknown_error',
        status: 502,
      })
      expect(create).not.toHaveBeenCalled()
    })

    it('holds isLoading until the authenticator answers', async () => {
      let resolveCreate!: (value: unknown) => void
      const create = vi.fn().mockReturnValue(new Promise((r) => { resolveCreate = r }))
      stubCredentials({ create })
      mockFetch.mockResolvedValueOnce(jsonResponse(creationOptions))
      mockFetch.mockResolvedValueOnce(emptyResponse())

      const { composable } = mountComposable()
      const promise = composable.register()
      await vi.waitFor(() => expect(create).toHaveBeenCalled())

      expect(composable.isLoading.value).toBe(true)

      resolveCreate(attestationCredential())
      await promise

      expect(composable.isLoading.value).toBe(false)
    })
  })

  describe('verify', () => {
    it('authenticates with the challenge token and swaps in the real access token', async () => {
      const get = vi.fn().mockResolvedValue(assertionCredential())
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(jsonResponse(assertionOptions))
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'real-token', token_type: 'Bearer', expires_in: 900 }))

      const { composable, client } = mountComposable()
      const result = await composable.verify('challenge-token')

      const [beginURL, beginInit] = mockFetch.mock.calls[0]
      expect(beginURL).toBe('https://vault42.example.com/auth/2fa/webauthn/verify/begin')
      expect(beginInit.headers.Authorization).toBe('Bearer challenge-token')

      const pk = get.mock.calls[0][0].publicKey
      expect(new Uint8Array(pk.challenge)).toEqual(CHALLENGE_BYTES)
      expect(pk.rpId).toBe('vault42.example.com')
      expect(pk.timeout).toBe(60000)
      expect(pk.userVerification).toBe('required')
      expect(new Uint8Array(pk.allowCredentials[0].id)).toEqual(new Uint8Array([1, 2, 3]))
      expect(pk.allowCredentials[0].transports).toEqual(['internal'])

      const [finishURL, finishInit] = mockFetch.mock.calls[1]
      expect(finishURL).toBe('https://vault42.example.com/auth/2fa/webauthn/verify/finish')
      expect(finishInit.headers.Authorization).toBe('Bearer challenge-token')
      expect(JSON.parse(finishInit.body)).toEqual({
        id: 'cred-id-1',
        rawId: RAW_ID_B64,
        type: 'public-key',
        response: {
          authenticatorData: 'AQID',
          clientDataJSON: 'e30',
          signature: '____',
        },
      })

      expect(result.access_token).toBe('real-token')
      expect(client.accessToken).toBe('real-token')
      expect(composable.error.value).toBeNull()
    })

    it('encodes a discoverable-credential userHandle', async () => {
      const get = vi.fn().mockResolvedValue(assertionCredential(buf(0xfb, 0xff, 0x00)))
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(jsonResponse(assertionOptions))
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'real-token', token_type: 'Bearer', expires_in: 900 }))

      const { composable } = mountComposable()
      await composable.verify()

      const body = JSON.parse(mockFetch.mock.calls[1][1].body)
      expect(body.response.userHandle).toBe(RAW_ID_B64)
    })

    it('restores the previous access token when the user cancels', async () => {
      const cancel = new DOMException('Not allowed.', 'NotAllowedError')
      const get = vi.fn().mockRejectedValue(cancel)
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(jsonResponse(assertionOptions))

      const { composable, client } = mountComposable()
      client.accessToken = 'previous-token'

      await expect(composable.verify('challenge-token')).rejects.toBe(cancel)

      expect(client.accessToken).toBe('previous-token')
      expect(composable.error.value).toEqual({ code: 'webauthn_cancelled', status: 0 })
      expect(composable.isLoading.value).toBe(false)
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it('does not retain the challenge token when the server rejects the assertion', async () => {
      const get = vi.fn().mockResolvedValue(assertionCredential())
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(jsonResponse(assertionOptions))
      mockFetch.mockResolvedValueOnce(errorResponse('assertion_verification_failed', 400))

      const { composable, client } = mountComposable()

      await expect(composable.verify('challenge-token')).rejects.toMatchObject({
        code: 'assertion_verification_failed',
        status: 400,
      })

      expect(client.accessToken).toBeNull()
      expect(composable.error.value!.code).toBe('assertion_verification_failed')
    })

    it('does not auto-refresh when the challenge token is rejected with 401', async () => {
      const get = vi.fn()
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_challenge', 401))

      const { composable, client } = mountComposable()

      await expect(composable.verify('challenge-token')).rejects.toMatchObject({
        code: 'invalid_challenge',
        status: 401,
      })

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(get).not.toHaveBeenCalled()
      expect(client.accessToken).toBeNull()
    })

    it('leaves an already-authenticated session untouched when no challenge token is passed', async () => {
      const cancel = new DOMException('Not allowed.', 'NotAllowedError')
      const get = vi.fn().mockRejectedValue(cancel)
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(jsonResponse(assertionOptions))

      const { composable, client } = mountComposable()
      client.accessToken = 'session-token'

      await expect(composable.verify()).rejects.toBe(cancel)

      expect(client.accessToken).toBe('session-token')
    })

    it('treats a null assertion as a cancellation and never calls finish', async () => {
      const get = vi.fn().mockResolvedValue(null)
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(jsonResponse(assertionOptions))

      const { composable, client } = mountComposable()

      await expect(composable.verify('challenge-token')).rejects.toEqual({ code: 'webauthn_cancelled', status: 0 })

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(client.accessToken).toBeNull()
    })

    it('surfaces a network failure mid-assertion and restores the token', async () => {
      const get = vi.fn().mockResolvedValue(assertionCredential())
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(jsonResponse(assertionOptions))
      const netErr = new TypeError('Failed to fetch')
      mockFetch.mockRejectedValueOnce(netErr)

      const { composable, client } = mountComposable()
      client.accessToken = 'previous-token'

      await expect(composable.verify('challenge-token')).rejects.toBe(netErr)

      expect(client.accessToken).toBe('previous-token')
      expect(composable.error.value).toBe(netErr)
      expect(composable.isLoading.value).toBe(false)
    })

    it('sends the assertion but issues no token when the server answers 200 with no access_token', async () => {
      const get = vi.fn().mockResolvedValue(assertionCredential())
      stubCredentials({ get })
      mockFetch.mockResolvedValueOnce(jsonResponse(assertionOptions))
      mockFetch.mockResolvedValueOnce(jsonResponse({ token_type: 'Bearer', expires_in: 900 }))

      const { composable } = mountComposable()
      const result = await composable.verify('challenge-token')

      expect(result.access_token).toBeUndefined()
      expect(composable.error.value).toBeNull()
      expect(JSON.parse(mockFetch.mock.calls[1][1].body).rawId).toBe(RAW_ID_B64)
    })
  })

  describe('listCredentials', () => {
    it('fetches and stores the credential list', async () => {
      const creds = [{ id: 'c1', sign_count: 3, created_at: '2026-02-24T10:00:00Z' }]
      mockFetch.mockResolvedValueOnce(jsonResponse({ credentials: creds }))

      const { composable } = mountComposable()
      const result = await composable.listCredentials()

      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/auth/2fa/webauthn/credentials')
      expect(mockFetch.mock.calls[0][1].method).toBe('GET')
      expect(result).toEqual(creds)
      expect(composable.credentials.value).toEqual(creds)
    })

    it('keeps the last known list and stays silent when the fetch fails', async () => {
      const creds = [{ id: 'c1', sign_count: 3, created_at: '2026-02-24T10:00:00Z' }]
      mockFetch.mockResolvedValueOnce(jsonResponse({ credentials: creds }))
      const { composable } = mountComposable()
      await composable.listCredentials()

      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))
      const result = await composable.listCredentials()

      expect(result).toEqual(creds)
      expect(composable.credentials.value).toEqual(creds)
      expect(composable.error.value).toBeNull()
    })
  })

  describe('deleteCredential', () => {
    it('removes only the deleted credential from the list', async () => {
      const creds = [
        { id: 'c1', sign_count: 3, created_at: '2026-02-24T10:00:00Z' },
        { id: 'c2', sign_count: 1, created_at: '2026-02-25T10:00:00Z' },
      ]
      mockFetch.mockResolvedValueOnce(jsonResponse({ credentials: creds }))
      const { composable } = mountComposable()
      await composable.listCredentials()

      mockFetch.mockResolvedValueOnce(emptyResponse())
      await composable.deleteCredential('c1')

      const [url, init] = mockFetch.mock.calls[1]
      expect(url).toBe('https://vault42.example.com/auth/2fa/webauthn/credentials/c1')
      expect(init.method).toBe('DELETE')
      expect(composable.credentials.value.map((c) => c.id)).toEqual(['c2'])
      expect(composable.error.value).toBeNull()
    })

    it('keeps the credential listed when the delete fails', async () => {
      const creds = [{ id: 'c1', sign_count: 3, created_at: '2026-02-24T10:00:00Z' }]
      mockFetch.mockResolvedValueOnce(jsonResponse({ credentials: creds }))
      const { composable } = mountComposable()
      await composable.listCredentials()

      mockFetch.mockResolvedValueOnce(errorResponse('password_confirmation_required', 403))

      await expect(composable.deleteCredential('c1')).rejects.toMatchObject({
        code: 'password_confirmation_required',
        status: 403,
      })

      expect(composable.credentials.value).toEqual(creds)
      expect(composable.isLoading.value).toBe(false)
    })

    it('refuses a path-traversal credential id without issuing a request', async () => {
      const creds = [{ id: 'c1', sign_count: 3, created_at: '2026-02-24T10:00:00Z' }]
      mockFetch.mockResolvedValueOnce(jsonResponse({ credentials: creds }))
      const { composable } = mountComposable()
      await composable.listCredentials()
      mockFetch.mockClear()

      await expect(composable.deleteCredential('../../auth/2fa/totp')).rejects.toThrow('Invalid resource ID')

      expect(mockFetch).not.toHaveBeenCalled()
      expect(composable.credentials.value).toEqual(creds)
      expect(composable.isLoading.value).toBe(false)
    })
  })
})
