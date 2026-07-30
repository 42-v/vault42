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

function rawResponse(body: string, status = 200, headers: Record<string, string> = {}) {
  return new Response(body, { status, headers })
}

/** The cross-origin guard lives in the private request(); no public method reaches it. */
interface ClientInternals {
  request<T>(method: string, path: string, body?: unknown, retry?: boolean): Promise<T>
}

function internals(c: VaultClient): ClientInternals {
  return c as unknown as ClientInternals
}

describe('VaultClient — Transport', () => {
  let client: VaultClient

  beforeEach(() => {
    client = new VaultClient('https://vault42.example.com')
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('request init', () => {
    it('sends exactly Accept + X-Requested-With and no body on an unauthenticated GET', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

      await client.getProfile()

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/profile')
      expect(init.method).toBe('GET')
      expect(init.credentials).toBe('include')
      expect(init.headers).toEqual({
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      })
      expect(Object.prototype.hasOwnProperty.call(init, 'body')).toBe(false)
    })

    it('sends exactly the four headers and the serialized body on an authenticated POST', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 300 }))

      await client.confirmPassword('correct-horse-battery-staple')

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/auth/confirm')
      expect(init.method).toBe('POST')
      expect(init.credentials).toBe('include')
      expect(init.headers).toEqual({
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer tok-abc',
      })
      expect(init.body).toBe('{"password":"correct-horse-battery-staple"}')
    })

    it('strips every trailing slash from the base URL, not just the last one', async () => {
      const sloppy = new VaultClient('https://vault42.example.com///')
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

      await sloppy.getProfile()

      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/user/profile')
    })

    it('keeps a path prefix on the base URL', async () => {
      const prefixed = new VaultClient('https://vault42.example.com/api/')
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

      await prefixed.getProfile()

      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/api/user/profile')
    })

    it('passes the object returned by onRequest to fetch, not the one it built', async () => {
      const replacement: RequestInit = { method: 'GET', credentials: 'omit', headers: { 'X-Only': '1' } }
      const onRequest = vi.fn((_init: RequestInit) => replacement)
      const hooked = new VaultClient('https://vault42.example.com', { onRequest })
      hooked.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

      await hooked.getProfile()

      const built = onRequest.mock.calls[0][0]
      expect((built.headers as Record<string, string>).Authorization).toBe('Bearer tok-abc')
      expect(mockFetch.mock.calls[0][1]).toBe(replacement)
    })
  })

  describe('response body handling', () => {
    it('resolves undefined for a 204 with no body', async () => {
      mockFetch.mockResolvedValueOnce(rawResponse('', 204))

      const result = await client.deleteIdentity()

      expect(result).toBeUndefined()
    })

    it('resolves undefined for a 200 with an empty body', async () => {
      mockFetch.mockResolvedValueOnce(rawResponse('', 200))

      const result = await client.getIdentity()

      expect(result).toBeUndefined()
    })

    it('reports a 200 body that is not JSON as a VaultAPIError, not a raw SyntaxError', async () => {
      mockFetch.mockResolvedValueOnce(rawResponse('<html>captive portal</html>', 200, { 'Content-Type': 'text/html' }))

      const err = await client.getProfile().catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'invalid_response', status: 200 })
    })

    it('reports an unreadable success body as a VaultAPIError, not a raw TypeError', async () => {
      const broken = {
        ok: true,
        status: 200,
        headers: new Headers(),
        text: () => Promise.reject(new TypeError('network error')),
      }
      mockFetch.mockResolvedValueOnce(broken)

      const err = await client.getProfile().catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'invalid_response', status: 200 })
    })

    it('reports an unreadable binary body as a VaultAPIError, not a raw TypeError', async () => {
      const broken = {
        ok: true,
        status: 200,
        headers: new Headers(),
        arrayBuffer: () => Promise.reject(new TypeError('network error')),
      }
      mockFetch.mockResolvedValueOnce(broken)

      const err = await client.downloadBlob('blob-1').catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'invalid_response', status: 200 })
    })

    it('round-trips non-ASCII payloads without mangling', async () => {
      const payload = { given_name: 'Ěvęy', family_name: 'Ω日本語', country: 'SK' }
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'updated 🔐 Ω' }))

      const result = await client.putIdentity(payload)

      expect(mockFetch.mock.calls[0][1].body).toBe(JSON.stringify(payload))
      expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual(payload)
      expect(result.status).toBe('updated 🔐 Ω')
    })

    it('round-trips a multi-megabyte payload intact', async () => {
      const big = 'x'.repeat(1024 * 1024)
      mockFetch.mockResolvedValueOnce(jsonResponse({ given_name: big }))

      const result = await client.putIdentity({ given_name: big })

      expect(mockFetch.mock.calls[0][1].body.length).toBe(JSON.stringify({ given_name: big }).length)
      expect((result as unknown as { given_name: string }).given_name).toHaveLength(1024 * 1024)
    })
  })

  describe('origin pinning', () => {
    it('refuses an absolute URL whose origin differs from the base URL, before any fetch', async () => {
      client.accessToken = 'tok-abc'
      const foreign = [
        'https://evil.example.com/user/profile',
        'http://vault42.example.com/user/profile',
        'https://vault42.example.com.evil.com/user/profile',
      ]

      for (const path of foreign) {
        const err = await internals(client).request('GET', path).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(VaultAPIError)
        expect(err).toMatchObject({ code: 'invalid_request_url', status: 0 })
        expect((err as Error).message).toBe('Request URL origin does not match base URL origin')
      }
      expect(mockFetch).not.toHaveBeenCalled()
      expect(client.accessToken).toBe('tok-abc')
    })

    it('allows an absolute same-origin URL and authorizes it', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

      await internals(client).request('GET', 'https://vault42.example.com/user/profile')

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/profile')
      expect(init.headers.Authorization).toBe('Bearer tok-abc')
    })
  })

  describe('resource id validation', () => {
    it('rejects ids outside [A-Za-z0-9_-] without issuing a request', async () => {
      client.accessToken = 'tok-abc'

      await expect(client.deleteBlob('../../admin')).rejects.toThrow('Invalid resource ID')
      await expect(client.revokeSession('s1/../s2')).rejects.toThrow('Invalid resource ID')
      await expect(client.removeDevice('d1?x=1')).rejects.toThrow('Invalid resource ID')
      await expect(client.webauthnDeleteCredential('%2e%2e')).rejects.toThrow('Invalid resource ID')
      await expect(client.deleteNamedBlob('a b')).rejects.toThrow('Invalid resource ID')
      expect(mockFetch).not.toHaveBeenCalled()
    })

    it('rejects an id with the SDK error type so callers can branch on code', async () => {
      const err = await client.downloadNamedBlob('../secret').catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'invalid_resource_id', status: 0 })
      expect(mockFetch).not.toHaveBeenCalled()
    })
  })

  describe('binary transport', () => {
    it('sends the exact upload init: POST, credentials, label header, Blob body', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'b1', label: 'doc.bin', size_bytes: 1024, stored_bytes: 1024, checksum: 'sha256:a', created_at: '2026-02-24T10:00:00Z' }, 201))

      await client.uploadBlob(new ArrayBuffer(1024), 'doc.bin')

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/blobs')
      expect(init.method).toBe('POST')
      expect(init.credentials).toBe('include')
      expect(init.headers).toEqual({
        'X-Requested-With': 'XMLHttpRequest',
        'Authorization': 'Bearer tok-abc',
        'X-Blob-Label': 'doc.bin',
      })
      expect(init.body).toBeInstanceOf(Blob)
      expect((init.body as Blob).size).toBe(1024)
    })

    it('wraps a Uint8Array upload in a Blob of the same byte length', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'b2', label: '', size_bytes: 3, stored_bytes: 3, checksum: 'sha256:b', created_at: '2026-02-24T10:00:00Z' }, 201))

      await client.uploadBlob(new Uint8Array([1, 2, 3]))

      const body = mockFetch.mock.calls[0][1].body as Blob
      expect(body).toBeInstanceOf(Blob)
      expect(body.size).toBe(3)
    })

    it('refuses a label longer than 255 characters before issuing a request', async () => {
      const err = await client.uploadBlob(new ArrayBuffer(8), 'a'.repeat(256)).catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'invalid_blob_label', status: 0 })
      expect((err as Error).message).toBe('Blob label too long')
      expect(mockFetch).not.toHaveBeenCalled()
    })

    it('refuses a label carrying CR or LF instead of letting fetch throw', async () => {
      // A raw newline in a header value makes the platform fetch throw
      // "invalid header value", which is not a VaultAPIError and would also
      // permit header injection on a lenient stack.
      const injected = [
        'doc.bin\r\nX-Admin: 1',
        'doc.bin\nX-Admin: 1',
        'doc.bin\r',
        'doc\tbin',
      ]

      for (const label of injected) {
        const err = await client.uploadBlob(new ArrayBuffer(8), label).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(VaultAPIError)
        expect(err).toMatchObject({ code: 'invalid_blob_label', status: 0 })
      }
      expect(mockFetch).not.toHaveBeenCalled()
    })

    it('refuses a non-ASCII label, which the header layer cannot carry', async () => {
      const err = await client.uploadBlob(new ArrayBuffer(8), 'dokumentácia.pdf').catch((e: unknown) => e)

      expect(err).toBeInstanceOf(VaultAPIError)
      expect(err).toMatchObject({ code: 'invalid_blob_label', status: 0 })
      expect((err as Error).message).toBe('Blob label must contain only printable ASCII characters')
      expect(mockFetch).not.toHaveBeenCalled()
    })

    it('accepts the full printable ASCII range in a label', async () => {
      let ascii = ''
      for (let c = 0x20; c <= 0x7e; c++) ascii += String.fromCharCode(c)
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'b1', label: ascii, size_bytes: 1, stored_bytes: 1, checksum: 'sha256:a', created_at: '2026-02-24T10:00:00Z' }, 201))

      await client.uploadBlob(new Uint8Array([1]), ascii)

      expect(mockFetch.mock.calls[0][1].headers['X-Blob-Label']).toBe(ascii)
    })

    it('PUTs a named blob to the named path', async () => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'avatar', label: 'avatar', size_bytes: 4, stored_bytes: 4, checksum: 'sha256:c', created_at: '2026-02-24T10:00:00Z' }))

      await client.uploadNamedBlob('avatar_v2-1', new Uint8Array([1, 2, 3, 4]))

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/blobs/named/avatar_v2-1')
      expect(init.method).toBe('PUT')
      expect(init.headers.Authorization).toBe('Bearer tok-abc')
      expect((init.body as Blob).size).toBe(4)
    })

    it('reads label and checksum headers off a named download', async () => {
      mockFetch.mockResolvedValueOnce(new Response(new Uint8Array([9, 9]).buffer, {
        status: 200,
        headers: { 'X-Blob-Label': 'avatar', 'X-Blob-Checksum': 'sha256:c' },
      }))

      const result = await client.downloadNamedBlob('avatar_v2-1')

      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/user/blobs/named/avatar_v2-1')
      expect(result.data.byteLength).toBe(2)
      expect(result.label).toBe('avatar')
      expect(result.checksum).toBe('sha256:c')
    })

    it('runs the onRequest hook on binary requests too', async () => {
      const onRequest = vi.fn((init: RequestInit) => ({
        ...init,
        headers: { ...(init.headers as Record<string, string>), 'X-Fingerprint': 'fp1' },
      }))
      const hooked = new VaultClient('https://vault42.example.com', { onRequest })
      hooked.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(new Response(new Uint8Array([7]).buffer, { status: 200 }))

      await hooked.downloadNamedBlob('avatar')

      expect(onRequest).toHaveBeenCalledOnce()
      expect(mockFetch.mock.calls[0][1].headers).toEqual({
        'X-Requested-With': 'XMLHttpRequest',
        'Authorization': 'Bearer tok-abc',
        'X-Fingerprint': 'fp1',
      })
    })

    it('omits the Authorization header from a blob request when there is no token', async () => {
      mockFetch.mockResolvedValueOnce(new Response(new Uint8Array([1]).buffer, { status: 200 }))

      await client.downloadBlob('blob-1')

      expect(mockFetch.mock.calls[0][1].headers.Authorization).toBeUndefined()
      expect(mockFetch.mock.calls[0][1].credentials).toBe('include')
    })
  })
})
