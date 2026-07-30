import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { VaultClient } from '../client'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

const BASE = 'https://vault42.example.com'

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function binaryResponse(data: ArrayBuffer, headers: Record<string, string> = {}) {
  return new Response(data, { status: 200, headers })
}

const uploadOK = {
  id: 'b1',
  label: 'doc.bin',
  size_bytes: 4,
  stored_bytes: 4,
  checksum: 'sha256:a',
  created_at: '2026-02-24T10:00:00Z',
}

/**
 * The blob endpoints build their own binary init but share request()'s network
 * path, so every transport guarantee is re-proven here on the binary shape.
 */
describe('VaultClient — binary endpoints', () => {
  let client: VaultClient

  beforeEach(() => {
    client = new VaultClient(BASE)
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('onRequest hook', () => {
    it('hands fetch the object onRequest returned for an upload, not the one built', async () => {
      const replacement: RequestInit = { method: 'POST', credentials: 'omit', headers: { 'X-Only': '1' } }
      const onRequest = vi.fn((_init: RequestInit) => replacement)
      const hooked = new VaultClient(BASE, { onRequest })
      hooked.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse(uploadOK, 201))

      await hooked.uploadBlob(new Uint8Array([1, 2, 3, 4]), 'doc.bin')

      const built = onRequest.mock.calls[0][0]
      expect((built.headers as Record<string, string>).Authorization).toBe('Bearer tok-abc')
      expect((built.headers as Record<string, string>)['X-Blob-Label']).toBe('doc.bin')
      expect(mockFetch.mock.calls[0][1]).toBe(replacement)
    })

    it('hands fetch the object onRequest returned for a download, not the one built', async () => {
      const replacement: RequestInit = { method: 'GET', credentials: 'omit', headers: { 'X-Only': '1' } }
      const onRequest = vi.fn((_init: RequestInit) => replacement)
      const hooked = new VaultClient(BASE, { onRequest })
      hooked.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(binaryResponse(new Uint8Array([7]).buffer))

      await hooked.downloadBlob('blob-1')

      const built = onRequest.mock.calls[0][0]
      expect((built.headers as Record<string, string>).Authorization).toBe('Bearer tok-abc')
      expect(mockFetch.mock.calls[0][1]).toBe(replacement)
    })

    it('hands fetch the object onRequest returned for a named upload, not the one built', async () => {
      const replacement: RequestInit = { method: 'PUT', credentials: 'omit', headers: { 'X-Only': '1' } }
      const onRequest = vi.fn((_init: RequestInit) => replacement)
      const hooked = new VaultClient(BASE, { onRequest })
      hooked.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse(uploadOK))

      await hooked.uploadNamedBlob('avatar', new Uint8Array([1, 2, 3, 4]))

      expect((onRequest.mock.calls[0][0].headers as Record<string, string>).Authorization).toBe('Bearer tok-abc')
      expect(mockFetch.mock.calls[0][1]).toBe(replacement)
    })
  })

  describe('named upload body and headers', () => {
    it('omits Authorization on a named upload when no token is held', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(uploadOK))

      await client.uploadNamedBlob('avatar', new Uint8Array([1, 2]))

      expect(mockFetch.mock.calls[0][1].headers).toEqual({
        'X-Requested-With': 'XMLHttpRequest',
      })
      expect(mockFetch.mock.calls[0][1].credentials).toBe('include')
    })

    it('passes a caller-supplied Blob through to a named upload unwrapped', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(uploadOK))
      const blob = new Blob(['hello world'])

      await client.uploadNamedBlob('avatar', blob)

      expect(mockFetch.mock.calls[0][1].body).toBe(blob)
    })

    it('wraps an ArrayBuffer named upload in a Blob of the same byte length', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(uploadOK))

      await client.uploadNamedBlob('avatar', new ArrayBuffer(64))

      const body = mockFetch.mock.calls[0][1].body as Blob
      expect(body).toBeInstanceOf(Blob)
      expect(body.size).toBe(64)
    })

    it('never sends a blob label header on the named upload path', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(uploadOK))

      await client.uploadNamedBlob('avatar', new Uint8Array([1]))

      expect(mockFetch.mock.calls[0][1].headers['X-Blob-Label']).toBeUndefined()
    })
  })

  /**
   * The error body is attacker-influenced on a compromised or proxied edge.
   * Extraction must accept only the two documented shapes and fall back to a
   * fixed code otherwise — never leak an arbitrary field into `code`.
   */
  describe('error code extraction', () => {
    const cases: Array<[string, () => Promise<unknown>]> = [
      ['uploadBlob', () => client.uploadBlob(new Uint8Array([1]), 'doc.bin')],
      ['downloadBlob', () => client.downloadBlob('blob-1')],
      ['uploadNamedBlob', () => client.uploadNamedBlob('avatar', new Uint8Array([1]))],
      ['downloadNamedBlob', () => client.downloadNamedBlob('avatar')],
    ]

    it.each(cases)('%s falls back to the body "code" field when "error" is absent', async (_name, call) => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse({ code: 'blob_too_large' }, 413))

      await expect(call()).rejects.toMatchObject({ code: 'blob_too_large', status: 413 })
      expect(mockFetch).toHaveBeenCalledOnce()
    })

    it.each(cases)('%s reports unknown_error for a JSON body carrying neither field', async (_name, call) => {
      client.accessToken = 'tok-abc'
      mockFetch.mockResolvedValueOnce(jsonResponse({ detail: 'go away', message: 'nope' }, 500))

      await expect(call()).rejects.toMatchObject({ code: 'unknown_error', status: 500 })
      expect(client.accessToken).toBe('tok-abc')
    })

    it('auto-refreshes a 401 from a binary endpoint and replays it with the new bearer', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(jsonResponse({ error: 'token_expired' }, 401))
        .mockResolvedValueOnce(jsonResponse({ access_token: 'new-tok', token_type: 'Bearer', expires_in: 900 }))
        .mockResolvedValueOnce(binaryResponse(new Uint8Array([4, 2]).buffer))

      const result = await client.downloadBlob('blob-1')

      expect(result.data.byteLength).toBe(2)
      expect(mockFetch).toHaveBeenCalledTimes(3)
      expect(mockFetch.mock.calls[1][0]).toBe(`${BASE}/auth/refresh`)
      expect(mockFetch.mock.calls[2][1].headers.Authorization).toBe('Bearer new-tok')
      expect(client.accessToken).toBe('new-tok')
    })

    it('reports session_expired and drops the token when the binary refresh fails', async () => {
      client.accessToken = 'expired-tok'
      mockFetch
        .mockResolvedValueOnce(jsonResponse({ error: 'token_expired' }, 401))
        .mockResolvedValueOnce(jsonResponse({ error: 'invalid_refresh_token' }, 401))

      await expect(client.uploadBlob(new Uint8Array([1]), 'doc.bin')).rejects.toMatchObject({
        code: 'session_expired',
        status: 401,
      })
      expect(client.accessToken).toBeNull()
    })
  })
})
