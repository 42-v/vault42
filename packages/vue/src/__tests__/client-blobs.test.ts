import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { VaultClient } from '../client'

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

function binaryResponse(data: ArrayBuffer, headers: Record<string, string> = {}) {
  return new Response(data, {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      ...headers,
    },
  })
}

describe('VaultClient — Blobs', () => {
  let client: VaultClient

  beforeEach(() => {
    client = new VaultClient('https://vault42.example.com')
    client.accessToken = 'test-token'
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('listBlobs', () => {
    it('lists blobs with quota', async () => {
      const listResult = {
        blobs: [
          { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
        ],
        count: 1,
        quota: { used_bytes: 800, max_bytes: 10485760, used_count: 1, max_count: 50 },
      }
      mockFetch.mockResolvedValueOnce(jsonResponse(listResult))

      const result = await client.listBlobs()

      expect(result.blobs).toHaveLength(1)
      expect(result.blobs[0].id).toBe('blob-1')
      expect(result.quota.max_bytes).toBe(10485760)
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/blobs')
      expect(init.method).toBe('GET')
    })

    it('returns empty list', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ blobs: [], count: 0, quota: { used_bytes: 0, max_bytes: 10485760, used_count: 0, max_count: 50 } }))

      const result = await client.listBlobs()
      expect(result.blobs).toHaveLength(0)
      expect(result.count).toBe(0)
    })

    it('throws on error', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      await expect(client.listBlobs()).rejects.toMatchObject({
        code: 'internal_error',
        status: 500,
      })
    })
  })

  describe('uploadBlob', () => {
    it('uploads raw data with label', async () => {
      const uploadResult = {
        id: 'blob-1',
        label: 'test.bin',
        size_bytes: 1024,
        stored_bytes: 800,
        checksum: 'sha256:abc',
        created_at: '2026-02-24T10:00:00Z',
      }
      mockFetch.mockResolvedValueOnce(jsonResponse(uploadResult, 201))

      const data = new ArrayBuffer(1024)
      const result = await client.uploadBlob(data, 'test.bin')

      expect(result.id).toBe('blob-1')
      expect(result.label).toBe('test.bin')
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/blobs')
      expect(init.method).toBe('POST')
      expect(init.headers['X-Blob-Label']).toBe('test.bin')
      expect(init.headers.Authorization).toBe('Bearer test-token')
    })

    it('uploads without label', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'blob-2', label: '', size_bytes: 512, stored_bytes: 400, checksum: 'sha256:def', created_at: '2026-02-24T10:00:00Z' }, 201))

      const data = new ArrayBuffer(512)
      await client.uploadBlob(data)

      const [, init] = mockFetch.mock.calls[0]
      expect(init.headers['X-Blob-Label']).toBeUndefined()
    })

    it('uploads Blob type', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'blob-3', label: '', size_bytes: 100, stored_bytes: 80, checksum: 'sha256:ghi', created_at: '2026-02-24T10:00:00Z' }, 201))

      const blob = new Blob(['hello world'])
      await client.uploadBlob(blob, 'hello.txt')

      const [, init] = mockFetch.mock.calls[0]
      expect(init.body).toBe(blob)
    })

    it('throws on quota_exceeded', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('quota_exceeded', 409))

      await expect(
        client.uploadBlob(new ArrayBuffer(1024), 'big.bin'),
      ).rejects.toMatchObject({ code: 'quota_exceeded', status: 409 })
    })

    it('throws on blob_too_large', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('blob_too_large', 413))

      await expect(
        client.uploadBlob(new ArrayBuffer(1024)),
      ).rejects.toMatchObject({ code: 'blob_too_large', status: 413 })
    })

    it('throws on blob_too_small', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('blob_too_small', 400))

      await expect(
        client.uploadBlob(new ArrayBuffer(100)),
      ).rejects.toMatchObject({ code: 'blob_too_small', status: 400 })
    })
  })

  describe('downloadBlob', () => {
    it('downloads blob with label and checksum', async () => {
      const binaryData = new Uint8Array([1, 2, 3, 4, 5]).buffer
      mockFetch.mockResolvedValueOnce(binaryResponse(binaryData, {
        'X-Blob-Label': 'doc.pdf',
        'X-Blob-Checksum': 'sha256:abc',
      }))

      const result = await client.downloadBlob('blob-1')

      expect(result.data.byteLength).toBe(5)
      expect(result.label).toBe('doc.pdf')
      expect(result.checksum).toBe('sha256:abc')
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/blobs/blob-1')
      expect(init.method).toBe('GET')
    })

    it('downloads blob without label', async () => {
      const binaryData = new Uint8Array([10, 20]).buffer
      mockFetch.mockResolvedValueOnce(binaryResponse(binaryData, {
        'X-Blob-Checksum': 'sha256:xyz',
      }))

      const result = await client.downloadBlob('blob-2')
      expect(result.label).toBeUndefined()
      expect(result.checksum).toBe('sha256:xyz')
    })

    it('throws on not found', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))

      await expect(client.downloadBlob('nonexistent')).rejects.toMatchObject({
        code: 'blob_not_found',
        status: 404,
      })
    })
  })

  describe('deleteBlob', () => {
    it('deletes a blob', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'deleted' }))

      const result = await client.deleteBlob('blob-1')

      expect(result.status).toBe('deleted')
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/blobs/blob-1')
      expect(init.method).toBe('DELETE')
    })

    it('throws on not found', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))

      await expect(client.deleteBlob('nonexistent')).rejects.toMatchObject({
        code: 'blob_not_found',
        status: 404,
      })
    })
  })
})
