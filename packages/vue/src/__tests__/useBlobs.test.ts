import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { useBlobs } from '../composables/useBlobs'
import { createVaultPlugin } from '../plugin'

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
    headers: { 'Content-Type': 'application/octet-stream', ...headers },
  })
}

const sampleBlob = { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' }
const sampleQuota = { used_bytes: 800, max_bytes: 10485760, used_count: 1, max_count: 50 }
const sampleListResult = { blobs: [sampleBlob], count: 1, quota: sampleQuota }

function mountComposable() {
  let composable!: ReturnType<typeof useBlobs>

  const TestComponent = defineComponent({
    setup() {
      composable = useBlobs()
      return () => h('div')
    },
  })

  const plugin = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
  const wrapper = mount(TestComponent, {
    global: { plugins: [plugin] },
  })

  return { wrapper, composable }
}

describe('useBlobs', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('initializes with empty defaults', () => {
    const { composable } = mountComposable()

    expect(composable.blobs.value).toEqual([])
    expect(composable.quota.value).toBeNull()
    expect(composable.isLoading.value).toBe(false)
    expect(composable.isUploading.value).toBe(false)
    expect(composable.error.value).toBeNull()
  })

  describe('fetchBlobs', () => {
    it('fetches blobs and quota', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleListResult))

      const { composable } = mountComposable()
      await composable.fetchBlobs()

      expect(composable.blobs.value).toHaveLength(1)
      expect(composable.blobs.value[0].id).toBe('blob-1')
      expect(composable.quota.value).toEqual(sampleQuota)
      expect(composable.isLoading.value).toBe(false)
    })

    it('handles empty list', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ blobs: [], count: 0, quota: sampleQuota }))

      const { composable } = mountComposable()
      await composable.fetchBlobs()

      expect(composable.blobs.value).toEqual([])
    })

    it('handles missing blobs array', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ count: 0, quota: sampleQuota }))

      const { composable } = mountComposable()
      await composable.fetchBlobs()

      expect(composable.blobs.value).toEqual([])
    })

    it('sets isLoading during fetch', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))

      const { composable } = mountComposable()
      const promise = composable.fetchBlobs()

      expect(composable.isLoading.value).toBe(true)

      resolvePromise(jsonResponse(sampleListResult))
      await promise

      expect(composable.isLoading.value).toBe(false)
    })

    it('sets error on failure', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      const { composable } = mountComposable()
      await composable.fetchBlobs()

      expect(composable.error.value).not.toBeNull()
      expect(composable.error.value!.code).toBe('internal_error')
    })
  })

  describe('uploadBlob', () => {
    it('uploads and re-fetches list', async () => {
      // Upload response
      mockFetch.mockResolvedValueOnce(jsonResponse({
        id: 'blob-new', label: 'test.bin', size_bytes: 512, stored_bytes: 400, checksum: 'sha256:new', created_at: '2026-02-24T11:00:00Z',
      }, 201))
      // Re-fetch list after upload
      mockFetch.mockResolvedValueOnce(jsonResponse({
        blobs: [sampleBlob, { id: 'blob-new', label: 'test.bin', size_bytes: 512, stored_bytes: 400, checksum: 'sha256:new', created_at: '2026-02-24T11:00:00Z' }],
        count: 2,
        quota: { ...sampleQuota, used_count: 2, used_bytes: 1200 },
      }))

      const { composable } = mountComposable()
      const result = await composable.uploadBlob(new ArrayBuffer(512), 'test.bin')

      expect(result).toBe(true)
      expect(composable.blobs.value).toHaveLength(2)
      expect(composable.isUploading.value).toBe(false)
    })

    it('returns false on error', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('quota_exceeded', 409))

      const { composable } = mountComposable()
      const result = await composable.uploadBlob(new ArrayBuffer(1024))

      expect(result).toBe(false)
      expect(composable.error.value!.code).toBe('quota_exceeded')
    })

    it('sets isUploading during upload', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))

      const { composable } = mountComposable()
      const promise = composable.uploadBlob(new ArrayBuffer(512))

      expect(composable.isUploading.value).toBe(true)

      // Resolve upload, then re-fetch
      resolvePromise(jsonResponse({ id: 'blob-new', label: '', size_bytes: 512, stored_bytes: 400, checksum: 'sha256:new', created_at: '2026-02-24T11:00:00Z' }, 201))
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleListResult))
      await promise

      expect(composable.isUploading.value).toBe(false)
    })
  })

  describe('downloadBlob', () => {
    it('downloads blob data', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]).buffer
      mockFetch.mockResolvedValueOnce(binaryResponse(data, {
        'X-Blob-Label': 'doc.pdf',
        'X-Blob-Checksum': 'sha256:abc',
      }))

      const { composable } = mountComposable()
      const result = await composable.downloadBlob('blob-1')

      expect(result).not.toBeNull()
      expect(result!.data.byteLength).toBe(5)
      expect(result!.label).toBe('doc.pdf')
    })

    it('returns null on error', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))

      const { composable } = mountComposable()
      const result = await composable.downloadBlob('nonexistent')

      expect(result).toBeNull()
      expect(composable.error.value!.code).toBe('blob_not_found')
    })
  })

  describe('deleteBlob', () => {
    it('deletes and removes from local list', async () => {
      // First populate the list
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleListResult))
      const { composable } = mountComposable()
      await composable.fetchBlobs()
      expect(composable.blobs.value).toHaveLength(1)

      // Delete
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'deleted' }))
      const result = await composable.deleteBlob('blob-1')

      expect(result).toBe(true)
      expect(composable.blobs.value).toHaveLength(0)
    })

    it('returns false on error', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))

      const { composable } = mountComposable()
      const result = await composable.deleteBlob('nonexistent')

      expect(result).toBe(false)
      expect(composable.error.value!.code).toBe('blob_not_found')
    })

    it('clears previous error on new operation', async () => {
      // Cause an error first
      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))
      const { composable } = mountComposable()
      await composable.deleteBlob('bad-id')
      expect(composable.error.value).not.toBeNull()

      // Successful delete clears error
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'deleted' }))
      await composable.deleteBlob('good-id')
      expect(composable.error.value).toBeNull()
    })
  })
})
