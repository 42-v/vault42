import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { useBlobs } from '../composables/useBlobs'
import { createVaultPlugin } from '../plugin'

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

function binaryResponse(data: ArrayBuffer, headers: Record<string, string> = {}) {
  return new Response(data, {
    status: 200,
    headers: { 'Content-Type': 'application/octet-stream', ...headers },
  })
}

const sampleBlob = { id: 'avatar', label: 'avatar', size_bytes: 4, stored_bytes: 4, checksum: 'sha256:c', created_at: '2026-02-24T10:00:00Z' }
const sampleQuota = { used_bytes: 4, max_bytes: 10485760, used_count: 1, max_count: 50 }
const sampleListResult = { blobs: [sampleBlob], count: 1, quota: sampleQuota }

function mountComposable() {
  let composable!: ReturnType<typeof useBlobs>

  const TestComponent = defineComponent({
    setup() {
      composable = useBlobs()
      return () => h('div')
    },
  })

  const wrapper = mount(TestComponent, {
    global: { plugins: [createVaultPlugin({ baseURL: BASE })] },
  })

  return { wrapper, composable }
}

describe('useBlobs — named blobs', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('uploadNamedBlob', () => {
    it('PUTs to the named path and refreshes the list from the server', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleBlob))
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleListResult))

      const { composable } = mountComposable()
      const result = await composable.uploadNamedBlob('avatar', new Uint8Array([1, 2, 3, 4]))

      expect(result).toBe(true)
      const [uploadURL, uploadInit] = mockFetch.mock.calls[0]
      expect(uploadURL).toBe(`${BASE}/user/blobs/named/avatar`)
      expect(uploadInit.method).toBe('PUT')
      expect((uploadInit.body as Blob).size).toBe(4)
      expect(mockFetch.mock.calls[1][0]).toBe(`${BASE}/user/blobs`)
      expect(composable.blobs.value).toEqual([sampleBlob])
      expect(composable.quota.value).toEqual(sampleQuota)
      expect(composable.error.value).toBeNull()
      expect(composable.isUploading.value).toBe(false)
    })

    it('returns false and leaves the cached list untouched when the upload is rejected', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleListResult))
      const { composable } = mountComposable()
      await composable.fetchBlobs()

      mockFetch.mockResolvedValueOnce(errorResponse('quota_exceeded', 409))
      const result = await composable.uploadNamedBlob('avatar', new Uint8Array([1, 2]))

      expect(result).toBe(false)
      expect(composable.error.value!.code).toBe('quota_exceeded')
      expect(composable.error.value!.status).toBe(409)
      expect(composable.blobs.value).toEqual([sampleBlob])
      expect(composable.isUploading.value).toBe(false)
      expect(mockFetch).toHaveBeenCalledTimes(2)
    })

    it('reports success but surfaces the error when only the follow-up list refresh fails', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleBlob))
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      const { composable } = mountComposable()
      const result = await composable.uploadNamedBlob('avatar', new Uint8Array([1, 2, 3, 4]))

      expect(result).toBe(true)
      expect(composable.error.value!.code).toBe('internal_error')
      expect(composable.blobs.value).toEqual([])
      expect(composable.isLoading.value).toBe(false)
      expect(composable.isUploading.value).toBe(false)
    })

    it('refuses a traversal name without issuing a request and clears isUploading', async () => {
      const { composable } = mountComposable()

      const result = await composable.uploadNamedBlob('../../admin', new Uint8Array([1]))

      expect(result).toBe(false)
      expect(composable.error.value).toBeInstanceOf(Error)
      expect((composable.error.value as unknown as Error).message).toBe('Invalid resource ID')
      expect(mockFetch).not.toHaveBeenCalled()
      expect(composable.isUploading.value).toBe(false)
    })

    it('holds isUploading true for the whole upload-then-refresh sequence', async () => {
      let releaseUpload!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { releaseUpload = r }))

      const { composable } = mountComposable()
      const promise = composable.uploadNamedBlob('avatar', new Uint8Array([1, 2, 3, 4]))

      expect(composable.isUploading.value).toBe(true)

      mockFetch.mockResolvedValueOnce(jsonResponse(sampleListResult))
      releaseUpload(jsonResponse(sampleBlob))
      await promise

      expect(composable.isUploading.value).toBe(false)
    })
  })

  describe('downloadNamedBlob', () => {
    it('returns the bytes and the label header from the named path', async () => {
      mockFetch.mockResolvedValueOnce(binaryResponse(new Uint8Array([9, 9, 9]).buffer, {
        'X-Blob-Label': 'avatar.png',
      }))

      const { composable } = mountComposable()
      const result = await composable.downloadNamedBlob('avatar')

      expect(mockFetch.mock.calls[0][0]).toBe(`${BASE}/user/blobs/named/avatar`)
      expect(mockFetch.mock.calls[0][1].method).toBe('GET')
      expect(result!.data.byteLength).toBe(3)
      expect(result!.label).toBe('avatar.png')
      expect(composable.error.value).toBeNull()
    })

    it('returns null rather than partial data when the named download fails', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))

      const { composable } = mountComposable()
      const result = await composable.downloadNamedBlob('avatar')

      expect(result).toBeNull()
      expect(composable.error.value!.code).toBe('blob_not_found')
      expect(composable.error.value!.status).toBe(404)
    })

    it('clears a stale error before a successful download', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))
      const { composable } = mountComposable()
      await composable.downloadNamedBlob('missing')
      expect(composable.error.value).not.toBeNull()

      mockFetch.mockResolvedValueOnce(binaryResponse(new Uint8Array([1]).buffer))
      await composable.downloadNamedBlob('avatar')

      expect(composable.error.value).toBeNull()
    })

    it('refuses a traversal name without issuing a request', async () => {
      const { composable } = mountComposable()

      const result = await composable.downloadNamedBlob('..%2fadmin')

      expect(result).toBeNull()
      expect((composable.error.value as unknown as Error).message).toBe('Invalid resource ID')
      expect(mockFetch).not.toHaveBeenCalled()
    })
  })

  describe('deleteNamedBlob', () => {
    it('deletes then re-reads the list from the server instead of filtering locally', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleListResult))
      const { composable } = mountComposable()
      await composable.fetchBlobs()
      expect(composable.blobs.value).toHaveLength(1)

      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'deleted' }))
      mockFetch.mockResolvedValueOnce(jsonResponse({ blobs: [], count: 0, quota: { ...sampleQuota, used_bytes: 0, used_count: 0 } }))
      const result = await composable.deleteNamedBlob('avatar')

      expect(result).toBe(true)
      const [deleteURL, deleteInit] = mockFetch.mock.calls[1]
      expect(deleteURL).toBe(`${BASE}/user/blobs/named/avatar`)
      expect(deleteInit.method).toBe('DELETE')
      expect(mockFetch.mock.calls[2][0]).toBe(`${BASE}/user/blobs`)
      expect(composable.blobs.value).toEqual([])
      expect(composable.quota.value!.used_count).toBe(0)
    })

    it('returns false and keeps the entry cached when the delete is rejected', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleListResult))
      const { composable } = mountComposable()
      await composable.fetchBlobs()

      mockFetch.mockResolvedValueOnce(errorResponse('blob_not_found', 404))
      const result = await composable.deleteNamedBlob('avatar')

      expect(result).toBe(false)
      expect(composable.error.value!.code).toBe('blob_not_found')
      expect(composable.blobs.value).toEqual([sampleBlob])
      expect(mockFetch).toHaveBeenCalledTimes(2)
    })

    it('refuses a traversal name without issuing a request', async () => {
      const { composable } = mountComposable()

      const result = await composable.deleteNamedBlob('a/b')

      expect(result).toBe(false)
      expect((composable.error.value as unknown as Error).message).toBe('Invalid resource ID')
      expect(mockFetch).not.toHaveBeenCalled()
    })
  })
})
