import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { useIdentity } from '../composables/useIdentity'
import { createVaultPlugin } from '../plugin'

// Mock fetch globally
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

/** Helper: mount a component that uses the composable inside a plugin context */
function mountComposable() {
  let composable!: ReturnType<typeof useIdentity>

  const TestComponent = defineComponent({
    setup() {
      composable = useIdentity()
      return () => h('div')
    },
  })

  const plugin = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
  const wrapper = mount(TestComponent, {
    global: { plugins: [plugin] },
  })

  return { wrapper, composable }
}

describe('useIdentity', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('initializes with null/false defaults', () => {
    const { composable } = mountComposable()

    expect(composable.identity.value).toBeNull()
    expect(composable.isLoading.value).toBe(false)
    expect(composable.isSaving.value).toBe(false)
    expect(composable.error.value).toBeNull()
  })

  describe('fetchIdentity', () => {
    it('fetches and stores identity', async () => {
      const identity = { given_name: 'Jane', family_name: 'Doe', country: 'US', updated_at: '2026-02-24T10:00:00Z' }
      mockFetch.mockResolvedValueOnce(jsonResponse(identity))

      const { composable } = mountComposable()

      await composable.fetchIdentity()

      expect(composable.identity.value).toEqual(identity)
      expect(composable.isLoading.value).toBe(false)
      expect(composable.error.value).toBeNull()
    })

    it('sets isLoading during fetch', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))

      const { composable } = mountComposable()
      const fetchPromise = composable.fetchIdentity()

      expect(composable.isLoading.value).toBe(true)

      resolvePromise(jsonResponse({ given_name: 'Jane' }))
      await fetchPromise

      expect(composable.isLoading.value).toBe(false)
    })

    it('handles 404 gracefully (no identity)', async () => {
      // Start from a loaded identity so the 404 has something to clear: a
      // "no identity yet" 404 must reset the ref, not leave stale data on screen.
      mockFetch.mockResolvedValueOnce(jsonResponse({ given_name: 'Jane', country: 'US' }))
      const { composable } = mountComposable()
      await composable.fetchIdentity()
      expect(composable.identity.value).not.toBeNull()

      mockFetch.mockResolvedValueOnce(errorResponse('identity_not_found', 404))
      await composable.fetchIdentity()

      expect(composable.identity.value).toBeNull()
      expect(composable.error.value).toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('sets error on non-404 errors', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      const { composable } = mountComposable()
      await composable.fetchIdentity()

      expect(composable.error.value).not.toBeNull()
      expect(composable.error.value!.code).toBe('internal_error')
    })
  })

  describe('saveIdentity', () => {
    it('saves and returns true on success', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'updated' }))

      const { composable } = mountComposable()
      const result = await composable.saveIdentity({ given_name: 'Jane', country: 'US' })

      expect(result).toBe(true)
      expect(composable.identity.value).toMatchObject({ given_name: 'Jane', country: 'US' })
      expect(composable.isSaving.value).toBe(false)
    })

    it('merges with existing identity', async () => {
      // First fetch existing identity
      mockFetch.mockResolvedValueOnce(jsonResponse({ given_name: 'Jane', family_name: 'Doe', country: 'US' }))
      const { composable } = mountComposable()
      await composable.fetchIdentity()

      // Then save partial update
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'updated' }))
      await composable.saveIdentity({ family_name: 'Smith' })

      expect(composable.identity.value).toMatchObject({
        given_name: 'Jane',
        family_name: 'Smith',
        country: 'US',
      })
    })

    it('returns false and sets error on failure', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_country', 400))

      const { composable } = mountComposable()
      const result = await composable.saveIdentity({ country: 'XX' })

      expect(result).toBe(false)
      expect(composable.error.value!.code).toBe('invalid_country')
    })

    it('sets isSaving during save', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))

      const { composable } = mountComposable()
      const savePromise = composable.saveIdentity({ given_name: 'Jane' })

      expect(composable.isSaving.value).toBe(true)

      resolvePromise(jsonResponse({ status: 'updated' }))
      await savePromise

      expect(composable.isSaving.value).toBe(false)
    })
  })

  describe('deleteIdentity', () => {
    it('deletes and clears identity', async () => {
      // Set up existing identity
      mockFetch.mockResolvedValueOnce(jsonResponse({ given_name: 'Jane' }))
      const { composable } = mountComposable()
      await composable.fetchIdentity()
      expect(composable.identity.value).not.toBeNull()

      // Delete
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'deleted' }))
      const result = await composable.deleteIdentity()

      expect(result).toBe(true)
      expect(composable.identity.value).toBeNull()
    })

    it('returns false on error', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      const { composable } = mountComposable()
      const result = await composable.deleteIdentity()

      expect(result).toBe(false)
      expect(composable.error.value!.code).toBe('internal_error')
    })
  })
})
