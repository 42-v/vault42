import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { useProfile } from '../composables/useProfile'
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

function errorResponse(error: string, status: number) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const sampleProfile = {
  id: 'u1',
  email: 'jane@example.com',
  email_verified: true,
  display_name: 'Jane',
  avatar_url: '',
  locale: 'en',
  mfa_required: false,
  mfa_enabled: true,
  mfa_methods: ['totp'],
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-02-24T10:00:00Z',
}

function mountComposable() {
  let composable!: ReturnType<typeof useProfile>
  let client!: VaultClient

  const TestComponent = defineComponent({
    setup() {
      client = useVaultClient()
      composable = useProfile()
      return () => h('div')
    },
  })

  const plugin = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
  const wrapper = mount(TestComponent, {
    global: { plugins: [plugin] },
  })

  return { wrapper, composable, client }
}

describe('useProfile', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('initializes with no profile and no error', () => {
    const { composable } = mountComposable()

    expect(composable.profile.value).toBeNull()
    expect(composable.isLoading.value).toBe(false)
    expect(composable.error.value).toBeNull()
  })

  describe('fetchProfile', () => {
    it('GETs /user/profile with credentials and stores the result', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleProfile))

      const { composable } = mountComposable()
      await composable.fetchProfile()

      expect(mockFetch).toHaveBeenCalledOnce()
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/profile')
      expect(init.method).toBe('GET')
      expect(init.credentials).toBe('include')
      expect(init.headers['X-Requested-With']).toBe('XMLHttpRequest')
      expect(composable.profile.value).toEqual(sampleProfile)
      expect(composable.error.value).toBeNull()
    })

    it('sets isLoading for the duration of the request', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))

      const { composable } = mountComposable()
      const promise = composable.fetchProfile()

      expect(composable.isLoading.value).toBe(true)

      resolvePromise(jsonResponse(sampleProfile))
      await promise

      expect(composable.isLoading.value).toBe(false)
    })

    it('leaves the profile null and records the error code on a 500', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      const { composable } = mountComposable()
      await composable.fetchProfile()

      expect(composable.profile.value).toBeNull()
      expect(composable.error.value).toMatchObject({ code: 'internal_error', status: 500 })
      expect(composable.isLoading.value).toBe(false)
    })

    it('reports unknown_error when the body is not JSON', async () => {
      mockFetch.mockResolvedValueOnce(new Response('<html>502 Bad Gateway</html>', { status: 502 }))

      const { composable } = mountComposable()
      await composable.fetchProfile()

      expect(composable.profile.value).toBeNull()
      expect(composable.error.value).toMatchObject({ code: 'unknown_error', status: 502 })
    })

    it('records the error and stops loading when fetch itself throws', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))

      const { composable } = mountComposable()
      await composable.fetchProfile()

      expect(composable.profile.value).toBeNull()
      expect(composable.error.value).not.toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('does not clobber the loaded profile when a later refetch fails', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleProfile))
      const { composable } = mountComposable()
      await composable.fetchProfile()

      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))
      await composable.fetchProfile()

      expect(composable.profile.value).toEqual(sampleProfile)
      expect(composable.error.value!.code).toBe('internal_error')
    })

    it('clears a previous error on the next successful fetch', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))
      const { composable } = mountComposable()
      await composable.fetchProfile()
      expect(composable.error.value).not.toBeNull()

      mockFetch.mockResolvedValueOnce(jsonResponse(sampleProfile))
      await composable.fetchProfile()

      expect(composable.error.value).toBeNull()
      expect(composable.profile.value).toEqual(sampleProfile)
    })

    it('replaces the whole profile rather than merging into the stale one', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleProfile))
      const { composable } = mountComposable()
      await composable.fetchProfile()

      mockFetch.mockResolvedValueOnce(jsonResponse({ ...sampleProfile, mfa_enabled: false, mfa_methods: [] }))
      await composable.fetchProfile()

      expect(composable.profile.value!.mfa_enabled).toBe(false)
      expect(composable.profile.value!.mfa_methods).toEqual([])
    })
  })

  describe('mid-flight 401', () => {
    it('refreshes once and retries the profile request', async () => {
      const { composable, client } = mountComposable()
      client.accessToken = 'expired-tok'

      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'fresh-tok', token_type: 'Bearer', expires_in: 900 }))
      mockFetch.mockResolvedValueOnce(jsonResponse(sampleProfile))

      await composable.fetchProfile()

      expect(mockFetch).toHaveBeenCalledTimes(3)
      expect(mockFetch.mock.calls[1][0]).toBe('https://vault42.example.com/auth/refresh')
      expect(mockFetch.mock.calls[2][1].headers.Authorization).toBe('Bearer fresh-tok')
      expect(client.accessToken).toBe('fresh-tok')
      expect(composable.profile.value).toEqual(sampleProfile)
      expect(composable.error.value).toBeNull()
    })

    it('drops the access token and surfaces session_expired when the refresh fails', async () => {
      const { composable, client } = mountComposable()
      client.accessToken = 'expired-tok'

      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_refresh', 401))

      await composable.fetchProfile()

      expect(client.accessToken).toBeNull()
      expect(composable.error.value).toMatchObject({ code: 'session_expired', status: 401 })
      expect(composable.profile.value).toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('does not attempt a refresh when there is no access token', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))

      const { composable } = mountComposable()
      await composable.fetchProfile()

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(composable.error.value).toMatchObject({ code: 'unauthorized', status: 401 })
      expect(composable.profile.value).toBeNull()
    })
  })

  it('shares one refresh between two composables racing the same 401', async () => {
    const plugin = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
    let a!: ReturnType<typeof useProfile>
    let b!: ReturnType<typeof useProfile>
    let client!: VaultClient

    const TestComponent = defineComponent({
      setup() {
        client = useVaultClient()
        a = useProfile()
        b = useProfile()
        return () => h('div')
      },
    })
    mount(TestComponent, { global: { plugins: [plugin] } })
    client.accessToken = 'expired-tok'

    mockFetch.mockImplementation((url: string) => {
      if (url.endsWith('/auth/refresh')) {
        return Promise.resolve(jsonResponse({ access_token: 'fresh-tok', token_type: 'Bearer', expires_in: 900 }))
      }
      return Promise.resolve(
        client.accessToken === 'fresh-tok'
          ? jsonResponse(sampleProfile)
          : errorResponse('unauthorized', 401),
      )
    })

    await Promise.all([a.fetchProfile(), b.fetchProfile()])

    const refreshCalls = mockFetch.mock.calls.filter((c) => String(c[0]).endsWith('/auth/refresh'))
    expect(refreshCalls).toHaveLength(1)
    expect(a.profile.value).toEqual(sampleProfile)
    expect(b.profile.value).toEqual(sampleProfile)
  })
})
