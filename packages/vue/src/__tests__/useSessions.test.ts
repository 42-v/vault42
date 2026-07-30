import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { useSessions } from '../composables/useSessions'
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

const sessionA = {
  id: 'sess-a',
  friendly_name: 'This laptop',
  ip: '10.0.0.1',
  user_agent: 'Firefox',
  trusted: true,
  first_seen_at: '2026-01-01T00:00:00Z',
}
const sessionB = {
  id: 'sess-b',
  friendly_name: 'Old phone',
  ip: '10.0.0.2',
  user_agent: 'Safari',
  trusted: false,
  first_seen_at: '2026-02-01T00:00:00Z',
}
const deviceA = {
  id: 'sess-a',
  friendly_name: 'This laptop',
  trusted: true,
  ip: '10.0.0.1',
  user_agent: 'Firefox',
  first_seen_at: '2026-01-01T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
}
const deviceB = {
  id: 'sess-b',
  friendly_name: 'Old phone',
  trusted: false,
  ip: '10.0.0.2',
  user_agent: 'Safari',
  first_seen_at: '2026-02-01T00:00:00Z',
  created_at: '2026-02-01T00:00:00Z',
}

function mountComposable() {
  let composable!: ReturnType<typeof useSessions>
  let client!: VaultClient

  const TestComponent = defineComponent({
    setup() {
      client = useVaultClient()
      composable = useSessions()
      return () => h('div')
    },
  })

  const plugin = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
  const wrapper = mount(TestComponent, {
    global: { plugins: [plugin] },
  })

  return { wrapper, composable, client }
}

/** Load both lists with sessionA/sessionB and deviceA/deviceB, then reset the fetch mock. */
async function withLoadedLists() {
  const ctx = mountComposable()
  mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: [sessionA, sessionB] }))
  await ctx.composable.fetchSessions()
  mockFetch.mockResolvedValueOnce(jsonResponse({ devices: [deviceA, deviceB] }))
  await ctx.composable.fetchDevices()
  mockFetch.mockReset()
  return ctx
}

describe('useSessions', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('initializes with empty lists and no error', () => {
    const { composable } = mountComposable()

    expect(composable.sessions.value).toEqual([])
    expect(composable.devices.value).toEqual([])
    expect(composable.isLoading.value).toBe(false)
    expect(composable.error.value).toBeNull()
  })

  describe('fetchSessions', () => {
    it('GETs /user/sessions and stores the unwrapped array', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: [sessionA, sessionB] }))

      const { composable } = mountComposable()
      await composable.fetchSessions()

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/sessions')
      expect(init.method).toBe('GET')
      expect(composable.sessions.value).toEqual([sessionA, sessionB])
      expect(composable.isLoading.value).toBe(false)
      expect(composable.error.value).toBeNull()
    })

    it('treats a null sessions field as an empty list', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: null }))
      await composable.fetchSessions()

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(composable.sessions.value).toEqual([])
      expect(composable.error.value).toBeNull()
    })

    it('preserves server-side session fields the SDK type does not declare', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: [{ ...sessionA, current: true }, sessionB] }))

      const { composable } = mountComposable()
      await composable.fetchSessions()

      expect(composable.sessions.value[0]).toMatchObject({ id: 'sess-a', current: true })
      expect(composable.sessions.value[1]).not.toHaveProperty('current')
    })

    it('sets isLoading for the duration of the request', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))

      const { composable } = mountComposable()
      const promise = composable.fetchSessions()

      expect(composable.isLoading.value).toBe(true)

      resolvePromise(jsonResponse({ sessions: [] }))
      await promise

      expect(composable.isLoading.value).toBe(false)
    })

    it('records the error code and leaves the list empty on a 500', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      const { composable } = mountComposable()
      await composable.fetchSessions()

      expect(composable.sessions.value).toEqual([])
      expect(composable.error.value).toMatchObject({ code: 'internal_error', status: 500 })
      expect(composable.isLoading.value).toBe(false)
    })

    it('reports unknown_error when the body is not JSON', async () => {
      mockFetch.mockResolvedValueOnce(new Response('gateway timeout', { status: 504 }))

      const { composable } = mountComposable()
      await composable.fetchSessions()

      expect(composable.error.value).toMatchObject({ code: 'unknown_error', status: 504 })
    })

    it('records the error and stops loading when fetch itself throws', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))

      const { composable } = mountComposable()
      await composable.fetchSessions()

      expect(composable.sessions.value).toEqual([])
      expect(composable.error.value).not.toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('keeps the previously loaded list when a refetch fails', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))
      await composable.fetchSessions()

      expect(composable.sessions.value).toEqual([sessionA, sessionB])
      expect(composable.error.value!.code).toBe('internal_error')
    })
  })

  describe('revokeSession', () => {
    it('DELETEs the session then refetches both sessions and devices', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(emptyResponse())
      mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: [sessionA] }))
      mockFetch.mockResolvedValueOnce(jsonResponse({ devices: [deviceA] }))

      await composable.revokeSession('sess-b')

      expect(mockFetch).toHaveBeenCalledTimes(3)
      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/user/sessions/sess-b')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
      expect(mockFetch.mock.calls[1][0]).toBe('https://vault42.example.com/user/sessions')
      expect(mockFetch.mock.calls[2][0]).toBe('https://vault42.example.com/user/devices')
      expect(composable.sessions.value).toEqual([sessionA])
      expect(composable.devices.value).toEqual([deviceA])
      expect(composable.error.value).toBeNull()
    })

    it('leaves both lists untouched when the revoke is rejected', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(errorResponse('session_not_found', 404))
      await composable.revokeSession('sess-b')

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(composable.sessions.value).toEqual([sessionA, sessionB])
      expect(composable.devices.value).toEqual([deviceA, deviceB])
      expect(composable.error.value).toMatchObject({ code: 'session_not_found', status: 404 })
    })

    it('does not remove the row optimistically before the server confirms', async () => {
      const { composable } = await withLoadedLists()

      let resolveDelete!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolveDelete = r }))

      const promise = composable.revokeSession('sess-b')
      expect(composable.sessions.value).toEqual([sessionA, sessionB])

      resolveDelete(errorResponse('internal_error', 500))
      await promise

      expect(composable.sessions.value).toEqual([sessionA, sessionB])
    })

    it('refuses a path-traversal id without issuing any request', async () => {
      const { composable } = await withLoadedLists()

      await composable.revokeSession('../../admin/users')

      expect(mockFetch).not.toHaveBeenCalled()
      expect(composable.error.value).not.toBeNull()
      expect(composable.sessions.value).toEqual([sessionA, sessionB])
    })

    it('surfaces the refetch failure when the revoke itself succeeded', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(emptyResponse())
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))
      mockFetch.mockResolvedValueOnce(jsonResponse({ devices: [deviceA] }))

      await composable.revokeSession('sess-b')

      expect(composable.error.value).toMatchObject({ code: 'internal_error', status: 500 })
      expect(composable.sessions.value).toEqual([sessionA, sessionB])
    })

    it('refreshes once and retries when the DELETE hits a 401', async () => {
      const { composable, client } = await withLoadedLists()
      client.accessToken = 'expired-tok'

      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      mockFetch.mockResolvedValueOnce(jsonResponse({ access_token: 'fresh-tok', token_type: 'Bearer', expires_in: 900 }))
      mockFetch.mockResolvedValueOnce(emptyResponse())
      mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: [sessionA] }))
      mockFetch.mockResolvedValueOnce(jsonResponse({ devices: [deviceA] }))

      await composable.revokeSession('sess-b')

      expect(mockFetch.mock.calls[1][0]).toBe('https://vault42.example.com/auth/refresh')
      expect(mockFetch.mock.calls[2][1].headers.Authorization).toBe('Bearer fresh-tok')
      expect(client.accessToken).toBe('fresh-tok')
      expect(composable.sessions.value).toEqual([sessionA])
      expect(composable.error.value).toBeNull()
    })

    it('drops the token and leaves the list intact when the refresh fails', async () => {
      const { composable, client } = await withLoadedLists()
      client.accessToken = 'expired-tok'

      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_refresh', 401))

      await composable.revokeSession('sess-b')

      expect(client.accessToken).toBeNull()
      expect(composable.error.value).toMatchObject({ code: 'session_expired', status: 401 })
      expect(composable.sessions.value).toEqual([sessionA, sessionB])
      expect(composable.devices.value).toEqual([deviceA, deviceB])
    })
  })

  describe('revokeAllSessions', () => {
    it('DELETEs the collection and clears both local lists', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(emptyResponse())
      await composable.revokeAllSessions()

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/user/sessions')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
      expect(composable.sessions.value).toEqual([])
      expect(composable.devices.value).toEqual([])
      expect(composable.error.value).toBeNull()
    })

    it('keeps both lists when the server refuses', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))
      await composable.revokeAllSessions()

      expect(composable.sessions.value).toEqual([sessionA, sessionB])
      expect(composable.devices.value).toEqual([deviceA, deviceB])
      expect(composable.error.value).toMatchObject({ code: 'internal_error', status: 500 })
    })

    it('keeps both lists when the network throws', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))
      await composable.revokeAllSessions()

      expect(composable.sessions.value).toEqual([sessionA, sessionB])
      expect(composable.devices.value).toEqual([deviceA, deviceB])
      expect(composable.error.value).not.toBeNull()
    })
  })

  describe('fetchDevices', () => {
    it('GETs /user/devices and stores the unwrapped array', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ devices: [deviceA] }))

      const { composable } = mountComposable()
      await composable.fetchDevices()

      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/user/devices')
      expect(composable.devices.value).toEqual([deviceA])
    })

    it('treats a null devices field as an empty list', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(jsonResponse({ devices: null }))
      await composable.fetchDevices()

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(composable.devices.value).toEqual([])
      expect(composable.error.value).toBeNull()
    })

    it('records the error code on failure', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      const { composable } = mountComposable()
      await composable.fetchDevices()

      expect(composable.devices.value).toEqual([])
      expect(composable.error.value).toMatchObject({ code: 'internal_error', status: 500 })
    })
  })

  describe('renameDevice', () => {
    it('PATCHes friendly_name and updates only the matching row', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(emptyResponse())
      await composable.renameDevice('sess-b', 'Work phone')

      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/devices/sess-b')
      expect(init.method).toBe('PATCH')
      expect(JSON.parse(init.body)).toEqual({ friendly_name: 'Work phone' })
      expect(composable.devices.value[1].friendly_name).toBe('Work phone')
      expect(composable.devices.value[0].friendly_name).toBe('This laptop')
    })

    it('keeps the old name when the rename fails', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(errorResponse('device_not_found', 404))
      await composable.renameDevice('sess-b', 'Work phone')

      expect(composable.devices.value[1].friendly_name).toBe('Old phone')
      expect(composable.error.value).toMatchObject({ code: 'device_not_found', status: 404 })
    })

    it('is a no-op locally when the id is not in the loaded list', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(emptyResponse())
      await composable.renameDevice('sess-unknown', 'Ghost')

      expect(composable.devices.value.map((d) => d.friendly_name)).toEqual(['This laptop', 'Old phone'])
      expect(composable.error.value).toBeNull()
    })
  })

  describe('removeDevice', () => {
    it('DELETEs the device then refetches both lists', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(emptyResponse())
      mockFetch.mockResolvedValueOnce(jsonResponse({ sessions: [sessionA] }))
      mockFetch.mockResolvedValueOnce(jsonResponse({ devices: [deviceA] }))

      await composable.removeDevice('sess-b')

      expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/user/devices/sess-b')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
      expect(composable.sessions.value).toEqual([sessionA])
      expect(composable.devices.value).toEqual([deviceA])
    })

    it('leaves both lists untouched when the removal fails', async () => {
      const { composable } = await withLoadedLists()

      mockFetch.mockResolvedValueOnce(errorResponse('device_not_found', 404))
      await composable.removeDevice('sess-b')

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(composable.sessions.value).toEqual([sessionA, sessionB])
      expect(composable.devices.value).toEqual([deviceA, deviceB])
      expect(composable.error.value).toMatchObject({ code: 'device_not_found', status: 404 })
    })

    it('refuses a path-traversal id without issuing any request', async () => {
      const { composable } = await withLoadedLists()

      await composable.removeDevice('sess-b/../../admin')

      expect(mockFetch).not.toHaveBeenCalled()
      expect(composable.devices.value).toEqual([deviceA, deviceB])
    })
  })
})
