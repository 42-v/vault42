import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { useConfirm } from '../composables/useConfirm'
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

function mountComposable() {
  let composable!: ReturnType<typeof useConfirm>

  const TestComponent = defineComponent({
    setup() {
      composable = useConfirm()
      return () => h('div')
    },
  })

  const plugin = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
  const wrapper = mount(TestComponent, {
    global: { plugins: [plugin] },
  })

  return { wrapper, composable }
}

describe('useConfirm', () => {
  beforeEach(() => {
    mockFetch.mockReset()
    // The confirmation grant is module-level state shared by every instance.
    mountComposable().composable.clearConfirmation()
  })

  afterEach(() => {
    mountComposable().composable.clearConfirmation()
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('starts with no confirmation grant', () => {
    const { composable } = mountComposable()

    expect(composable.isConfirmed()).toBe(false)
    expect(composable.confirmed.value).toBe(false)
    expect(composable.isLoading.value).toBe(false)
    expect(composable.error.value).toBeNull()
  })

  describe('confirm', () => {
    it('POSTs the password to /auth/confirm and opens the grant', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 300 }))

      const { composable } = mountComposable()
      const result = await composable.confirm('correct horse battery staple')

      expect(result).toBe(true)
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/auth/confirm')
      expect(init.method).toBe('POST')
      expect(init.credentials).toBe('include')
      expect(JSON.parse(init.body)).toEqual({ password: 'correct horse battery staple' })
      expect(composable.isConfirmed()).toBe(true)
      expect(composable.error.value).toBeNull()
    })

    it('sets isLoading for the duration of the request', async () => {
      let resolvePromise!: (value: Response) => void
      mockFetch.mockReturnValueOnce(new Promise<Response>((r) => { resolvePromise = r }))

      const { composable } = mountComposable()
      const promise = composable.confirm('pw')

      expect(composable.isLoading.value).toBe(true)

      resolvePromise(jsonResponse({ confirmed: true, expires_in: 300 }))
      await promise

      expect(composable.isLoading.value).toBe(false)
    })

    it('returns false and opens no grant when the server answers confirmed:false', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: false, expires_in: 300 }))

      const { composable } = mountComposable()
      const result = await composable.confirm('wrong-password')

      expect(mockFetch).toHaveBeenCalledOnce()
      expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({ password: 'wrong-password' })
      expect(result).toBe(false)
      expect(composable.confirmed.value).toBe(false)
      expect(composable.isConfirmed()).toBe(false)
      expect(composable.error.value).toBeNull()
    })

    it('fails closed on a 401 and records the error code', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_credentials', 401))

      const { composable } = mountComposable()
      const result = await composable.confirm('wrong-password')

      expect(result).toBe(false)
      expect(composable.isConfirmed()).toBe(false)
      expect(composable.error.value).toMatchObject({ code: 'invalid_credentials', status: 401 })
      expect(composable.isLoading.value).toBe(false)
    })

    it('fails closed when the network throws', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))

      const { composable } = mountComposable()
      const result = await composable.confirm('pw')

      expect(result).toBe(false)
      expect(composable.isConfirmed()).toBe(false)
      expect(composable.error.value).not.toBeNull()
      expect(composable.isLoading.value).toBe(false)
    })

    it('fails closed when the success body is not JSON', async () => {
      mockFetch.mockResolvedValueOnce(new Response('confirmed', { status: 200 }))

      const { composable } = mountComposable()
      const result = await composable.confirm('pw')

      expect(result).toBe(false)
      expect(composable.isConfirmed()).toBe(false)
      expect(composable.error.value).not.toBeNull()
    })

    it('opens no grant when the server omits expires_in', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true }))

      const { composable } = mountComposable()
      const result = await composable.confirm('pw')

      // The server said yes, so the flag flips — but with no expiry the grant
      // window is unusable and isConfirmed() must still refuse.
      expect(result).toBe(true)
      expect(composable.confirmed.value).toBe(true)
      expect(composable.isConfirmed()).toBe(false)
    })

    it('opens no grant when the server sends a negative expires_in', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: -3600 }))

      const { composable } = mountComposable()
      const result = await composable.confirm('pw')

      expect(result).toBe(true)
      expect(composable.confirmed.value).toBe(true)
      expect(composable.isConfirmed()).toBe(false)
    })

    it('sends the password but keeps no copy of it in the exposed state', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_credentials', 401))

      const { composable } = mountComposable()
      await composable.confirm('super-secret-password')

      // The password must reach the wire...
      expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({
        password: 'super-secret-password',
      })
      // ...and nowhere else. A rejected attempt must leave the exposed refs at
      // their pristine values apart from the error code the server returned.
      expect(composable.confirmed.value).toBe(false)
      expect(composable.isLoading.value).toBe(false)
      expect(composable.error.value).toEqual(
        expect.objectContaining({ code: 'invalid_credentials', status: 401 }),
      )
      const exposed = JSON.stringify({
        confirmed: composable.confirmed.value,
        isLoading: composable.isLoading.value,
        error: composable.error.value,
        errorMessage: composable.error.value?.message,
      })
      expect(exposed).not.toContain('super-secret-password')
    })

    it('does not revoke a live grant when a later attempt is rejected', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 300 }))
      const { composable } = mountComposable()
      await composable.confirm('right')
      expect(composable.isConfirmed()).toBe(true)

      mockFetch.mockResolvedValueOnce(errorResponse('invalid_credentials', 401))
      const result = await composable.confirm('wrong')

      expect(result).toBe(false)
      expect(composable.isConfirmed()).toBe(true)
    })
  })

  describe('expiry', () => {
    it('closes the grant by wall clock even before the timer fires', async () => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 300 }))

      const { composable } = mountComposable()
      await composable.confirm('pw')
      expect(composable.isConfirmed()).toBe(true)

      // Move the clock past the grant without letting the auto-expire timer run.
      vi.setSystemTime(new Date('2026-07-30T00:05:01Z'))

      expect(composable.confirmed.value).toBe(true)
      expect(composable.isConfirmed()).toBe(false)
    })

    it('clears the confirmed flag when the auto-expire timer fires', async () => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 300 }))

      const { composable } = mountComposable()
      await composable.confirm('pw')
      expect(composable.confirmed.value).toBe(true)

      vi.advanceTimersByTime(300_000)

      expect(composable.confirmed.value).toBe(false)
      expect(composable.isConfirmed()).toBe(false)
    })

    it('cancels the previous timer so a stale expiry cannot close a fresh grant', async () => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))

      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 100 }))
      const { composable } = mountComposable()
      await composable.confirm('pw')

      vi.advanceTimersByTime(50_000)

      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 100 }))
      await composable.confirm('pw')

      // t=110s: the first grant's timer would have fired at t=100s if it were still armed.
      vi.advanceTimersByTime(60_000)

      expect(composable.confirmed.value).toBe(true)
      expect(composable.isConfirmed()).toBe(true)

      // The second grant still expires on its own schedule at t=150s.
      vi.advanceTimersByTime(40_000)
      expect(composable.isConfirmed()).toBe(false)
    })
  })

  describe('clearConfirmation', () => {
    it('closes the grant immediately', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 300 }))
      const { composable } = mountComposable()
      await composable.confirm('pw')
      expect(composable.isConfirmed()).toBe(true)

      composable.clearConfirmation()

      expect(composable.confirmed.value).toBe(false)
      expect(composable.isConfirmed()).toBe(false)
    })

    it('disarms the pending expiry timer', async () => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))

      mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 100 }))
      const { composable } = mountComposable()
      await composable.confirm('pw')
      expect(vi.getTimerCount()).toBe(1)

      composable.clearConfirmation()
      expect(vi.getTimerCount()).toBe(0)
    })
  })

  it('shares the grant across every instance of the composable', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ confirmed: true, expires_in: 300 }))
    const first = mountComposable().composable
    await first.confirm('pw')

    const second = mountComposable().composable

    expect(second.isConfirmed()).toBe(true)
    expect(second.confirmed.value).toBe(true)
    expect(second.error.value).toBeNull()

    second.clearConfirmation()
    expect(first.isConfirmed()).toBe(false)
  })
})
