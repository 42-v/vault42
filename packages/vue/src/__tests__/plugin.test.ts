import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createApp, defineComponent, h } from 'vue'
import { createVaultPlugin, useVaultClient } from '../plugin'
import { VaultClient } from '../client'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Mount a component that resolves useVaultClient() inside a plugin context. */
function mountWithPlugin(p = createVaultPlugin({ baseURL: 'https://vault42.example.com' })) {
  let client!: VaultClient

  const wrapper = mount(
    defineComponent({
      setup() {
        client = useVaultClient()
        return () => h('div')
      },
    }),
    { global: { plugins: [p] } },
  )

  return { wrapper, client, p }
}

describe('createVaultPlugin', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('provides a VaultClient that useVaultClient resolves', () => {
    const { client } = mountWithPlugin()
    expect(client).toBeInstanceOf(VaultClient)
  })

  it('builds request URLs from the configured baseURL', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

    const { client } = mountWithPlugin()
    await client.getProfile()

    expect(mockFetch).toHaveBeenCalledWith('https://vault42.example.com/user/profile', {
      method: 'GET',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
    })
  })

  it('strips a trailing slash from baseURL instead of emitting a double slash', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

    const { client } = mountWithPlugin(
      createVaultPlugin({ baseURL: 'https://vault42.example.com/' }),
    )
    await client.getProfile()

    expect(mockFetch.mock.calls[0][0]).toBe('https://vault42.example.com/user/profile')
  })

  it('forwards clientOptions to the client it constructs', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))
    const onRequest = vi.fn((init: RequestInit) => ({
      ...init,
      headers: { ...(init.headers as Record<string, string>), 'X-Fingerprint': 'fp-1' },
    }))

    const { client } = mountWithPlugin(
      createVaultPlugin({ baseURL: 'https://vault42.example.com', clientOptions: { onRequest } }),
    )
    await client.getProfile()

    expect(onRequest).toHaveBeenCalledTimes(1)
    expect(mockFetch).toHaveBeenCalledWith('https://vault42.example.com/user/profile', {
      method: 'GET',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Fingerprint': 'fp-1',
      },
    })
  })

  it('shares one client across every component in the app', () => {
    const p = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
    const seen: VaultClient[] = []

    const Child = defineComponent({
      setup() {
        seen.push(useVaultClient())
        return () => h('i')
      },
    })

    mount(
      defineComponent({
        setup() {
          seen.push(useVaultClient())
          return () => h('div', [h(Child)])
        },
      }),
      { global: { plugins: [p] } },
    )

    expect(seen).toHaveLength(2)
    expect(seen[0]).toBe(seen[1])
    // The shared instance is what carries the access token between composables.
    seen[0].accessToken = 'token-abc'
    expect(seen[1].accessToken).toBe('token-abc')
  })

  it('gives separate plugin instances separate clients and separate tokens', () => {
    const a = mountWithPlugin()
    const b = mountWithPlugin()

    a.client.accessToken = 'token-a'

    expect(a.client).not.toBe(b.client)
    expect(b.client.accessToken).toBeNull()
  })
})

describe('createVaultPlugin repeated installation', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  it('is safe to install twice: the provided client still works and is not reset', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'u1' }))

    const p = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
    p.install(createApp({ render: () => h('div') }))
    // A token acquired under the first installation must survive the second.
    const firstMount = mountWithPlugin(p)
    firstMount.client.accessToken = 'token-abc'

    let resolved!: VaultClient
    const host = createApp(
      defineComponent({
        setup() {
          resolved = useVaultClient()
          return () => h('div')
        },
      }),
    )
    expect(() => {
      host.use(p)
      host.use(p)
    }).not.toThrow()
    host.mount(document.createElement('div'))

    expect(resolved.accessToken).toBe('token-abc')
    await resolved.getProfile()
    expect(mockFetch).toHaveBeenCalledWith('https://vault42.example.com/user/profile', {
      method: 'GET',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Authorization: 'Bearer token-abc',
      },
    })
    host.unmount()
  })

  it('DEFECT: one plugin object installed on two apps shares the access token', () => {
    // The client is constructed in createVaultPlugin, not in install(), so the
    // same credential-bearing instance is handed to every app that uses the
    // plugin object. A second app (or a second mount in a test) inherits a
    // logged-in session it never authenticated.
    const p = createVaultPlugin({ baseURL: 'https://vault42.example.com' })
    const first = mountWithPlugin(p)
    first.client.accessToken = 'token-abc'

    const second = mountWithPlugin(p)

    expect(second.client).toBe(first.client)
    expect(second.client.accessToken).toBe('token-abc')
  })
})

describe('useVaultClient without the plugin', () => {
  it('throws a diagnostic error inside a component', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})

    expect(() =>
      mount(
        defineComponent({
          setup() {
            useVaultClient()
            return () => h('div')
          },
        }),
      ),
    ).toThrow(
      '[@vault42/vue] VaultClient not provided. Did you call app.use(createVaultPlugin({ baseURL: "..." }))?',
    )
  })

  it('throws rather than returning undefined outside any component setup', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})

    expect(() => useVaultClient()).toThrow('[@vault42/vue] VaultClient not provided')
  })
})
