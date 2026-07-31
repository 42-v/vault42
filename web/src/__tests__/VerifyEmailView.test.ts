import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import VerifyEmailView from '../views/VerifyEmailView.vue'
import en from '../locales/en.json'

const mockVerifyEmail = vi.fn()
const mockPush = vi.fn()
const mockRoute = { query: {} as Record<string, string | null | undefined> }

vi.mock('@vault42/vue', () => ({
  useVaultClient: () => ({
    verifyEmail: mockVerifyEmail,
  }),
  useT: () => ({
    t: (key: string, params?: Record<string, string | number>) => {
      const val = (en as Record<string, string>)[key] ?? key
      if (!params) return val
      return val.replace(/\{(\w+)\}/g, (_, name: string) => params[name] != null ? String(params[name]) : `{${name}}`)
    },
    formatDate: (d: Date) => d.toLocaleDateString(),
  }),
}))

vi.mock('vue-router', () => ({
  useRoute: () => mockRoute,
  useRouter: () => ({ push: mockPush }),
}))

const RouterLinkStub = defineComponent({
  props: { to: { type: String, default: '' } },
  setup(props, { slots }) {
    return () => h('a', { href: props.to }, slots.default ? slots.default() : [])
  },
})

function mountView() {
  return mount(VerifyEmailView, {
    global: {
      stubs: {
        Teleport: true,
        RouterLink: RouterLinkStub,
      },
    },
  })
}

describe('VerifyEmailView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockRoute.query = { token: 'tok_valid' }
    mockVerifyEmail.mockResolvedValue(undefined)
    // Only the countdown timer is faked; promises still settle normally.
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  // ---- Loading ----

  it('shows the verifying state until the request settles', async () => {
    let resolve!: () => void
    mockVerifyEmail.mockReturnValue(new Promise<void>(r => { resolve = r }))

    const wrapper = mountView()
    expect(wrapper.text()).toContain('Verifying your email...')
    expect(wrapper.find('.vault42-spinner').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('Email Verified')
    expect(wrapper.text()).not.toContain('Verification Failed')

    resolve()
    await flushPromises()
    expect(wrapper.text()).toContain('Email Verified')
  })

  // ---- Valid token ----

  it('verifies with the exact token from the query string', async () => {
    mockRoute.query = { token: 'tok_abc 123/+' }
    mountView()
    await flushPromises()

    expect(mockVerifyEmail).toHaveBeenCalledOnce()
    expect(mockVerifyEmail).toHaveBeenCalledWith('tok_abc 123/+')
  })

  it('renders the success state after a valid token', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Email Verified')
    expect(wrapper.text()).toContain('Your email has been verified successfully.')
    expect(wrapper.text()).not.toContain('Verification Failed')
    expect(wrapper.find('.vault42-spinner').exists()).toBe(false)

    const signIn = wrapper.findAll('a').find(a => a.text() === 'Sign In Now')
    expect(signIn).toBeDefined()
    expect(signIn!.attributes('href')).toBe('/login')
  })

  // ---- Missing token ----

  it('fails without calling the API when the token is missing', async () => {
    mockRoute.query = {}
    const wrapper = mountView()
    await flushPromises()

    expect(mockVerifyEmail).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Verification Failed')
    expect(wrapper.text()).toContain('Missing verification token.')
  })

  it('treats an empty token as missing', async () => {
    mockRoute.query = { token: '' }
    const wrapper = mountView()
    await flushPromises()

    expect(mockVerifyEmail).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Missing verification token.')
  })

  // ---- Expired / already used ----

  it('explains an expired or already-consumed link', async () => {
    mockVerifyEmail.mockRejectedValue({ code: 'invalid_or_expired_token' })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Verification Failed')
    expect(wrapper.text()).toContain('This link has expired or was already used.')
    expect(wrapper.text()).toContain('The link may have expired or already been used.')
    expect(wrapper.text()).not.toContain('Email Verified')
  })

  it('surfaces throttling as a distinct message', async () => {
    mockVerifyEmail.mockRejectedValue({ code: 'rate_limited' })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Too many requests. Please wait a moment.')
  })

  it('falls back to a verification-failed message when the rejection carries no code', async () => {
    mockVerifyEmail.mockRejectedValue(new TypeError('Failed to fetch'))
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Verification Failed')
    expect(wrapper.text()).toContain('Verification failed. The link may have expired.')
  })

  it('falls back when the rejection is not an object at all', async () => {
    mockVerifyEmail.mockRejectedValue('boom')
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Verification failed. The link may have expired.')
  })

  it('does not schedule a redirect after a failure', async () => {
    mockVerifyEmail.mockRejectedValue({ code: 'invalid_or_expired_token' })
    const wrapper = mountView()
    await flushPromises()

    vi.advanceTimersByTime(10_000)
    await flushPromises()

    expect(mockPush).not.toHaveBeenCalled()
    expect(wrapper.text()).not.toContain('Redirecting in')

    // Tearing down a view that never started a timer must stay quiet.
    wrapper.unmount()
    vi.advanceTimersByTime(10_000)
    expect(mockPush).not.toHaveBeenCalled()
  })

  // ---- Countdown / redirect ----

  it('counts down and then redirects exactly once', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Redirecting in 3...')

    vi.advanceTimersByTime(1000)
    await flushPromises()
    expect(wrapper.text()).toContain('Redirecting in 2...')
    expect(mockPush).not.toHaveBeenCalled()

    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(mockPush).toHaveBeenCalledOnce()
    expect(mockPush).toHaveBeenCalledWith('/login')

    vi.advanceTimersByTime(10_000)
    await flushPromises()
    expect(mockPush).toHaveBeenCalledOnce()
  })

  it('honours a relative redirect target', async () => {
    mockRoute.query = { token: 'tok_valid', redirect: '/dashboard?tab=1' }
    mountView()
    await flushPromises()

    vi.advanceTimersByTime(3000)
    await flushPromises()

    expect(mockPush).toHaveBeenCalledWith('/dashboard?tab=1')
  })

  it('refuses an absolute redirect target and falls back to /login', async () => {
    mockRoute.query = { token: 'tok_valid', redirect: 'https://evil.example.com/steal' }
    mountView()
    await flushPromises()

    vi.advanceTimersByTime(3000)
    await flushPromises()

    expect(mockPush).toHaveBeenCalledWith('/login')
  })

  it('refuses a protocol-relative redirect target', async () => {
    mockRoute.query = { token: 'tok_valid', redirect: '//evil.example.com' }
    mountView()
    await flushPromises()

    vi.advanceTimersByTime(3000)
    await flushPromises()

    expect(mockPush).toHaveBeenCalledWith('/login')
  })

  // ---- Teardown ----

  it('stops the countdown when the view is unmounted', async () => {
    const wrapper = mountView()
    await flushPromises()

    vi.advanceTimersByTime(1000)
    await flushPromises()

    wrapper.unmount()
    vi.advanceTimersByTime(10_000)
    await flushPromises()

    expect(mockPush).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
})
