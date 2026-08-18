import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, defineComponent, h } from 'vue'
import OAuthCallbackView from '../views/OAuthCallbackView.vue'
import { safeRedirect } from '../utils/safeRedirect'
import en from '../locales/en.json'

const mockAccessToken = ref<string | null>(null)
const mockRequires2FA = ref(false)
const mockChallengeToken = ref<string | null>(null)

const mockParseCallback = vi.fn()
const mockExchangeCode = vi.fn()
const mockFetchProfile = vi.fn()
const mockReplace = vi.fn()

vi.mock('@vault42/vue', () => ({
  useAuth: () => ({
    accessToken: mockAccessToken,
    requires2FA: mockRequires2FA,
    challengeToken: mockChallengeToken,
  }),
  useOAuth: () => ({
    parseCallback: mockParseCallback,
    exchangeCode: mockExchangeCode,
  }),
  useProfile: () => ({
    fetchProfile: mockFetchProfile,
  }),
  useT: () => ({
    t: (key: string) => (en as Record<string, string>)[key] ?? key,
    formatDate: (d: Date) => d.toLocaleDateString(),
  }),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ replace: mockReplace }),
}))

const RouterLinkStub = defineComponent({
  props: { to: { type: [String, Object], required: true } },
  setup(props, { slots }) {
    return () => h('a', { href: String(props.to) }, slots.default ? slots.default() : [])
  },
})

/** Puts the browser at an OAuth callback URL, then mounts the view. */
async function mountAt(url: string) {
  window.history.replaceState(null, '', url)
  const wrapper = mount(OAuthCallbackView, {
    global: { components: { RouterLink: RouterLinkStub } },
  })
  await flushPromises()
  return wrapper
}

function errorText(wrapper: ReturnType<typeof mount>): string {
  return wrapper.find('.vault42-card p').text()
}

describe('OAuthCallbackView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAccessToken.value = null
    mockRequires2FA.value = false
    mockChallengeToken.value = null
    mockParseCallback.mockReturnValue(null)
    mockExchangeCode.mockResolvedValue({ access_token: 'access-token' })
    mockFetchProfile.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('fragment handling', () => {
    it('parses the URL fragment the provider returned', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code' })
      await mountAt('/oauth/callback#code=auth-code')

      expect(mockParseCallback).toHaveBeenCalledWith('#code=auth-code')
    })

    it('strips the fragment from the URL so tokens do not linger in history', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code' })
      const replaceState = vi.spyOn(window.history, 'replaceState')

      await mountAt('/oauth/callback#code=auth-code&challenge_token=secret')

      expect(replaceState).toHaveBeenCalledWith(null, '', '/oauth/callback')
      expect(window.location.hash).toBe('')
    })

    it('strips the fragment even when the callback is an error', async () => {
      mockParseCallback.mockReturnValue({ error: 'access_denied' })
      await mountAt('/oauth/callback#error=access_denied')

      expect(window.location.hash).toBe('')
    })
  })

  describe('aborted callbacks', () => {
    it('reports missing data and does not exchange anything when the fragment is empty', async () => {
      mockParseCallback.mockReturnValue(null)
      const wrapper = await mountAt('/oauth/callback')

      expect(errorText(wrapper)).toBe('No authentication data received.')
      expect(mockExchangeCode).not.toHaveBeenCalled()
      expect(mockAccessToken.value).toBeNull()
      expect(mockReplace).not.toHaveBeenCalled()
    })

    it('aborts on a provider error without signing the user in', async () => {
      mockParseCallback.mockReturnValue({ error: 'access_denied' })
      const wrapper = await mountAt('/oauth/callback#error=access_denied')

      expect(mockExchangeCode).not.toHaveBeenCalled()
      expect(mockAccessToken.value).toBeNull()
      expect(mockRequires2FA.value).toBe(false)
      expect(mockReplace).not.toHaveBeenCalled()
      expect(wrapper.text()).toContain('Authentication Failed')
    })

    it('aborts a state mismatch reported by the server without signing the user in', async () => {
      // The vault rejects the provider callback when the OAuth state does not
      // match and hands the SPA an error instead of a code.
      mockParseCallback.mockReturnValue({ error: 'invalid_state' })
      const wrapper = await mountAt('/oauth/callback#error=invalid_state')

      expect(mockExchangeCode).not.toHaveBeenCalled()
      expect(mockAccessToken.value).toBeNull()
      expect(mockReplace).not.toHaveBeenCalled()
      expect(errorText(wrapper)).toBe('This request is no longer valid. Please start again.')
    })

    it('never renders text from the fragment as the error message', async () => {
      // result.error comes out of window.location.hash, so anyone can craft it.
      // Rendered verbatim it read as an official message from the vault inside
      // the vault's own error card: a working phishing surface, and against the
      // rule errorMessages.ts states for itself ("The code string is
      // server-controlled and must never reach the rendered message").
      const attack = 'Your account is locked. Call +1-555-0100 to restore access.'
      mockParseCallback.mockReturnValue({ error: attack })
      const wrapper = await mountAt('/oauth/callback#error=' + encodeURIComponent(attack))

      expect(wrapper.text()).not.toContain('555-0100')
      expect(errorText(wrapper)).toBe('Something went wrong. Please try again.')
    })

    it('translates a known provider error code', async () => {
      mockParseCallback.mockReturnValue({ error: 'oauth_failed' })
      const wrapper = await mountAt('/oauth/callback#error=oauth_failed')

      expect(errorText(wrapper)).toBe('Social sign-in failed. Please try again.')
    })

    it('aborts a fragment that carries a state but no code', async () => {
      mockParseCallback.mockReturnValue({ state: 'attacker-supplied' })
      const wrapper = await mountAt('/oauth/callback#state=attacker-supplied')

      expect(errorText(wrapper)).toBe('Unexpected callback response.')
      expect(mockExchangeCode).not.toHaveBeenCalled()
      expect(mockAccessToken.value).toBeNull()
      expect(mockReplace).not.toHaveBeenCalled()
    })

    it('aborts when the code is present but empty', async () => {
      mockParseCallback.mockReturnValue({ code: '' })
      const wrapper = await mountAt('/oauth/callback#code=')

      expect(errorText(wrapper)).toBe('Unexpected callback response.')
      expect(mockExchangeCode).not.toHaveBeenCalled()
      expect(mockAccessToken.value).toBeNull()
    })

    it('shows an error instead of an endless spinner when the exchange fails', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code' })
      mockExchangeCode.mockRejectedValue(new Error('network down'))

      const wrapper = await mountAt('/oauth/callback#code=auth-code')

      expect(errorText(wrapper)).toBe('Failed to complete sign in. Please try again.')
      expect(wrapper.find('.vault42-spinner').exists()).toBe(false)
      expect(mockAccessToken.value).toBeNull()
      expect(mockReplace).not.toHaveBeenCalled()
    })

    it('offers a way back to sign in from every failure', async () => {
      mockParseCallback.mockReturnValue({ error: 'access_denied' })
      const wrapper = await mountAt('/oauth/callback#error=access_denied')

      const link = wrapper.find('a')
      expect(link.attributes('href')).toBe('/login')
      expect(link.text()).toBe('Back to Sign In')
    })
  })

  describe('two-factor challenge', () => {
    it('hands the challenge to the login view without granting a session', async () => {
      mockParseCallback.mockReturnValue({ requires_2fa: true, challenge_token: 'challenge-1' })
      await mountAt('/oauth/callback#requires_2fa=true&challenge_token=challenge-1')

      expect(mockRequires2FA.value).toBe(true)
      expect(mockChallengeToken.value).toBe('challenge-1')
      expect(mockAccessToken.value).toBeNull()
      expect(mockExchangeCode).not.toHaveBeenCalled()
      expect(mockReplace).toHaveBeenCalledWith('/login')
    })

    it('normalises a missing challenge token to null rather than undefined', async () => {
      mockParseCallback.mockReturnValue({ requires_2fa: true })
      await mountAt('/oauth/callback#requires_2fa=true')

      expect(mockChallengeToken.value).toBeNull()
      expect(mockReplace).toHaveBeenCalledWith('/login')
    })

    it('ignores a code that arrives alongside a 2FA challenge', async () => {
      mockParseCallback.mockReturnValue({ requires_2fa: true, code: 'auth-code' })
      await mountAt('/oauth/callback#requires_2fa=true&code=auth-code')

      expect(mockExchangeCode).not.toHaveBeenCalled()
      expect(mockAccessToken.value).toBeNull()
    })
  })

  describe('successful sign in', () => {
    it('exchanges the code and stores the returned access token', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code' })
      await mountAt('/oauth/callback#code=auth-code')

      expect(mockExchangeCode).toHaveBeenCalledWith('auth-code')
      expect(mockAccessToken.value).toBe('access-token')
      expect(mockFetchProfile).toHaveBeenCalledOnce()
      expect(mockReplace).toHaveBeenCalledWith('/')
    })

    it('still completes sign in when the profile fetch fails', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code' })
      mockFetchProfile.mockRejectedValue(new Error('profile unavailable'))

      const wrapper = await mountAt('/oauth/callback#code=auth-code')

      expect(mockAccessToken.value).toBe('access-token')
      expect(mockReplace).toHaveBeenCalledWith('/')
      expect(wrapper.text()).not.toContain('Authentication Failed')
    })

    // DEFECT, pinned rather than endorsed: `exchangeCode` can resolve without an
    // access token (the vault answers a 2FA-gated exchange that way, and
    // useOAuth already guards for it). The view assigns it unconditionally and
    // navigates as though sign in succeeded, so the user lands on the dashboard
    // signed out and with no error shown. Reported separately; this test exists
    // so the behaviour cannot change unnoticed.
    it('DEFECT: treats an exchange with no access_token as a successful sign in', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code' })
      mockExchangeCode.mockResolvedValue({ requires_2fa: true })

      const wrapper = await mountAt('/oauth/callback#code=auth-code')

      expect(mockAccessToken.value).toBeUndefined()
      expect(mockReplace).toHaveBeenCalledWith('/')
      expect(wrapper.text()).not.toContain('Authentication Failed')
    })

    it('shows the pending state until the exchange resolves', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code' })
      let release: (value: { access_token: string }) => void = () => {}
      mockExchangeCode.mockReturnValue(new Promise((resolve) => { release = resolve }))

      window.history.replaceState(null, '', '/oauth/callback#code=auth-code')
      const wrapper = mount(OAuthCallbackView, {
        global: { components: { RouterLink: RouterLinkStub } },
      })
      await flushPromises()

      expect(wrapper.find('.vault42-spinner').exists()).toBe(true)
      expect(wrapper.text()).toContain('Completing sign in...')
      expect(mockReplace).not.toHaveBeenCalled()

      release({ access_token: 'access-token' })
      await flushPromises()

      expect(mockReplace).toHaveBeenCalledWith('/')
      // The spinner is torn down by the navigation, not by this component, so
      // what matters here is that no error state was entered on the way out.
      expect(wrapper.text()).not.toContain('Authentication Failed')
    })
  })

  describe('post-callback navigation', () => {
    it('always lands on the dashboard and never on a caller-supplied target', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code' })
      await mountAt('/oauth/callback?redirect=//evil.com#code=auth-code')

      expect(mockReplace).toHaveBeenCalledTimes(1)
      expect(mockReplace).toHaveBeenCalledWith('/')
    })

    it('ignores a redirect smuggled into the fragment', async () => {
      mockParseCallback.mockReturnValue({ code: 'auth-code', redirect: 'https://evil.com' })
      await mountAt('/oauth/callback#code=auth-code&redirect=https://evil.com')

      expect(mockReplace).toHaveBeenCalledWith('/')
    })

    it('would reject those targets if the view ever started honouring one', async () => {
      // Guards the day someone wires a redirect through this view: the only
      // acceptable source of a target is safeRedirect.
      expect(safeRedirect('//evil.com')).toBe('/')
      expect(safeRedirect('https://evil.com')).toBe('/')
      expect(safeRedirect('/profile')).toBe('/profile')
    })
  })
})
