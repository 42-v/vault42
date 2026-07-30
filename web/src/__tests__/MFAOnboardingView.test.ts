import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, type VueWrapper } from '@vue/test-utils'
import MFAOnboardingView from '../views/MFAOnboardingView.vue'
import en from '../locales/en.json'

const mockPush = vi.fn()

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mockPush }),
}))

vi.mock('@vault42/vue', () => ({
  useT: () => ({
    t: (key: string, params?: Record<string, string | number>) => {
      const val = (en as Record<string, string>)[key] ?? key
      if (!params) return val
      return val.replace(/\{(\w+)\}/g, (_, name: string) => params[name] != null ? String(params[name]) : `{${name}}`)
    },
    formatDate: (d: Date) => d.toLocaleDateString(),
  }),
}))

function mountView() {
  return mount(MFAOnboardingView)
}

function buttonByText(wrapper: VueWrapper, text: string) {
  return wrapper.findAll('button').find(b => b.text() === text)
}

describe('MFAOnboardingView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('states that MFA is required and what the fallback is', () => {
    const wrapper = mountView()

    expect(wrapper.find('h1').text()).toBe('Secure Your Account')
    expect(wrapper.text()).toContain('Multi-factor authentication is required.')
    expect(wrapper.text()).toContain('Skip for now (email codes will be used)')
  })

  it('does not navigate away on mount', () => {
    mountView()
    expect(mockPush).not.toHaveBeenCalled()
  })

  it('sends the authenticator option to the 2FA page', async () => {
    const wrapper = mountView()

    await buttonByText(wrapper, 'Set up Authenticator App')!.trigger('click')

    expect(mockPush).toHaveBeenCalledOnce()
    expect(mockPush).toHaveBeenCalledWith('/2fa')
  })

  it('sends the security-key option to the 2FA page WebAuthn section', async () => {
    const wrapper = mountView()

    await buttonByText(wrapper, 'Set up Security Key')!.trigger('click')

    expect(mockPush).toHaveBeenCalledOnce()
    expect(mockPush).toHaveBeenCalledWith('/2fa#webauthn')
  })

  it('offers exactly the two enrolment paths as buttons', () => {
    const wrapper = mountView()
    const labels = wrapper.findAll('button').map(b => b.text())
    expect(labels).toEqual(['Set up Authenticator App', 'Set up Security Key'])
  })

  it('routes skip to the dashboard without following the placeholder href', async () => {
    const wrapper = mountView()
    const skip = wrapper.find('a')
    expect(skip.attributes('href')).toBe('#')

    const event = new Event('click', { cancelable: true, bubbles: true })
    skip.element.dispatchEvent(event)

    expect(event.defaultPrevented).toBe(true)
    expect(mockPush).toHaveBeenCalledWith('/')
  })

  it('lets the user leave without enrolling — skip is unconditional', async () => {
    // Documents current behaviour: the view has no policy input, so nothing here can
    // hold a user who is required to enrol. Enforcement lives outside this component.
    const wrapper = mountView()

    await wrapper.find('a').trigger('click')

    expect(mockPush).toHaveBeenCalledOnce()
    expect(mockPush).toHaveBeenCalledWith('/')
  })
})
