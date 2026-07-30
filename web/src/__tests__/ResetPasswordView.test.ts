import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import ResetPasswordView from '../views/ResetPasswordView.vue'
import en from '../locales/en.json'

const mockConfirmReset = vi.fn()
const mockPush = vi.fn()

const mockIsLoading = ref(false)
const mockError = ref<{ code: string } | null>(null)
const mockConfirmed = ref(false)
const mockQuery = ref<Record<string, string | undefined>>({})

vi.mock('@vault42/vue', () => ({
  usePasswordReset: () => ({
    isLoading: mockIsLoading,
    error: mockError,
    requested: ref(false),
    confirmed: mockConfirmed,
    requestReset: vi.fn(),
    confirmReset: mockConfirmReset,
    changePassword: vi.fn(),
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
  useRoute: () => ({ query: mockQuery.value }),
  useRouter: () => ({ push: mockPush }),
}))

const RouterLinkStub = {
  props: ['to'],
  template: '<a :href="to"><slot /></a>',
}

const VALID_TOKEN = 'reset-token_ABC123456789'
const GOOD_PASSWORD = 'correct-horse-battery-staple'

function mountView() {
  return mount(ResetPasswordView, {
    global: {
      stubs: {
        Teleport: true,
        RouterLink: RouterLinkStub,
      },
    },
  })
}

function passwordInputs(wrapper: ReturnType<typeof mountView>) {
  const inputs = wrapper.findAll('input[type="password"]')
  return { newPassword: inputs[0], confirmPassword: inputs[1] }
}

async function fill(wrapper: ReturnType<typeof mountView>, pw: string, confirm = pw) {
  const { newPassword, confirmPassword } = passwordInputs(wrapper)
  await newPassword.setValue(pw)
  await confirmPassword.setValue(confirm)
}

describe('ResetPasswordView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIsLoading.value = false
    mockError.value = null
    mockConfirmed.value = false
    mockQuery.value = { token: VALID_TOKEN }
    // Mirrors the real composable: success flips `confirmed`.
    mockConfirmReset.mockImplementation(async () => {
      mockConfirmed.value = true
    })
  })

  it('renders the page title', () => {
    const wrapper = mountView()
    expect(wrapper.find('h1').text()).toBe('Set New Password')
  })

  it('refuses to show the form when the link carries no token', () => {
    mockQuery.value = {}
    const wrapper = mountView()

    expect(wrapper.text()).toContain('Invalid Link')
    expect(wrapper.text()).toContain('This reset link is missing a token. Please request a new one.')
    expect(wrapper.find('form').exists()).toBe(false)
  })

  it('offers a route back to requesting a new link when the token is missing', () => {
    mockQuery.value = {}
    const wrapper = mountView()

    const link = wrapper.find('a[href="/forgot-password"]')
    expect(link.exists()).toBe(true)
    expect(link.text()).toBe('Request New Link')
  })

  it('rejects tokens that do not match the safe format', () => {
    const bad = [
      'short',
      '../../etc/passwd',
      '<script>alert(1)</script>',
      'token with spaces here',
      'a'.repeat(257),
      '',
    ]
    for (const token of bad) {
      mockQuery.value = { token }
      const wrapper = mountView()
      expect(wrapper.find('form').exists(), `token ${JSON.stringify(token.slice(0, 20))} should be rejected`).toBe(false)
      expect(wrapper.text()).toContain('Invalid Link')
    }
  })

  it('shows the form for a well-formed token', () => {
    const wrapper = mountView()
    expect(wrapper.find('form').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('Invalid Link')
  })

  it('blocks submission while the confirmation does not match', async () => {
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD, GOOD_PASSWORD + 'x')

    expect(wrapper.text()).toContain('Passwords do not match')
    expect((wrapper.find('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(true)

    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(mockConfirmReset).not.toHaveBeenCalled()
  })

  it('clears the mismatch warning once the confirmation matches', async () => {
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD, 'nope')
    expect(wrapper.text()).toContain('Passwords do not match')

    await passwordInputs(wrapper).confirmPassword.setValue(GOOD_PASSWORD)
    expect(wrapper.text()).not.toContain('Passwords do not match')
    expect((wrapper.find('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(false)
  })

  it('blocks submission for a password shorter than 15 characters', async () => {
    const wrapper = mountView()
    await fill(wrapper, 'short-pass-14c')

    expect((wrapper.find('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(true)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(mockConfirmReset).not.toHaveBeenCalled()
  })

  it('grades password strength as the user types', async () => {
    const wrapper = mountView()
    await passwordInputs(wrapper).newPassword.setValue('abcde')
    expect(wrapper.text()).toContain('Too short (5 characters)')

    await passwordInputs(wrapper).newPassword.setValue('a'.repeat(16))
    expect(wrapper.text()).toContain('Acceptable (16 characters)')

    await passwordInputs(wrapper).newPassword.setValue('a'.repeat(40))
    expect(wrapper.text()).toContain('Excellent (40 characters)')
  })

  it('submits the token from the URL together with the new password', async () => {
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockConfirmReset).toHaveBeenCalledOnce()
    expect(mockConfirmReset).toHaveBeenCalledWith(VALID_TOKEN, GOOD_PASSWORD)
  })

  it('replaces the form with a session-revocation notice on success', async () => {
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.text()).toContain('Password Reset')
    expect(wrapper.text()).toContain('Your password has been updated. All sessions have been revoked.')
  })

  it('routes to the login page from the success screen', async () => {
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    const signIn = wrapper.findAll('button').find(b => b.text() === 'Sign In')
    expect(signIn).toBeDefined()
    await signIn!.trigger('click')
    expect(mockPush).toHaveBeenCalledWith('/login')
  })

  it('reports an expired token instead of a false success', async () => {
    mockConfirmReset.mockImplementation(async () => {
      mockError.value = { code: 'invalid_or_expired_token' }
      throw { code: 'invalid_or_expired_token' }
    })
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('This link has expired or was already used.')
    expect(wrapper.text()).not.toContain('All sessions have been revoked.')
    expect(wrapper.find('form').exists()).toBe(true)
  })

  it('surfaces a breached-password rejection', async () => {
    mockConfirmReset.mockImplementation(async () => {
      mockError.value = { code: 'password_breached' }
      throw { code: 'password_breached' }
    })
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('This password has appeared in a data breach. Please choose a different one.')
  })

  it('keeps both password fields filled after a rejected reset', async () => {
    mockConfirmReset.mockImplementation(async () => {
      mockError.value = { code: 'password_breached' }
      throw { code: 'password_breached' }
    })
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    const { newPassword, confirmPassword } = passwordInputs(wrapper)
    expect((newPassword.element as HTMLInputElement).value).toBe(GOOD_PASSWORD)
    expect((confirmPassword.element as HTMLInputElement).value).toBe(GOOD_PASSWORD)
  })

  it('shows progress and locks the button while the reset is in flight', async () => {
    mockConfirmReset.mockImplementation(() => {
      mockIsLoading.value = true
      return new Promise(() => {})
    })
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    const btn = wrapper.find('button[type="submit"]')
    expect(btn.text()).toBe('Resetting...')
    expect(btn.find('.vault42-spinner').exists()).toBe(true)
    expect((btn.element as HTMLButtonElement).disabled).toBe(true)
  })

  it('ignores a second submit while the first is still in flight', async () => {
    mockConfirmReset.mockImplementation(() => {
      mockIsLoading.value = true
      return new Promise(() => {})
    })
    const wrapper = mountView()
    await fill(wrapper, GOOD_PASSWORD)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockConfirmReset).toHaveBeenCalledOnce()
  })
})
