import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, reactive, nextTick } from 'vue'
import LoginView from '../views/LoginView.vue'
import en from '../locales/en.json'

// LoginView is a thin shell around VaultLoginForm: everything the user actually
// does (credentials, the 2FA handoff, error copy) happens inside that form and
// comes back to the view as a `success` event. Stubbing the form would test
// nothing, so the real component is mounted and only the auth layer beneath it
// is faked.
const mockLogin = vi.fn()
const mockVerify2FA = vi.fn()
const mockVerify2FABackupCode = vi.fn()
const mockVerify2FAEmailOTP = vi.fn()
const mockVerify2FAWebAuthn = vi.fn()
const mockWebAuthnVerify = vi.fn()
const mockResendEmailOTP = vi.fn()
const mockAuthorize = vi.fn()
const mockPush = vi.fn()

const mockUser = ref<Record<string, unknown> | null>(null)
const mockError = ref<{ code?: string; status?: number } | null>(null)
const mockIsLoading = ref(false)
const mockWebAuthnLoading = ref(false)
const mockWebAuthnSupported = ref(true)
const mockRequires2FA = ref(false)
const mockChallengeToken = ref<string | null>(null)
const mockAvailableMethods = ref<string[]>([])

const mockRoute = reactive<{ query: Record<string, string> }>({ query: {} })

const authState = {
  user: mockUser,
  error: mockError,
  isLoading: mockIsLoading,
  requires2FA: mockRequires2FA,
  challengeToken: mockChallengeToken,
  availableMethods: mockAvailableMethods,
  login: mockLogin,
  verify2FA: mockVerify2FA,
  verify2FABackupCode: mockVerify2FABackupCode,
  verify2FAEmailOTP: mockVerify2FAEmailOTP,
  verify2FAWebAuthn: mockVerify2FAWebAuthn,
}

const tShim = {
  t: (key: string, params?: Record<string, string | number>) => {
    const val = (en as Record<string, string>)[key] ?? key
    if (!params) return val
    return val.replace(/\{(\w+)\}/g, (_, name: string) => params[name] != null ? String(params[name]) : `{${name}}`)
  },
  formatDate: (d: Date) => d.toLocaleDateString(),
}

vi.mock('../../../packages/vue/src/composables/useAuth', () => ({
  useAuth: () => authState,
}))

vi.mock('../../../packages/vue/src/composables/useWebAuthn', () => ({
  useWebAuthn: () => ({
    isSupported: mockWebAuthnSupported,
    isLoading: mockWebAuthnLoading,
    verify: mockWebAuthnVerify,
  }),
}))

vi.mock('../../../packages/vue/src/plugin', () => ({
  useVaultClient: () => ({ resendEmailOTP: mockResendEmailOTP }),
}))

vi.mock('@vault42/vue', async () => ({
  VaultLoginForm: (await import('../../../packages/vue/src/components/VaultLoginForm.vue')).default,
  useOAuth: () => ({ authorize: mockAuthorize }),
  useAuth: () => authState,
  useT: () => tShim,
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mockPush }),
  useRoute: () => mockRoute,
}))

function mountView() {
  return mount(LoginView, {
    global: {
      stubs: { Teleport: true },
    },
  })
}

type Wrapper = ReturnType<typeof mountView>

async function submitCredentials(wrapper: Wrapper, email = 'user@example.com', password = 'correct horse battery') {
  await wrapper.find('#vault42-login-email').setValue(email)
  await wrapper.find('#vault42-login-password').setValue(password)
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

function errorText(wrapper: Wrapper): string {
  return wrapper.find('.vault42-login-form__error').text()
}

describe('LoginView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUser.value = null
    mockError.value = null
    mockIsLoading.value = false
    mockWebAuthnLoading.value = false
    mockWebAuthnSupported.value = true
    mockRequires2FA.value = false
    mockChallengeToken.value = null
    mockAvailableMethods.value = []
    mockRoute.query = {}
    mockLogin.mockResolvedValue(undefined)
    mockVerify2FA.mockResolvedValue(undefined)
    mockVerify2FABackupCode.mockResolvedValue(undefined)
    mockVerify2FAEmailOTP.mockResolvedValue(undefined)
    mockVerify2FAWebAuthn.mockResolvedValue(undefined)
    mockWebAuthnVerify.mockResolvedValue(undefined)
    mockResendEmailOTP.mockResolvedValue(undefined)
  })

  it('renders the sign-in heading', () => {
    const wrapper = mountView()
    expect(wrapper.find('h1').text()).toBe('Sign in to Vault42')
  })

  // ---- credential submit ----

  it('submits the typed credentials with remember-me off by default', async () => {
    const wrapper = mountView()
    await submitCredentials(wrapper, 'ada@example.com', 'a very long passphrase')

    expect(mockLogin).toHaveBeenCalledOnce()
    expect(mockLogin).toHaveBeenCalledWith('ada@example.com', 'a very long passphrase', false)
  })

  it('passes remember-me through when the box is ticked', async () => {
    const wrapper = mountView()
    await wrapper.find('input[type="checkbox"]').setValue(true)
    await submitCredentials(wrapper, 'ada@example.com', 'a very long passphrase')

    expect(mockLogin).toHaveBeenCalledWith('ada@example.com', 'a very long passphrase', true)
  })

  it('navigates home after a successful login with no redirect param', async () => {
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(mockPush).toHaveBeenCalledWith('/')
  })

  // ---- ?redirect= handling ----

  it('carries the ?redirect= param through a successful login', async () => {
    mockRoute.query = { redirect: '/storage?tab=files' }
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(mockPush).toHaveBeenCalledWith('/storage?tab=files')
  })

  it('refuses an off-site ?redirect= target and falls back home', async () => {
    mockRoute.query = { redirect: 'https://evil.example/steal' }
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(mockPush).toHaveBeenCalledWith('/')
  })

  it('refuses a protocol-relative ?redirect= target and falls back home', async () => {
    mockRoute.query = { redirect: '//evil.example/steal' }
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(mockPush).toHaveBeenCalledWith('/')
  })

  // ---- MFA handoff ----

  it('hands off to the 2FA challenge instead of navigating when login requires 2FA', async () => {
    mockLogin.mockImplementation(async () => {
      mockRequires2FA.value = true
      mockChallengeToken.value = 'challenge-abc'
      mockAvailableMethods.value = ['totp']
    })
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(mockPush).not.toHaveBeenCalled()
    expect(wrapper.find('#vault42-totp-code').exists()).toBe(true)
    expect(wrapper.find('#vault42-login-password').exists()).toBe(false)
  })

  it('verifies the typed TOTP code and only then navigates', async () => {
    mockRequires2FA.value = true
    mockAvailableMethods.value = ['totp']
    mockRoute.query = { redirect: '/sessions' }
    const wrapper = mountView()

    await wrapper.find('#vault42-totp-code').setValue('123456')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockVerify2FA).toHaveBeenCalledWith('123456')
    expect(mockPush).toHaveBeenCalledWith('/sessions')
  })

  it('does not navigate when the 2FA code is rejected', async () => {
    mockRequires2FA.value = true
    mockAvailableMethods.value = ['totp']
    mockVerify2FA.mockImplementation(async () => {
      mockError.value = { code: 'invalid_code', status: 401 }
      throw mockError.value
    })
    const wrapper = mountView()

    await wrapper.find('#vault42-totp-code').setValue('000000')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockPush).not.toHaveBeenCalled()
    expect(errorText(wrapper)).toBe('Invalid verification code')
    expect(wrapper.find('#vault42-totp-code').exists()).toBe(true)
  })

  it('keeps the verify button disabled until the code is six digits', async () => {
    mockRequires2FA.value = true
    mockAvailableMethods.value = ['totp']
    const wrapper = mountView()
    const button = () => wrapper.find('button[type="submit"]').element as HTMLButtonElement

    expect(button().disabled).toBe(true)
    await wrapper.find('#vault42-totp-code').setValue('12345')
    expect(button().disabled).toBe(true)
    await wrapper.find('#vault42-totp-code').setValue('123456')
    expect(button().disabled).toBe(false)
  })

  it('offers the security key first and navigates after it verifies', async () => {
    mockRequires2FA.value = true
    mockChallengeToken.value = 'challenge-xyz'
    mockAvailableMethods.value = ['webauthn', 'totp']
    const wrapper = mountView()

    const keyButton = wrapper.findAll('button').find(b => b.text() === 'Use Security Key')
    expect(keyButton).toBeDefined()
    await keyButton!.trigger('click')
    await flushPromises()

    expect(mockWebAuthnVerify).toHaveBeenCalledWith('challenge-xyz')
    expect(mockVerify2FAWebAuthn).toHaveBeenCalledOnce()
    expect(mockPush).toHaveBeenCalledWith('/')
  })

  it('surfaces a failed security key attempt and stays on the challenge', async () => {
    mockRequires2FA.value = true
    mockAvailableMethods.value = ['webauthn', 'totp']
    mockWebAuthnVerify.mockRejectedValue({ code: 'webauthn_failed' })
    const wrapper = mountView()

    await wrapper.findAll('button').find(b => b.text() === 'Use Security Key')!.trigger('click')
    await flushPromises()

    expect(mockVerify2FAWebAuthn).not.toHaveBeenCalled()
    expect(mockPush).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Security key verification failed. Please try again.')
    expect(wrapper.findAll('button').some(b => b.text() === 'Use Security Key')).toBe(true)
  })

  it('falls back to the email OTP challenge when no key or authenticator is enrolled', async () => {
    mockRequires2FA.value = true
    mockAvailableMethods.value = ['email_otp']
    const wrapper = mountView()

    expect(wrapper.text()).toContain('Check your email for a verification code.')
    await wrapper.find('#vault42-email-otp-code').setValue('654321')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockVerify2FAEmailOTP).toHaveBeenCalledWith('654321')
    expect(mockPush).toHaveBeenCalledWith('/')
  })

  it('restores the resend link after a failed resend instead of hanging on "Sending..."', async () => {
    mockRequires2FA.value = true
    mockAvailableMethods.value = ['email_otp']
    mockResendEmailOTP.mockRejectedValue({ code: 'rate_limited', status: 429 })
    const wrapper = mountView()

    const resend = wrapper.findAll('a').find(a => a.text() === 'Resend code')
    await resend!.trigger('click')
    await flushPromises()

    expect(mockResendEmailOTP).toHaveBeenCalledOnce()
    expect(wrapper.text()).toContain('Resend code')
    expect(wrapper.text()).not.toContain('Sending...')
  })

  it('accepts a backup code as the 2FA fallback', async () => {
    mockRequires2FA.value = true
    mockAvailableMethods.value = ['totp', 'backup_code']
    const wrapper = mountView()

    await wrapper.findAll('a').find(a => a.text() === 'Use a backup code')!.trigger('click')
    await wrapper.find('#vault42-backup-code').setValue('aaaa-bbbb-cccc')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockVerify2FABackupCode).toHaveBeenCalledWith('aaaa-bbbb-cccc')
    expect(mockPush).toHaveBeenCalledWith('/')
  })

  // ---- MFA onboarding handoff ----

  it('routes to MFA onboarding when MFA is required but not yet configured', async () => {
    mockRoute.query = { redirect: '/storage' }
    mockLogin.mockImplementation(async () => {
      mockUser.value = { mfa_required: true, mfa_enabled: false }
    })
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(mockPush).toHaveBeenCalledOnce()
    expect(mockPush).toHaveBeenCalledWith('/mfa-onboarding')
  })

  it('honours the redirect when MFA is required and already configured', async () => {
    mockRoute.query = { redirect: '/storage' }
    mockLogin.mockImplementation(async () => {
      mockUser.value = { mfa_required: true, mfa_enabled: true }
    })
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(mockPush).toHaveBeenCalledWith('/storage')
  })

  // ---- error rendering ----

  it('shows the same message for an unknown account as for a wrong password', async () => {
    mockLogin.mockImplementation(async () => {
      mockError.value = { code: 'invalid_credentials', status: 401 }
      throw mockError.value
    })

    const unknownUser = mountView()
    await submitCredentials(unknownUser, 'nobody@example.com', 'a very long passphrase')
    const unknownUserText = errorText(unknownUser)

    mockError.value = null
    const wrongPassword = mountView()
    await submitCredentials(wrongPassword, 'ada@example.com', 'wrong passphrase here')
    const wrongPasswordText = errorText(wrongPassword)

    expect(unknownUserText).toBe('Invalid email or password')
    expect(wrongPasswordText).toBe(unknownUserText)
    expect(unknownUser.text()).not.toMatch(/no account|not found|unknown|does not exist/i)
    expect(mockPush).not.toHaveBeenCalled()
  })

  it('keeps the typed email after a rejected login so the user can retry', async () => {
    mockLogin.mockImplementation(async () => {
      mockError.value = { code: 'invalid_credentials', status: 401 }
      throw mockError.value
    })
    const wrapper = mountView()
    await submitCredentials(wrapper, 'ada@example.com', 'wrong passphrase here')

    expect((wrapper.find('#vault42-login-email').element as HTMLInputElement).value).toBe('ada@example.com')
    expect((wrapper.find('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(false)
  })

  it('reports a locked account without navigating', async () => {
    mockLogin.mockImplementation(async () => {
      mockError.value = { code: 'account_locked', status: 403 }
      throw mockError.value
    })
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(errorText(wrapper)).toBe('Account temporarily locked. Please try again later.')
    expect(mockPush).not.toHaveBeenCalled()
  })

  it('surfaces a 503 server_busy rejection instead of silently doing nothing', async () => {
    mockLogin.mockImplementation(async () => {
      mockError.value = { code: 'server_busy', status: 503 }
      throw mockError.value
    })
    const wrapper = mountView()
    await submitCredentials(wrapper)

    // The user must be told the attempt failed and must be able to retry —
    // no navigation, a visible error, an enabled button, credentials intact.
    expect(mockPush).not.toHaveBeenCalled()
    expect(wrapper.find('.vault42-login-form__error').exists()).toBe(true)
    expect(errorText(wrapper).trim()).not.toBe('')
    expect((wrapper.find('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(false)
    expect((wrapper.find('#vault42-login-email').element as HTMLInputElement).value).toBe('user@example.com')
  })

  it('renders a generic failure when the error carries no code', async () => {
    mockLogin.mockImplementation(async () => {
      mockError.value = {}
      throw new Error('network down')
    })
    const wrapper = mountView()
    await submitCredentials(wrapper)

    expect(errorText(wrapper)).toBe('Login failed')
    expect(mockPush).not.toHaveBeenCalled()
  })

  // ---- disabled while submitting ----

  it('disables the submit button and blocks a second submit while the login is in flight', async () => {
    let finishLogin: () => void = () => {}
    mockLogin.mockImplementation(() => {
      mockIsLoading.value = true
      return new Promise<void>(resolve => {
        finishLogin = () => {
          mockIsLoading.value = false
          resolve()
        }
      })
    })

    const wrapper = mountView()
    await wrapper.find('#vault42-login-email').setValue('ada@example.com')
    await wrapper.find('#vault42-login-password').setValue('a very long passphrase')
    await wrapper.find('form').trigger('submit')
    await nextTick()

    const button = wrapper.find('button[type="submit"]')
    expect((button.element as HTMLButtonElement).disabled).toBe(true)
    expect(button.text()).toBe('Signing in...')

    // The disabled default button is the only double-submit guard: a click on
    // it must not start a second login while the first is still in flight.
    await button.trigger('click')
    await nextTick()
    expect(mockLogin).toHaveBeenCalledOnce()

    finishLogin()
    await flushPromises()
    expect(mockPush).toHaveBeenCalledWith('/')
    expect((wrapper.find('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(false)
  })

  // ---- ancillary navigation ----

  it('shows the password-changed notice only when the login was reached that way', async () => {
    const plain = mountView()
    expect(plain.text()).not.toContain('Password changed. Please log in with your new password.')

    mockRoute.query = { reason: 'password_changed' }
    await nextTick()
    expect(plain.find('.vault42-alert-success').text()).toBe('Password changed. Please log in with your new password.')
  })

  it('starts the OAuth flow for the provider whose button was clicked', async () => {
    const wrapper = mountView()
    const buttons = wrapper.findAll('.vault42-btn-outline')

    await buttons[0].trigger('click')
    await buttons[1].trigger('click')
    await buttons[2].trigger('click')

    expect(mockAuthorize.mock.calls).toEqual([['github'], ['google'], ['facebook']])
  })

  it('routes to password reset from the form link', async () => {
    const wrapper = mountView()

    await wrapper.findAll('a').find(a => a.text() === 'Forgot password?')!.trigger('click')

    expect(mockPush).toHaveBeenCalledWith('/forgot-password')
  })

  // NOTE: the "Create an account" link never renders — VaultLoginForm declares
  // `showRegisterLink?: boolean` as a type-only prop, so Vue's boolean casting
  // turns the absent prop into `false` and the `showRegisterLink !== false`
  // guard is never satisfied. LoginView does not bind the prop, so the handler
  // below is currently unreachable from the UI. Reported, not encoded: this
  // test pins the view's contract for the event itself.
  it('routes to registration when the form asks for it', async () => {
    const wrapper = mountView()

    wrapper.findComponent({ name: 'VaultLoginForm' }).vm.$emit('register-click')
    await nextTick()

    expect(mockPush).toHaveBeenCalledWith('/register')
  })
})
