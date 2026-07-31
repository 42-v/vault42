import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, nextTick } from 'vue'
import VaultLoginForm from '../components/VaultLoginForm.vue'
import { createI18nPlugin } from '../i18n/plugin'
import type { VaultError } from '../types'

const mockLogin = vi.fn()
const mockVerify2FA = vi.fn()
const mockVerify2FABackupCode = vi.fn()
const mockVerify2FAEmailOTP = vi.fn()
const mockVerify2FAWebAuthn = vi.fn()
const mockWebAuthnVerify = vi.fn()
const mockResendEmailOTP = vi.fn()

const user = ref<Record<string, unknown> | null>(null)
const error = ref<VaultError | null>(null)
const isLoading = ref(false)
const requires2FA = ref(false)
const challengeToken = ref<string | null>(null)
const availableMethods = ref<string[]>([])
const webauthnSupported = ref(true)
const webauthnLoading = ref(false)

vi.mock('../composables/useAuth', () => ({
  useAuth: () => ({
    user,
    error,
    isLoading,
    requires2FA,
    challengeToken,
    availableMethods,
    login: mockLogin,
    verify2FA: mockVerify2FA,
    verify2FABackupCode: mockVerify2FABackupCode,
    verify2FAEmailOTP: mockVerify2FAEmailOTP,
    verify2FAWebAuthn: mockVerify2FAWebAuthn,
  }),
}))

vi.mock('../composables/useWebAuthn', () => ({
  useWebAuthn: () => ({
    isSupported: webauthnSupported,
    isLoading: webauthnLoading,
    verify: mockWebAuthnVerify,
  }),
}))

vi.mock('../plugin', () => ({
  useVaultClient: () => ({ resendEmailOTP: mockResendEmailOTP }),
}))

type MountOptions = Parameters<typeof mount<typeof VaultLoginForm>>[1]

function mountForm(options: MountOptions = {}) {
  return mount(VaultLoginForm, options)
}

type Wrapper = ReturnType<typeof mountForm>

async function fill(wrapper: Wrapper, email = 'ada@example.com', password = 'a very long passphrase') {
  await wrapper.find('#vault42-login-email').setValue(email)
  await wrapper.find('#vault42-login-password').setValue(password)
}

function errorText(wrapper: Wrapper): string {
  return wrapper.find('.vault42-login-form__error').text()
}

async function failLoginWith(wrapper: Wrapper, code: string) {
  mockLogin.mockImplementation(async () => {
    error.value = { code, status: 400 } as VaultError
    throw error.value
  })
  await fill(wrapper)
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  user.value = null
  error.value = null
  isLoading.value = false
  requires2FA.value = false
  challengeToken.value = null
  availableMethods.value = []
  webauthnSupported.value = true
  webauthnLoading.value = false
  mockLogin.mockResolvedValue(undefined)
  mockWebAuthnVerify.mockResolvedValue(undefined)
  mockVerify2FAWebAuthn.mockResolvedValue(undefined)
})

describe('VaultLoginForm register link', () => {
  it('renders the register link by default and emits register-click', async () => {
    const wrapper = mountForm()
    const link = wrapper.find('.vault42-login-form__register-link a')

    expect(link.exists()).toBe(true)
    expect(link.text()).toBe('Create an account')

    await link.trigger('click')
    expect(wrapper.emitted('register-click')).toHaveLength(1)
  })

  it('hides the register link only when the host opts out', () => {
    const wrapper = mountForm({ props: { showRegisterLink: false } })

    expect(wrapper.find('.vault42-login-form__register-link').exists()).toBe(false)
  })
})

describe('VaultLoginForm error copy', () => {
  it('renders friendly copy for a 503 server_busy rejection', async () => {
    const wrapper = mountForm()
    await failLoginWith(wrapper, 'server_busy')

    expect(errorText(wrapper)).toBe('The server is busy right now. Please try again in a moment.')
  })

  it.each([
    ['account_banned', 'This account is not available. Please contact support.'],
    ['account_disabled', 'This account is not available. Please contact support.'],
    ['too_many_attempts', 'Too many failed attempts. Please try again later.'],
    ['too_many_sessions', 'Too many active sessions. Sign out on another device and try again.'],
    ['rate_limit_exceeded', 'Too many attempts. Please wait and try again.'],
  ])('renders friendly copy for %s', async (code, copy) => {
    const wrapper = mountForm()
    await failLoginWith(wrapper, code)

    expect(errorText(wrapper)).toBe(copy)
  })

  it('never echoes an unmapped server code back into the DOM', async () => {
    const wrapper = mountForm()
    await failLoginWith(wrapper, 'totally_unknown_code_<img src=x>')

    expect(errorText(wrapper)).toBe('Something went wrong. Please try again.')
    expect(wrapper.html()).not.toContain('totally_unknown_code')
  })

  it('lets the host override copy through the errorMessages prop', async () => {
    const wrapper = mountForm({ props: { errorMessages: { server_busy: 'Try again shortly' } } })
    await failLoginWith(wrapper, 'server_busy')

    expect(errorText(wrapper)).toBe('Try again shortly')
  })

  it('maps a WebAuthn failure code instead of showing it raw', async () => {
    requires2FA.value = true
    availableMethods.value = ['webauthn']
    mockWebAuthnVerify.mockRejectedValue({ code: 'cloned_authenticator_detected', status: 401 })
    const wrapper = mountForm()

    await wrapper.find('.vault42-login-form__2fa-button').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('This security key was rejected for security reasons.')
    expect(wrapper.html()).not.toContain('cloned_authenticator_detected')
  })
})

describe('VaultLoginForm submit guard', () => {
  it('ignores a submit event dispatched with empty credentials', async () => {
    const wrapper = mountForm()

    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockLogin).not.toHaveBeenCalled()
  })

  it('ignores a submit event dispatched while a login is in flight', async () => {
    const wrapper = mountForm()
    await fill(wrapper)
    mockLogin.mockImplementation(() => {
      isLoading.value = true
      return new Promise<void>(() => {})
    })

    await wrapper.find('form').trigger('submit')
    await nextTick()
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockLogin).toHaveBeenCalledOnce()
  })

  it('still submits a filled form', async () => {
    const wrapper = mountForm()
    await fill(wrapper, 'ada@example.com', 'a very long passphrase')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockLogin).toHaveBeenCalledWith('ada@example.com', 'a very long passphrase', false)
    expect(wrapper.emitted('success')).toHaveLength(1)
  })
})

describe('VaultLoginForm i18n', () => {
  const de = {
    'login.email': 'E-Mail',
    'login.password': 'Passwort',
    'login.submit': 'Anmelden',
    'login.signingIn': 'Anmeldung...',
    'login.createAccount': 'Konto erstellen',
    'login.failed': 'Anmeldung fehlgeschlagen',
    'login.2fa.verify': 'Bestaetigen',
  }

  function mountLocalized(locale = 'de') {
    return mountForm({
      global: { plugins: [createI18nPlugin({ locale, messages: { de } })] },
    })
  }

  it('renders the locale copy for the credential form', () => {
    const wrapper = mountLocalized()

    expect(wrapper.find('label[for="vault42-login-email"]').text()).toBe('E-Mail')
    expect(wrapper.find('label[for="vault42-login-password"]').text()).toBe('Passwort')
    expect(wrapper.find('button[type="submit"]').text()).toBe('Anmelden')
    expect(wrapper.find('.vault42-login-form__register-link a').text()).toBe('Konto erstellen')
  })

  it('renders the locale copy for the 2FA step', () => {
    requires2FA.value = true
    availableMethods.value = ['totp']
    const wrapper = mountLocalized()

    expect(wrapper.find('button[type="submit"]').text()).toBe('Bestaetigen')
  })

  it('falls back to English for a key the locale does not carry', () => {
    const wrapper = mountLocalized()

    expect(wrapper.find('.vault42-login-form__forgot-link').text()).toBe('Forgot password?')
    expect(wrapper.find('h2').text()).toBe('Sign In')
  })

  it('re-renders when the locale changes', async () => {
    const plugin = createI18nPlugin({ locale: 'en', messages: { de, en: {} } })
    const wrapper = mountForm({ global: { plugins: [plugin] } })

    expect(wrapper.find('button[type="submit"]').text()).toBe('Sign In')

    plugin.instance.setLocale('de')
    await nextTick()

    expect(wrapper.find('button[type="submit"]').text()).toBe('Anmelden')
  })
})
