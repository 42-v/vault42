import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, nextTick } from 'vue'
import VaultRegisterForm from '../components/VaultRegisterForm.vue'
import { createI18nPlugin } from '../i18n/plugin'
import type { VaultError } from '../types'

const mockRegister = vi.fn()

const error = ref<VaultError | null>(null)
const isLoading = ref(false)

vi.mock('../composables/useAuth', () => ({
  useAuth: () => ({
    error,
    isLoading,
    register: mockRegister,
  }),
}))

type MountOptions = Parameters<typeof mount<typeof VaultRegisterForm>>[1]

function mountForm(options: MountOptions = {}) {
  return mount(VaultRegisterForm, options)
}

type Wrapper = ReturnType<typeof mountForm>

const VALID_PASSWORD = 'correct horse battery staple'

async function fill(
  wrapper: Wrapper,
  opts: { email?: string; password?: string; confirm?: string } = {},
) {
  const password = opts.password ?? VALID_PASSWORD
  await wrapper.find('#vault42-reg-email').setValue(opts.email ?? 'ada@example.com')
  await wrapper.find('#vault42-reg-password').setValue(password)
  await wrapper.find('#vault42-reg-confirm').setValue(opts.confirm ?? password)
  await nextTick()
}

function errorText(wrapper: Wrapper): string {
  return wrapper.find('.vault42-register-form__error').text()
}

async function failRegisterWith(wrapper: Wrapper, code: string) {
  mockRegister.mockImplementation(async () => {
    error.value = { code, status: 400 } as VaultError
    throw error.value
  })
  await fill(wrapper)
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  error.value = null
  isLoading.value = false
  mockRegister.mockResolvedValue(undefined)
})

describe('VaultRegisterForm error copy', () => {
  it('gives no enumeration signal for an email-conflict code', async () => {
    // The server answers a duplicate registration with the same 201 it sends
    // for a new account, so the form must never render copy that confirms an
    // address is already registered, whatever code reaches it.
    for (const code of ['email_taken', 'email_already_registered']) {
      const wrapper = mountForm()
      await failRegisterWith(wrapper, code)

      expect(errorText(wrapper)).toBe('Something went wrong. Please try again.')
      expect(wrapper.text()).not.toMatch(/already|exists|taken|registered/i)
      error.value = null
    }
  })

  it.each([
    ['registration_disabled', 'Registration is currently closed.'],
    ['server_busy', 'The server is busy right now. Please try again in a moment.'],
    ['rate_limit_exceeded', 'Too many attempts. Please try again later'],
    ['invalid_input', 'Please check the details you entered and try again'],
  ])('renders friendly copy for %s', async (code, copy) => {
    const wrapper = mountForm()
    await failRegisterWith(wrapper, code)

    expect(errorText(wrapper)).toBe(copy)
  })

  it('never echoes an unmapped server code back into the DOM', async () => {
    const wrapper = mountForm()
    await failRegisterWith(wrapper, 'totally_unknown_code_<img src=x>')

    expect(errorText(wrapper)).toBe('Something went wrong. Please try again.')
    expect(wrapper.html()).not.toContain('totally_unknown_code')
  })

  it('states the configured minimum in the too-short message', async () => {
    const wrapper = mountForm({ props: { minPasswordLength: 20 } })
    await fill(wrapper, { password: 'a'.repeat(20), confirm: 'a'.repeat(20) })
    await failRegisterWith(wrapper, 'password_too_short')

    expect(errorText(wrapper)).toBe('Password must be at least 20 characters')
  })
})

describe('VaultRegisterForm submit guard', () => {
  it('ignores a submit event dispatched with a too-short password', async () => {
    const wrapper = mountForm()
    await fill(wrapper, { password: '12345678901234', confirm: '12345678901234' })

    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockRegister).not.toHaveBeenCalled()
  })

  it('ignores a submit event dispatched with a mismatched confirmation', async () => {
    const wrapper = mountForm()
    await fill(wrapper, { confirm: VALID_PASSWORD + '!' })

    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockRegister).not.toHaveBeenCalled()
  })

  it('still submits a valid form', async () => {
    const wrapper = mountForm()
    await fill(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockRegister).toHaveBeenCalledWith('ada@example.com', VALID_PASSWORD, undefined)
    expect(wrapper.emitted('success')).toHaveLength(1)
  })
})

describe('VaultRegisterForm i18n', () => {
  const de = {
    'register.header': 'Konto erstellen',
    'register.email': 'E-Mail',
    'register.password': 'Passwort',
    'register.confirmPassword': 'Passwort bestaetigen',
    'register.submit': 'Konto anlegen',
    'register.minChars': 'Mindestens {count} Zeichen',
    'register.passwordsDoNotMatch': 'Passwoerter stimmen nicht ueberein',
  }

  function mountLocalized(props: Record<string, unknown> = {}) {
    return mountForm({
      props,
      global: { plugins: [createI18nPlugin({ locale: 'de', messages: { de } })] },
    })
  }

  it('renders the locale copy for the form', () => {
    const wrapper = mountLocalized()

    expect(wrapper.find('h2').text()).toBe('Konto erstellen')
    expect(wrapper.find('label[for="vault42-reg-email"]').text()).toBe('E-Mail')
    expect(wrapper.find('label[for="vault42-reg-confirm"]').text()).toBe('Passwort bestaetigen')
    expect(wrapper.find('button[type="submit"]').text()).toBe('Konto anlegen')
  })

  it('interpolates the minimum length into the locale hint', async () => {
    const wrapper = mountLocalized({ minPasswordLength: 20 })
    await wrapper.find('#vault42-reg-password').setValue('too short')
    await nextTick()

    expect(wrapper.find('.vault42-register-form__hint--error').text()).toBe('Mindestens 20 Zeichen')
  })

  it('falls back to English for a key the locale does not carry', () => {
    const wrapper = mountLocalized()

    expect(wrapper.find('label[for="vault42-reg-name"]').text()).toBe('Display Name')
  })
})
