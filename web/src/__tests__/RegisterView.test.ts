import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises, RouterLinkStub } from '@vue/test-utils'
import { ref, nextTick } from 'vue'
import RegisterView from '../views/RegisterView.vue'
import en from '../locales/en.json'

// RegisterView is a shell around VaultRegisterForm: the password rules, the
// breach rejection and the anti-enumeration success copy all live in that form
// and reach the view as a `success` event. Stubbing the form would test
// nothing, so the real component is mounted over a faked auth layer.
const mockRegister = vi.fn()

const mockError = ref<{ code?: string; status?: number } | null>(null)
const mockIsLoading = ref(false)

const authState = {
  register: mockRegister,
  error: mockError,
  isLoading: mockIsLoading,
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

vi.mock('@vault42/vue', async () => ({
  VaultRegisterForm: (await import('../../../packages/vue/src/components/VaultRegisterForm.vue')).default,
  useT: () => tShim,
}))

function mountView() {
  return mount(RegisterView, {
    global: {
      stubs: { RouterLink: RouterLinkStub, Teleport: true },
    },
  })
}

type Wrapper = ReturnType<typeof mountView>

const VALID_PASSWORD = 'correct horse battery staple' // 28 chars, no composition tricks

async function fillForm(wrapper: Wrapper, opts: { email?: string; password?: string; confirm?: string; name?: string } = {}) {
  const password = opts.password ?? VALID_PASSWORD
  if (opts.name !== undefined) await wrapper.find('#vault42-reg-name').setValue(opts.name)
  await wrapper.find('#vault42-reg-email').setValue(opts.email ?? 'ada@example.com')
  await wrapper.find('#vault42-reg-password').setValue(password)
  await wrapper.find('#vault42-reg-confirm').setValue(opts.confirm ?? password)
  await nextTick()
}

function submitButton(wrapper: Wrapper): HTMLButtonElement {
  return wrapper.find('button[type="submit"]').element as HTMLButtonElement
}

async function submit(wrapper: Wrapper) {
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

/**
 * Clicks the real submit button. VaultRegisterForm has no in-handler guard —
 * `:disabled="!canSubmit"` on the default button is the whole defence — so an
 * invalid-input test has to go through the button the user can actually press.
 */
async function clickSubmit(wrapper: Wrapper) {
  await wrapper.find('button[type="submit"]').trigger('click')
  await flushPromises()
}

describe('RegisterView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockError.value = null
    mockIsLoading.value = false
    mockRegister.mockResolvedValue(undefined)
  })

  it('states the 15-character minimum up front', () => {
    const wrapper = mountView()
    expect(wrapper.find('h1').text()).toBe('Create your account')
    expect(wrapper.text()).toContain('Passwords must be at least 15 characters')
  })

  // ---- password rules: NIST length only, no composition rules ----

  it('rejects a 14-character password and explains the minimum', async () => {
    const wrapper = mountView()
    await fillForm(wrapper, { password: '12345678901234' })

    expect(wrapper.text()).toContain('Minimum 15 characters')
    expect(submitButton(wrapper).disabled).toBe(true)

    await clickSubmit(wrapper)
    expect(mockRegister).not.toHaveBeenCalled()
  })

  it('accepts a plain 15-character passphrase with no composition rules', async () => {
    const wrapper = mountView()
    await fillForm(wrapper, { password: 'aaaaaaaaaaaaaaa' })

    expect(wrapper.text()).not.toContain('Minimum 15 characters')
    expect(submitButton(wrapper).disabled).toBe(false)

    await submit(wrapper)
    expect(mockRegister).toHaveBeenCalledWith('ada@example.com', 'aaaaaaaaaaaaaaa', undefined)
  })

  it('enforces the minimum in the markup as well as the guard', () => {
    const wrapper = mountView()
    expect(wrapper.find('#vault42-reg-password').attributes('minlength')).toBe('15')
  })

  it('blocks submission while the confirmation does not match', async () => {
    const wrapper = mountView()
    await fillForm(wrapper, { confirm: VALID_PASSWORD + '!' })

    expect(wrapper.text()).toContain('Passwords do not match')
    expect(submitButton(wrapper).disabled).toBe(true)

    await clickSubmit(wrapper)
    expect(mockRegister).not.toHaveBeenCalled()
  })

  it('does not nag about a mismatch before the confirmation is typed', async () => {
    const wrapper = mountView()
    await wrapper.find('#vault42-reg-password').setValue(VALID_PASSWORD)
    await nextTick()

    expect(wrapper.text()).not.toContain('Passwords do not match')
  })

  it('sends the display name when one is given', async () => {
    const wrapper = mountView()
    await fillForm(wrapper, { name: 'Ada Lovelace' })
    await submit(wrapper)

    expect(mockRegister).toHaveBeenCalledWith('ada@example.com', VALID_PASSWORD, 'Ada Lovelace')
  })

  // ---- success / anti-enumeration ----

  it('replaces the form with the check-your-email panel after registering', async () => {
    const wrapper = mountView()
    await fillForm(wrapper)
    await submit(wrapper)

    expect(wrapper.text()).toContain('Account Created')
    expect(wrapper.text()).toContain('Check your email for a verification link to activate your account.')
    expect(wrapper.find('form').exists()).toBe(false)
  })

  it('shows an identical panel for a duplicate email as for a fresh one', async () => {
    // The server answers a duplicate registration with the same 201
    // "verification_email_sent" body it sends for a new account, so the SPA
    // must not be able to tell the two apart.
    const fresh = mountView()
    await fillForm(fresh, { email: 'new@example.com' })
    await submit(fresh)
    const freshPanel = fresh.find('.vault42-card').text()

    const duplicate = mountView()
    await fillForm(duplicate, { email: 'taken@example.com' })
    await submit(duplicate)
    const duplicatePanel = duplicate.find('.vault42-card').text()

    expect(duplicatePanel).toBe(freshPanel)
    expect(duplicatePanel).not.toMatch(/already|exists|taken|registered account/i)
  })

  // ---- error branches ----

  it('reports a breached password and keeps the user on the form', async () => {
    mockRegister.mockImplementation(async () => {
      mockError.value = { code: 'password_breached', status: 400 }
      throw mockError.value
    })
    const wrapper = mountView()
    await fillForm(wrapper)
    await submit(wrapper)

    expect(wrapper.find('.vault42-register-form__error').text()).toBe('This password has been found in a data breach')
    expect(wrapper.text()).not.toContain('Account Created')
    expect(wrapper.find('form').exists()).toBe(true)
  })

  it('keeps the typed email after a breach rejection so only the password must change', async () => {
    mockRegister.mockImplementation(async () => {
      mockError.value = { code: 'password_breached', status: 400 }
      throw mockError.value
    })
    const wrapper = mountView()
    await fillForm(wrapper, { email: 'ada@example.com', name: 'Ada Lovelace' })
    await submit(wrapper)

    expect((wrapper.find('#vault42-reg-email').element as HTMLInputElement).value).toBe('ada@example.com')
    expect((wrapper.find('#vault42-reg-name').element as HTMLInputElement).value).toBe('Ada Lovelace')
    expect(submitButton(wrapper).disabled).toBe(false)
  })

  it('surfaces a 403 registration_disabled rejection instead of faking success', async () => {
    // The register route is normally gated by GET /auth/capabilities, but that
    // call is fire-and-forget: a user who lands here before it resolves can
    // still submit and get a 403 back from POST /auth/register.
    mockRegister.mockImplementation(async () => {
      mockError.value = { code: 'registration_disabled', status: 403 }
      throw mockError.value
    })
    const wrapper = mountView()
    await fillForm(wrapper)
    await submit(wrapper)

    expect(wrapper.text()).not.toContain('Account Created')
    expect(wrapper.find('.vault42-register-form__error').exists()).toBe(true)
    expect(wrapper.find('.vault42-register-form__error').text().trim()).not.toBe('')
    expect(wrapper.find('form').exists()).toBe(true)
  })

  it('reports rate limiting without claiming the account was created', async () => {
    mockRegister.mockImplementation(async () => {
      mockError.value = { code: 'rate_limited', status: 429 }
      throw mockError.value
    })
    const wrapper = mountView()
    await fillForm(wrapper)
    await submit(wrapper)

    expect(wrapper.find('.vault42-register-form__error').text()).toBe('Too many attempts. Please try again later')
    expect(wrapper.text()).not.toContain('Account Created')
  })

  it('falls back to a generic failure when the rejection carries no code', async () => {
    mockRegister.mockImplementation(async () => {
      mockError.value = {}
      throw new Error('network down')
    })
    const wrapper = mountView()
    await fillForm(wrapper)
    await submit(wrapper)

    expect(wrapper.find('.vault42-register-form__error').text()).toBe('Registration failed')
    expect(wrapper.text()).not.toContain('Account Created')
  })

  // ---- disabled while submitting ----

  it('disables the button and blocks a second submit while registering', async () => {
    let finishRegister: () => void = () => {}
    mockRegister.mockImplementation(() => {
      mockIsLoading.value = true
      return new Promise<void>(resolve => {
        finishRegister = () => {
          mockIsLoading.value = false
          resolve()
        }
      })
    })

    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await nextTick()

    const button = wrapper.find('button[type="submit"]')
    expect((button.element as HTMLButtonElement).disabled).toBe(true)
    expect(button.text()).toBe('Creating account...')

    await button.trigger('click')
    await nextTick()
    expect(mockRegister).toHaveBeenCalledOnce()

    finishRegister()
    await flushPromises()
    expect(wrapper.text()).toContain('Account Created')
  })

  // ---- navigation out ----

  it('offers a sign-in link from both the form and the success panel', async () => {
    const wrapper = mountView()
    expect(wrapper.findAllComponents(RouterLinkStub).some(l => l.props('to') === '/login')).toBe(true)

    await fillForm(wrapper)
    await submit(wrapper)

    const links = wrapper.findAllComponents(RouterLinkStub)
    expect(links).toHaveLength(1)
    expect(links[0].props('to')).toBe('/login')
  })
})
