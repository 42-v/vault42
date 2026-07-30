import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, defineComponent, h } from 'vue'
import PasswordView from '../views/PasswordView.vue'
import en from '../locales/en.json'

const mockChangePassword = vi.fn()
const mockLogout = vi.fn()
const mockPush = vi.fn()

const mockIsLoading = ref(false)
const mockError = ref<{ code: string } | null>(null)
const mockGuardSlot = ref<'default' | 'loading'>('default')

vi.mock('@vault42/vue', () => ({
  usePasswordReset: () => ({
    isLoading: mockIsLoading,
    error: mockError,
    requested: ref(false),
    confirmed: ref(false),
    requestReset: vi.fn(),
    confirmReset: vi.fn(),
    changePassword: mockChangePassword,
  }),
  useAuth: () => ({
    logout: mockLogout,
  }),
  useT: () => ({
    t: (key: string, params?: Record<string, string | number>) => {
      const val = (en as Record<string, string>)[key] ?? key
      if (!params) return val
      return val.replace(/\{(\w+)\}/g, (_, name: string) => params[name] != null ? String(params[name]) : `{${name}}`)
    },
    formatDate: (d: Date) => d.toLocaleDateString(),
  }),
  VaultAuthGuard: defineComponent({
    setup(_, { slots }) {
      return () => mockGuardSlot.value === 'loading'
        ? (slots.loading ? slots.loading() : h('div'))
        : (slots.default ? slots.default() : h('div'))
    },
  }),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mockPush }),
}))

const CURRENT = 'my-old-passphrase-01'
const NEW = 'my-brand-new-passphrase'

function mountView() {
  return mount(PasswordView, {
    global: {
      stubs: {
        Teleport: true,
      },
    },
  })
}

async function fillForm(
  wrapper: ReturnType<typeof mountView>,
  opts: { current?: string; next?: string; confirm?: string } = {},
) {
  const current = opts.current ?? CURRENT
  const next = opts.next ?? NEW
  const confirm = opts.confirm ?? next
  await wrapper.find('#password-current').setValue(current)
  await wrapper.find('#password-new').setValue(next)
  await wrapper.find('#password-confirm').setValue(confirm)
}

function submitButton(wrapper: ReturnType<typeof mountView>) {
  return wrapper.find('button[type="submit"]')
}

function isDisabled(wrapper: ReturnType<typeof mountView>) {
  return (submitButton(wrapper).element as HTMLButtonElement).disabled
}

/** Simulates the composable rejecting: error ref is set and the call throws. */
function rejectWith(code: string) {
  mockChangePassword.mockImplementation(async () => {
    mockError.value = { code }
    throw { code }
  })
}

describe('PasswordView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIsLoading.value = false
    mockError.value = null
    mockGuardSlot.value = 'default'
    mockChangePassword.mockResolvedValue(undefined)
    mockLogout.mockResolvedValue(undefined)
  })

  it('renders the page title', () => {
    const wrapper = mountView()
    expect(wrapper.find('h1').text()).toBe('Change Password')
  })

  it('requires the current password before anything can be submitted', async () => {
    const wrapper = mountView()
    await fillForm(wrapper, { current: '' })

    expect(isDisabled(wrapper)).toBe(true)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockChangePassword).not.toHaveBeenCalled()
    expect(wrapper.find('#password-current').attributes('required')).toBeDefined()
  })

  it('blocks submission for a new password shorter than 15 characters', async () => {
    const wrapper = mountView()
    await fillForm(wrapper, { next: 'short-pass-14c' })

    expect(isDisabled(wrapper)).toBe(true)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockChangePassword).not.toHaveBeenCalled()
  })

  it('blocks submission while the confirmation does not match', async () => {
    const wrapper = mountView()
    await fillForm(wrapper, { confirm: NEW + 'x' })

    expect(wrapper.text()).toContain('Passwords do not match')
    expect(isDisabled(wrapper)).toBe(true)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockChangePassword).not.toHaveBeenCalled()
  })

  it('enables submission once every rule is satisfied', async () => {
    const wrapper = mountView()
    await fillForm(wrapper)

    expect(wrapper.text()).not.toContain('Passwords do not match')
    expect(isDisabled(wrapper)).toBe(false)
    expect(submitButton(wrapper).text()).toBe('Update Password')
  })

  it('sends the current and new password in that order', async () => {
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockChangePassword).toHaveBeenCalledOnce()
    expect(mockChangePassword).toHaveBeenCalledWith(CURRENT, NEW)
  })

  it('logs the session out and hands off to login with the password_changed notice', async () => {
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockLogout).toHaveBeenCalledOnce()
    expect(mockPush).toHaveBeenCalledWith({ path: '/login', query: { reason: 'password_changed' } })
    expect(mockLogout.mock.invocationCallOrder[0]).toBeLessThan(mockPush.mock.invocationCallOrder[0])
    expect(mockChangePassword.mock.invocationCallOrder[0]).toBeLessThan(mockLogout.mock.invocationCallOrder[0])
  })

  it('reports a wrong current password instead of a silent no-op', async () => {
    rejectWith('invalid_password')
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('Incorrect password.')
  })

  it('does not sign the user out when the change was rejected', async () => {
    rejectWith('invalid_password')
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockLogout).not.toHaveBeenCalled()
    expect(mockPush).not.toHaveBeenCalled()
    expect(wrapper.find('form').exists()).toBe(true)
  })

  it('keeps every field filled after a rejected change', async () => {
    rejectWith('password_breached')
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect((wrapper.find('#password-current').element as HTMLInputElement).value).toBe(CURRENT)
    expect((wrapper.find('#password-new').element as HTMLInputElement).value).toBe(NEW)
    expect((wrapper.find('#password-confirm').element as HTMLInputElement).value).toBe(NEW)
    expect(wrapper.find('.vault42-alert-error').text()).toBe('This password has appeared in a data breach. Please choose a different one.')
  })

  it('explains a reused password', async () => {
    rejectWith('password_same_as_current')
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('New password must be different from your current password.')
  })

  it('lets the user retry immediately after a rejection', async () => {
    rejectWith('invalid_password')
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(isDisabled(wrapper)).toBe(false)

    mockChangePassword.mockImplementation(async () => {
      mockError.value = null
    })
    await wrapper.find('#password-current').setValue('the-real-old-passphrase')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockChangePassword).toHaveBeenLastCalledWith('the-real-old-passphrase', NEW)
    expect(mockPush).toHaveBeenCalledWith({ path: '/login', query: { reason: 'password_changed' } })
  })

  it('shows progress and locks the button while the change is in flight', async () => {
    mockChangePassword.mockImplementation(() => {
      mockIsLoading.value = true
      return new Promise(() => {})
    })
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(submitButton(wrapper).text()).toBe('Updating...')
    expect(submitButton(wrapper).find('.vault42-spinner').exists()).toBe(true)
    expect(isDisabled(wrapper)).toBe(true)
  })

  it('ignores a second submit while the first is still in flight', async () => {
    mockChangePassword.mockImplementation(() => {
      mockIsLoading.value = true
      return new Promise(() => {})
    })
    const wrapper = mountView()
    await fillForm(wrapper)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockChangePassword).toHaveBeenCalledOnce()
  })

  it('grades the new password strength as the user types', async () => {
    const wrapper = mountView()
    await wrapper.find('#password-new').setValue('abcde')
    expect(wrapper.text()).toContain('Too short (5 characters)')

    await wrapper.find('#password-new').setValue('a'.repeat(22))
    expect(wrapper.text()).toContain('Strong (22 characters)')
  })

  it('withholds the form behind the auth gate while the session is still resolving', () => {
    mockGuardSlot.value = 'loading'
    const wrapper = mountView()

    expect(wrapper.find('.vault42-spinner-lg').exists()).toBe(true)
    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.find('#password-current').exists()).toBe(false)
  })

  it('shows no strength meter before anything is typed', () => {
    const wrapper = mountView()
    expect(wrapper.text()).not.toContain('characters)')
  })
})
