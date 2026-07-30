import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import ForgotPasswordView from '../views/ForgotPasswordView.vue'
import en from '../locales/en.json'

const mockRequestReset = vi.fn()

const mockIsLoading = ref(false)
const mockError = ref<{ code: string } | null>(null)
const mockRequested = ref(false)

vi.mock('@vault42/vue', () => ({
  usePasswordReset: () => ({
    isLoading: mockIsLoading,
    error: mockError,
    requested: mockRequested,
    confirmed: ref(false),
    requestReset: mockRequestReset,
    confirmReset: vi.fn(),
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

const RouterLinkStub = {
  props: ['to'],
  template: '<a :href="to"><slot /></a>',
}

function mountView() {
  return mount(ForgotPasswordView, {
    global: {
      stubs: {
        Teleport: true,
        RouterLink: RouterLinkStub,
      },
    },
  })
}

/** Fills the email field and submits the form, resolving the request. */
async function submitEmail(wrapper: ReturnType<typeof mountView>, email: string) {
  await wrapper.find('#reset-email').setValue(email)
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

describe('ForgotPasswordView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIsLoading.value = false
    mockError.value = null
    mockRequested.value = false
    // Mirrors the real composable: the server answers 200 for every address,
    // so the composable flips `requested` no matter who was asked for.
    mockRequestReset.mockImplementation(async () => {
      mockRequested.value = true
    })
  })

  it('renders the page title', () => {
    const wrapper = mountView()
    expect(wrapper.find('h1').text()).toBe('Reset Password')
  })

  it('requests a reset for the exact address typed', async () => {
    const wrapper = mountView()
    await submitEmail(wrapper, 'someone@example.com')

    expect(mockRequestReset).toHaveBeenCalledOnce()
    expect(mockRequestReset).toHaveBeenCalledWith('someone@example.com')
  })

  it('does not fire a request when the email field is empty', async () => {
    const wrapper = mountView()
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockRequestReset).not.toHaveBeenCalled()
  })

  it('renders byte-identical confirmation for a registered and an unregistered address', async () => {
    // Account exists.
    const known = mountView()
    await submitEmail(known, 'registered@example.com')
    const knownHtml = known.find('.vault42-card').html()

    // Account does not exist — the API still answers 200.
    mockRequested.value = false
    const unknown = mountView()
    await submitEmail(unknown, 'nobody-here@example.com')
    const unknownHtml = unknown.find('.vault42-card').html()

    expect(unknownHtml).toBe(knownHtml)
  })

  it('never echoes the submitted address back into the confirmation', async () => {
    const wrapper = mountView()
    await submitEmail(wrapper, 'victim@example.com')

    expect(wrapper.text()).not.toContain('victim@example.com')
    expect(wrapper.find('input#reset-email').exists()).toBe(false)
  })

  it('states the outcome conditionally so existence is not disclosed', async () => {
    const wrapper = mountView()
    await submitEmail(wrapper, 'someone@example.com')

    expect(wrapper.text()).toContain('Check Your Email')
    expect(wrapper.text()).toContain("If an account with that email exists, we've sent a password reset link. It expires in 1 hour.")
  })

  it('replaces the form with the confirmation so it cannot be resubmitted', async () => {
    const wrapper = mountView()
    await submitEmail(wrapper, 'someone@example.com')

    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.find('a[href="/login"]').text()).toBe('Back to Sign In')
  })

  it('shows a friendly error and keeps the form when the request fails', async () => {
    mockRequestReset.mockImplementation(async () => {
      mockError.value = { code: 'rate_limited' }
    })
    const wrapper = mountView()
    await submitEmail(wrapper, 'someone@example.com')

    expect(wrapper.find('.vault42-alert-error').text()).toBe('Too many requests. Please wait a moment.')
    expect(wrapper.text()).not.toContain('Check Your Email')
    expect(wrapper.find('form').exists()).toBe(true)
  })

  it('falls back to generic copy for an unrecognised error code', async () => {
    mockRequestReset.mockImplementation(async () => {
      mockError.value = { code: 'some_new_server_code' }
    })
    const wrapper = mountView()
    await submitEmail(wrapper, 'someone@example.com')

    expect(wrapper.find('.vault42-alert-error').text()).toBe('Something went wrong. Please try again.')
  })

  it('keeps the typed address after a failed request so it need not be retyped', async () => {
    mockRequestReset.mockImplementation(async () => {
      mockError.value = { code: 'internal_error' }
    })
    const wrapper = mountView()
    await submitEmail(wrapper, 'someone@example.com')

    expect((wrapper.find('#reset-email').element as HTMLInputElement).value).toBe('someone@example.com')
  })

  it('disables the submit button and shows progress while the request is in flight', async () => {
    const wrapper = mountView()
    await wrapper.find('#reset-email').setValue('someone@example.com')
    mockIsLoading.value = true
    await wrapper.vm.$nextTick()

    const btn = wrapper.find('button[type="submit"]')
    expect((btn.element as HTMLButtonElement).disabled).toBe(true)
    expect(btn.text()).toBe('Sending...')
    expect(btn.find('.vault42-spinner').exists()).toBe(true)
  })

  it('disables the submit button until an address is entered', async () => {
    const wrapper = mountView()
    const btn = wrapper.find('button[type="submit"]')
    expect((btn.element as HTMLButtonElement).disabled).toBe(true)

    await wrapper.find('#reset-email').setValue('someone@example.com')
    expect((btn.element as HTMLButtonElement).disabled).toBe(false)
    expect(btn.text()).toBe('Send Reset Link')
  })
})
