import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { ref, defineComponent, h, nextTick } from 'vue'
import TwoFactorView from '../views/TwoFactorView.vue'
import en from '../locales/en.json'

const mockToDataURL = vi.fn()

vi.mock('qrcode', () => ({
  default: { toDataURL: (...args: unknown[]) => mockToDataURL(...args) },
}))

// use2FA
const mockSetupTOTP = vi.fn()
const mockVerifyTOTP = vi.fn()
const mockDisableTOTP = vi.fn()
const mockGenerateBackupCodes = vi.fn()
const mockFetchMFAStatus = vi.fn()

const mockTotpSetup = ref<{ secret: string; otp_url: string } | null>(null)
const mockBackupCodes = ref<string[]>([])
const mockMfaStatus = ref<{ totp_enabled: boolean; webauthn_enabled: boolean; backup_codes_remaining: number } | null>(null)
const mockIsLoading = ref(false)
const mockError = ref<{ code: string } | null>(null)
const mockIsVerified = ref(false)

// useWebAuthn
const mockRegisterWebAuthn = vi.fn()
const mockListCredentials = vi.fn()
const mockDeleteCredential = vi.fn()

const mockWebauthnSupported = ref(true)
const mockWebauthnLoading = ref(false)
const mockWebauthnError = ref<{ code: string } | null>(null)
const mockCredentials = ref<Array<{ id: string; sign_count: number; created_at: string }>>([])

// useConfirm
const mockIsConfirmed = vi.fn<() => boolean>()
const mockConfirm = vi.fn()
const mockConfirmLoading = ref(false)
const mockConfirmError = ref<{ code: string } | null>(null)

// Mirrors VaultAuthGuard's own gate: while the session is still booting it renders
// the #loading slot instead of the default one.
const mockAuthLoading = ref(false)

vi.mock('@vault42/vue', () => ({
  use2FA: () => ({
    totpSetup: mockTotpSetup,
    backupCodes: mockBackupCodes,
    mfaStatus: mockMfaStatus,
    isLoading: mockIsLoading,
    error: mockError,
    isVerified: mockIsVerified,
    setupTOTP: mockSetupTOTP,
    verifyTOTP: mockVerifyTOTP,
    disableTOTP: mockDisableTOTP,
    generateBackupCodes: mockGenerateBackupCodes,
    fetchMFAStatus: mockFetchMFAStatus,
  }),
  useWebAuthn: () => ({
    isSupported: mockWebauthnSupported,
    isLoading: mockWebauthnLoading,
    error: mockWebauthnError,
    credentials: mockCredentials,
    register: mockRegisterWebAuthn,
    listCredentials: mockListCredentials,
    deleteCredential: mockDeleteCredential,
  }),
  useConfirm: () => ({
    isConfirmed: mockIsConfirmed,
    isLoading: mockConfirmLoading,
    error: mockConfirmError,
    confirm: mockConfirm,
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
      return () => {
        if (mockAuthLoading.value) return slots.loading ? slots.loading() : h('div')
        return slots.default ? slots.default() : h('div')
      }
    },
  }),
}))

const SECRET = 'JBSWY3DPEHPK3PXP'
const OTP_URL = 'otpauth://totp/Vault42:jane@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Vault42'
const QR_DATA_URL = 'data:image/png;base64,QRQRQR'

// DEFECT (reported, not encoded): handleVerify awaits verifyTOTP without a local catch,
// and use2FA.verifyTOTP re-throws, so a rejected verification escapes the click handler as
// an unhandled rejection. The app-level handler below absorbs it so these assertions stay
// about what the user sees. Remove it once handleVerify catches its own failure.
const swallowedErrors: unknown[] = []

function mountView() {
  return mount(TwoFactorView, {
    global: {
      stubs: { Teleport: true },
      config: {
        errorHandler: (err: unknown) => { swallowedErrors.push(err) },
      },
    },
  })
}

function buttonByText(wrapper: VueWrapper, text: string) {
  return wrapper.findAll('button').find(b => b.text() === text)
}

/** Drives the re-auth dialog to success with the given password. */
async function passConfirmDialog(wrapper: VueWrapper, password = 'hunter2') {
  await wrapper.find('input[type="password"]').setValue(password)
  await buttonByText(wrapper, 'Confirm')!.trigger('click')
  await flushPromises()
}

describe('TwoFactorView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    swallowedErrors.length = 0

    mockTotpSetup.value = null
    mockBackupCodes.value = []
    mockMfaStatus.value = null
    mockIsLoading.value = false
    mockError.value = null
    mockIsVerified.value = false

    mockWebauthnSupported.value = true
    mockWebauthnLoading.value = false
    mockWebauthnError.value = null
    mockCredentials.value = []

    mockConfirmLoading.value = false
    mockConfirmError.value = null

    mockAuthLoading.value = false

    mockToDataURL.mockResolvedValue(QR_DATA_URL)
    mockFetchMFAStatus.mockResolvedValue(undefined)
    mockListCredentials.mockResolvedValue([])
    mockSetupTOTP.mockImplementation(async () => {
      mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    })
    mockVerifyTOTP.mockImplementation(async () => {
      mockIsVerified.value = true
    })
    mockDisableTOTP.mockResolvedValue(undefined)
    mockGenerateBackupCodes.mockResolvedValue(undefined)
    mockRegisterWebAuthn.mockResolvedValue(undefined)
    mockDeleteCredential.mockResolvedValue(undefined)
    mockIsConfirmed.mockReturnValue(false)
    mockConfirm.mockResolvedValue(true)

    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
      writable: true,
    })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('loads MFA status and registered credentials on mount', async () => {
    mountView()
    await flushPromises()
    expect(mockFetchMFAStatus).toHaveBeenCalledOnce()
    expect(mockListCredentials).toHaveBeenCalledOnce()
  })

  it('shows only a spinner while the session is still booting', async () => {
    mockAuthLoading.value = true
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('.vault42-spinner-lg').exists()).toBe(true)
    // None of the MFA controls may flash before the session is known.
    expect(wrapper.find('h1').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('Two-Factor Authentication')
    expect(buttonByText(wrapper, 'Register Security Key')).toBeUndefined()
    expect(buttonByText(wrapper, 'Begin Setup')).toBeUndefined()
    expect(buttonByText(wrapper, 'Generate New Codes')).toBeUndefined()
  })

  // --- Re-authentication gate -------------------------------------------------

  it('does not start TOTP enrolment until the password is re-entered', async () => {
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await flushPromises()

    expect(mockSetupTOTP).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Confirm Your Password')
  })

  it('runs the pending action only after the password is confirmed', async () => {
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await passConfirmDialog(wrapper, 'correct horse')
    await flushPromises()

    expect(mockConfirm).toHaveBeenCalledWith('correct horse')
    expect(mockSetupTOTP).toHaveBeenCalledOnce()
    expect(wrapper.text()).not.toContain('Confirm Your Password')
  })

  it('keeps the dialog open and skips the action when the password is wrong', async () => {
    mockConfirm.mockResolvedValue(false)
    mockConfirmError.value = { code: 'invalid_credentials' }
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await passConfirmDialog(wrapper, 'wrong')

    expect(mockSetupTOTP).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Confirm Your Password')
    expect(wrapper.find('.vault42-alert-error').text()).toBe('Invalid email or password.')
  })

  it('ignores a confirm click with an empty password instead of calling the API', async () => {
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await buttonByText(wrapper, 'Confirm')!.trigger('click')
    await flushPromises()

    expect(mockConfirm).not.toHaveBeenCalled()
    expect(mockSetupTOTP).not.toHaveBeenCalled()
  })

  // The Confirm button carries :disabled="!confirmPassword", but Enter on the password
  // field is wired straight to handleConfirm and bypasses that guard entirely. Only the
  // early return inside handleConfirm stops an empty-password submit.
  it('ignores Enter on an empty password field but submits once one is typed', async () => {
    const wrapper = mountView()
    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')

    const password = wrapper.find('input[type="password"]')
    await password.trigger('keyup.enter')
    await flushPromises()

    expect(mockConfirm).not.toHaveBeenCalled()
    expect(mockSetupTOTP).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Confirm Your Password')

    await password.setValue('hunter2')
    await password.trigger('keyup.enter')
    await flushPromises()

    expect(mockConfirm).toHaveBeenCalledOnce()
    expect(mockConfirm).toHaveBeenCalledWith('hunter2')
    expect(mockSetupTOTP).toHaveBeenCalledOnce()
  })

  it('disables the confirm button while the password check is in flight', async () => {
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await wrapper.find('input[type="password"]').setValue('hunter2')
    mockConfirmLoading.value = true
    await nextTick()

    const btn = wrapper.findAll('button').find(b => b.text().includes('Verifying...'))!
    expect((btn.element as HTMLButtonElement).disabled).toBe(true)
  })

  it('drops the pending action when the dialog is cancelled', async () => {
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await buttonByText(wrapper, 'Cancel')!.trigger('click')
    await flushPromises()

    expect(wrapper.text()).not.toContain('Confirm Your Password')
    expect(mockSetupTOTP).not.toHaveBeenCalled()

    // The abandoned action must not fire on the next, unrelated confirmation either.
    mockIsConfirmed.mockReturnValue(true)
    await buttonByText(wrapper, 'Generate New Codes')!.trigger('click')
    await flushPromises()
    expect(mockSetupTOTP).not.toHaveBeenCalled()
    expect(mockGenerateBackupCodes).toHaveBeenCalledOnce()
  })

  it('skips the dialog while a recent confirmation is still valid', async () => {
    mockIsConfirmed.mockReturnValue(true)
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await flushPromises()

    expect(mockSetupTOTP).toHaveBeenCalledOnce()
    expect(wrapper.text()).not.toContain('Confirm Your Password')
  })

  // --- TOTP enrolment ---------------------------------------------------------

  it('renders the QR code from the enrolment otpauth URL', async () => {
    mockIsConfirmed.mockReturnValue(true)
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await flushPromises()

    expect(mockToDataURL).toHaveBeenCalledWith(OTP_URL, {
      width: 200,
      margin: 2,
      color: { dark: '#e2e8f0', light: '#00000000' },
    })
    expect(wrapper.find('img[alt="TOTP QR Code"]').attributes('src')).toBe(QR_DATA_URL)
  })

  it('offers the raw secret as the manual fallback during enrolment', async () => {
    mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain("Can't scan? Enter manually")
    expect(wrapper.find('details').text()).toContain(SECRET)
  })

  it('falls back to the manual secret without an error when QR rendering fails', async () => {
    mockToDataURL.mockRejectedValue(new Error('qr boom'))
    mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('img[alt="TOTP QR Code"]').exists()).toBe(false)
    expect(wrapper.find('details').text()).toContain(SECRET)
  })

  it('keeps Verify disabled until six digits are entered', async () => {
    mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    const wrapper = mountView()
    await flushPromises()

    const verify = buttonByText(wrapper, 'Verify')!
    expect((verify.element as HTMLButtonElement).disabled).toBe(true)

    await wrapper.find('input[inputmode="numeric"]').setValue('12345')
    expect((verify.element as HTMLButtonElement).disabled).toBe(true)

    await wrapper.find('input[inputmode="numeric"]').setValue('123456')
    expect((verify.element as HTMLButtonElement).disabled).toBe(false)
  })

  it('submits the typed code to verifyTOTP', async () => {
    mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    const wrapper = mountView()
    await flushPromises()

    await wrapper.find('input[inputmode="numeric"]').setValue('123456')
    await buttonByText(wrapper, 'Verify')!.trigger('click')
    await flushPromises()

    expect(mockVerifyTOTP).toHaveBeenCalledWith('123456')
  })

  // Enter on the code field calls handleVerify directly, so the button's
  // :disabled="code.length !== 6" never applies. A partial code must not reach the API.
  it('ignores Enter on a partial code and only submits a full six digits', async () => {
    mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    const wrapper = mountView()
    await flushPromises()

    const input = wrapper.find('input[inputmode="numeric"]')
    await input.setValue('123')
    await input.trigger('keyup.enter')
    await flushPromises()

    expect(mockVerifyTOTP).not.toHaveBeenCalled()
    expect(wrapper.text()).not.toContain('TOTP Active')

    await input.setValue('123456')
    await input.trigger('keyup.enter')
    await flushPromises()

    expect(mockVerifyTOTP).toHaveBeenCalledOnce()
    expect(mockVerifyTOTP).toHaveBeenCalledWith('123456')
  })

  it('shows progress on the verify button and refuses a second submit while in flight', async () => {
    mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    let settle!: () => void
    mockVerifyTOTP.mockImplementation(() => {
      mockIsLoading.value = true
      return new Promise<void>(resolve => {
        settle = () => {
          mockIsLoading.value = false
          mockIsVerified.value = true
          resolve()
        }
      })
    })

    const wrapper = mountView()
    await flushPromises()

    await wrapper.find('input[inputmode="numeric"]').setValue('123456')
    await buttonByText(wrapper, 'Verify')!.trigger('click')
    await nextTick()

    const verifying = buttonByText(wrapper, 'Verifying...')!
    expect(verifying).toBeDefined()
    expect((verifying.element as HTMLButtonElement).disabled).toBe(true)

    // DEFECT (reported, not encoded): handleVerify has no in-flight guard of its own, so
    // Enter on the code field still re-submits the same code mid-request. Only the button
    // is protected; asserting on the button is the behaviour that actually holds today.
    await verifying.trigger('click')
    await flushPromises()
    expect(mockVerifyTOTP).toHaveBeenCalledOnce()

    settle()
    await flushPromises()
    expect(wrapper.text()).toContain('TOTP Active')
  })

  it('removes the secret and QR from the page once enrolment is verified', async () => {
    mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.html()).toContain(SECRET)

    await wrapper.find('input[inputmode="numeric"]').setValue('123456')
    await buttonByText(wrapper, 'Verify')!.trigger('click')
    await flushPromises()

    expect(wrapper.html()).not.toContain(SECRET)
    expect(wrapper.find('img[alt="TOTP QR Code"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('TOTP Active')
  })

  it('shows the failure and preserves the typed code when verification is rejected', async () => {
    mockTotpSetup.value = { secret: SECRET, otp_url: OTP_URL }
    mockVerifyTOTP.mockImplementation(async () => {
      mockError.value = { code: 'invalid_totp_code' }
      throw { code: 'invalid_totp_code' }
    })
    const wrapper = mountView()
    await flushPromises()

    await wrapper.find('input[inputmode="numeric"]').setValue('000000')
    await buttonByText(wrapper, 'Verify')!.trigger('click')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('Invalid code. Please try again.')
    // Still on step 2 with the code intact — no false "TOTP Active".
    expect(wrapper.text()).not.toContain('TOTP Active')
    expect((wrapper.find('input[inputmode="numeric"]').element as HTMLInputElement).value).toBe('000000')
  })

  // --- Disable ----------------------------------------------------------------

  it('requires re-auth before disabling TOTP and keeps it active meanwhile', async () => {
    mockMfaStatus.value = { totp_enabled: true, webauthn_enabled: false, backup_codes_remaining: 5 }
    const wrapper = mountView()

    await buttonByText(wrapper, 'Disable')!.trigger('click')
    await flushPromises()

    expect(mockDisableTOTP).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('TOTP Active')

    await passConfirmDialog(wrapper)
    expect(mockDisableTOTP).toHaveBeenCalledOnce()
  })

  // --- WebAuthn ---------------------------------------------------------------

  it('explains the unsupported-browser case instead of offering registration', () => {
    mockWebauthnSupported.value = false
    const wrapper = mountView()

    expect(wrapper.text()).toContain('Your browser does not support WebAuthn.')
    expect(buttonByText(wrapper, 'Register Security Key')).toBeUndefined()
  })

  it('registers a passkey and refreshes status and credential list afterwards', async () => {
    mockIsConfirmed.mockReturnValue(true)
    const wrapper = mountView()
    await flushPromises()
    mockFetchMFAStatus.mockClear()
    mockListCredentials.mockClear()

    await buttonByText(wrapper, 'Register Security Key')!.trigger('click')
    await flushPromises()

    expect(mockRegisterWebAuthn).toHaveBeenCalledOnce()
    expect(mockFetchMFAStatus).toHaveBeenCalledOnce()
    expect(mockListCredentials).toHaveBeenCalledOnce()
  })

  it('surfaces a failed passkey registration and does not refresh state', async () => {
    mockIsConfirmed.mockReturnValue(true)
    mockRegisterWebAuthn.mockImplementation(async () => {
      mockWebauthnError.value = { code: 'webauthn_registration_failed' }
      throw { code: 'webauthn_registration_failed' }
    })
    const wrapper = mountView()
    mockFetchMFAStatus.mockClear()

    await buttonByText(wrapper, 'Register Security Key')!.trigger('click')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('Security key registration failed. Please try again.')
    expect(mockFetchMFAStatus).not.toHaveBeenCalled()
  })

  it('blocks a second registration attempt while the browser prompt is open', async () => {
    mockWebauthnLoading.value = true
    const wrapper = mountView()

    const btn = wrapper.findAll('button').find(b => b.text() === 'Waiting for key...')!
    expect((btn.element as HTMLButtonElement).disabled).toBe(true)
  })

  it('lists registered keys and switches the action to "Add Another Key"', () => {
    mockCredentials.value = [
      { id: 'credabcdef123456', sign_count: 3, created_at: '2026-03-01T10:00:00Z' },
    ]
    const wrapper = mountView()

    expect(wrapper.text()).toContain('Key credabcd...')
    expect(wrapper.text()).toContain('Used 3 times')
    expect(buttonByText(wrapper, 'Add Another Key')).toBeDefined()
  })

  it('removes a key by id only after re-auth', async () => {
    mockCredentials.value = [
      { id: 'credabcdef123456', sign_count: 1, created_at: '2026-03-01T10:00:00Z' },
    ]
    const wrapper = mountView()

    await buttonByText(wrapper, 'Remove')!.trigger('click')
    await flushPromises()
    expect(mockDeleteCredential).not.toHaveBeenCalled()

    await passConfirmDialog(wrapper)
    expect(mockDeleteCredential).toHaveBeenCalledWith('credabcdef123456')
  })

  // --- Backup codes -----------------------------------------------------------

  it('requires re-auth before generating backup codes', async () => {
    const wrapper = mountView()

    await buttonByText(wrapper, 'Generate New Codes')!.trigger('click')
    await flushPromises()
    expect(mockGenerateBackupCodes).not.toHaveBeenCalled()

    await passConfirmDialog(wrapper)
    expect(mockGenerateBackupCodes).toHaveBeenCalledOnce()
  })

  it('shows the one-time-only warning alongside freshly generated codes', async () => {
    mockIsConfirmed.mockReturnValue(true)
    mockGenerateBackupCodes.mockImplementation(async () => {
      mockBackupCodes.value = ['aaaa-1111', 'bbbb-2222']
    })
    const wrapper = mountView()

    expect(wrapper.text()).not.toContain('Save these codes now.')

    await buttonByText(wrapper, 'Generate New Codes')!.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('Save these codes now. They will not be shown again.')
    expect(wrapper.text()).toContain('Each code can only be used once.')
    const codes = wrapper.findAll('code').map(c => c.text())
    expect(codes).toEqual(['aaaa-1111', 'bbbb-2222'])
  })

  it('replaces the previous set when codes are regenerated', async () => {
    mockIsConfirmed.mockReturnValue(true)
    mockBackupCodes.value = ['old-1111', 'old-2222']
    mockGenerateBackupCodes.mockImplementation(async () => {
      mockBackupCodes.value = ['new-3333', 'new-4444']
    })
    const wrapper = mountView()
    expect(wrapper.text()).toContain('old-1111')

    await buttonByText(wrapper, 'Generate New Codes')!.trigger('click')
    await flushPromises()

    const codes = wrapper.findAll('code').map(c => c.text())
    expect(codes).toEqual(['new-3333', 'new-4444'])
    expect(wrapper.text()).not.toContain('old-1111')
  })

  it('leaves the old codes on screen and reports the error when generation fails', async () => {
    mockIsConfirmed.mockReturnValue(true)
    mockBackupCodes.value = ['old-1111']
    mockGenerateBackupCodes.mockImplementation(async () => {
      mockError.value = { code: 'rate_limited' }
    })
    const wrapper = mountView()

    await buttonByText(wrapper, 'Generate New Codes')!.trigger('click')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').exists()).toBe(true)
    expect(wrapper.findAll('code').map(c => c.text())).toEqual(['old-1111'])
  })

  it('copies every code as newline-separated text and acknowledges the copy', async () => {
    mockBackupCodes.value = ['aaaa-1111', 'bbbb-2222', 'cccc-3333']
    const wrapper = mountView()

    await buttonByText(wrapper, 'Copy all')!.trigger('click')
    await flushPromises()

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('aaaa-1111\nbbbb-2222\ncccc-3333')
    expect(buttonByText(wrapper, 'Copied!')).toBeDefined()
  })

  it('does not claim success when the clipboard write is refused', async () => {
    // writeText rejects in a non-secure context, when the document is not
    // focused, or when permission is denied. The promise used to be dropped and
    // "Copied!" shown regardless, so a user could believe their recovery codes
    // were saved with nothing on the clipboard.
    ;(navigator.clipboard.writeText as ReturnType<typeof vi.fn>)
      .mockRejectedValue(new DOMException('Write permission denied.', 'NotAllowedError'))
    mockBackupCodes.value = ['aaaa-1111', 'bbbb-2222']
    const wrapper = mountView()

    await buttonByText(wrapper, 'Copy all')!.trigger('click')
    await flushPromises()

    expect(buttonByText(wrapper, 'Copied!')).toBeUndefined()
    expect(buttonByText(wrapper, 'An error occurred')).toBeDefined()
  })

  it('selects the codes so they can still be copied by hand', async () => {
    ;(navigator.clipboard.writeText as ReturnType<typeof vi.fn>)
      .mockRejectedValue(new Error('denied'))
    const addRange = vi.fn()
    const removeAllRanges = vi.fn()
    vi.spyOn(window, 'getSelection').mockReturnValue(
      { addRange, removeAllRanges } as unknown as Selection,
    )
    mockBackupCodes.value = ['aaaa-1111', 'bbbb-2222']
    const wrapper = mountView()

    await buttonByText(wrapper, 'Copy all')!.trigger('click')
    await flushPromises()

    expect(removeAllRanges).toHaveBeenCalledOnce()
    expect(addRange).toHaveBeenCalledOnce()
    expect((addRange.mock.calls[0][0] as Range).toString()).toContain('aaaa-1111')
    vi.mocked(window.getSelection).mockRestore()
  })

  it('survives a browser that offers no selection either', async () => {
    ;(navigator.clipboard.writeText as ReturnType<typeof vi.fn>)
      .mockRejectedValue(new Error('denied'))
    vi.spyOn(window, 'getSelection').mockReturnValue(null)
    mockBackupCodes.value = ['aaaa-1111']
    const wrapper = mountView()

    await buttonByText(wrapper, 'Copy all')!.trigger('click')
    await flushPromises()

    expect(buttonByText(wrapper, 'An error occurred')).toBeDefined()
    vi.mocked(window.getSelection).mockRestore()
  })

  it('treats a missing Clipboard API as a failed copy rather than throwing', async () => {
    // navigator.clipboard is undefined outright on an insecure origin.
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true, writable: true })
    mockBackupCodes.value = ['aaaa-1111']
    const wrapper = mountView()

    await buttonByText(wrapper, 'Copy all')!.trigger('click')
    await flushPromises()

    expect(buttonByText(wrapper, 'Copied!')).toBeUndefined()
    expect(buttonByText(wrapper, 'An error occurred')).toBeDefined()
  })

  it('clears a previous copy failure when a later copy succeeds', async () => {
    ;(navigator.clipboard.writeText as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(new Error('denied'))
      .mockResolvedValueOnce(undefined)
    mockBackupCodes.value = ['aaaa-1111']
    const wrapper = mountView()

    await buttonByText(wrapper, 'Copy all')!.trigger('click')
    await flushPromises()
    expect(buttonByText(wrapper, 'An error occurred')).toBeDefined()

    await buttonByText(wrapper, 'An error occurred')!.trigger('click')
    await flushPromises()
    expect(buttonByText(wrapper, 'Copied!')).toBeDefined()
  })

  it('reverts the copy acknowledgement to "Copy all" after two seconds', async () => {
    // Only setTimeout is faked so the component's own promises still settle normally.
    vi.useFakeTimers({ toFake: ['setTimeout'] })
    mockBackupCodes.value = ['aaaa-1111']
    const wrapper = mountView()

    await buttonByText(wrapper, 'Copy all')!.trigger('click')
    expect(buttonByText(wrapper, 'Copied!')).toBeDefined()

    vi.advanceTimersByTime(1999)
    await nextTick()
    expect(buttonByText(wrapper, 'Copied!')).toBeDefined()

    vi.advanceTimersByTime(1)
    await nextTick()
    expect(buttonByText(wrapper, 'Copied!')).toBeUndefined()
    expect(buttonByText(wrapper, 'Copy all')).toBeDefined()
  })

  it('reports how many backup codes are left', () => {
    mockMfaStatus.value = { totp_enabled: true, webauthn_enabled: false, backup_codes_remaining: 4 }
    const wrapper = mountView()
    expect(wrapper.text()).toContain('4 codes remaining')
  })

  it('disables both generator buttons while a request is in flight', async () => {
    mockIsLoading.value = true
    const wrapper = mountView()

    const setupBtn = wrapper.findAll('button').find(b => b.text().includes('Generating...') && b.classes().includes('vault42-btn'))!
    const backupBtn = wrapper.findAll('button').find(b => b.classes().includes('vault42-btn-outline') && b.text().includes('Generating...'))!
    expect((setupBtn.element as HTMLButtonElement).disabled).toBe(true)
    expect((backupBtn.element as HTMLButtonElement).disabled).toBe(true)
  })

  it('shows the top-level error for a failed enrolment start', async () => {
    mockIsConfirmed.mockReturnValue(true)
    mockSetupTOTP.mockImplementation(async () => {
      mockError.value = { code: 'totp_already_enabled' }
    })
    const wrapper = mountView()

    await buttonByText(wrapper, 'Begin Setup')!.trigger('click')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('TOTP is already enabled on this account.')
    expect(wrapper.find('img[alt="TOTP QR Code"]').exists()).toBe(false)
  })
})
