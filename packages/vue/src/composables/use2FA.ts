import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { TOTPSetupResult, MFAStatus, VaultError } from '../types'

/**
 * Manages second-factor enrolment: TOTP setup and removal, and backup codes.
 *
 * This is the *enrolment* surface, for a signed-in user configuring MFA. It is
 * not the login-time challenge; completing a second factor during sign-in is
 * `verify2FA` and friends on {@link useAuth}.
 *
 * State is created per call and is not shared between callers.
 *
 * Calls `POST /auth/2fa/totp/setup`, `POST /auth/2fa/totp/verify`,
 * `DELETE /auth/2fa/totp`, `POST /auth/2fa/backup-codes` and
 * `GET /auth/2fa/status`.
 *
 * @returns
 * - `totpSetup`: the {@link TOTPSetupResult} holding the shared secret and the
 *   `otpauth://` URL to render as a QR code. It is returned once, at setup, and
 *   never again; the app must show it before the user navigates away.
 * - `backupCodes`: the codes from the most recent `generateBackupCodes()`,
 *   otherwise empty. Also shown once only.
 * - `mfaStatus`: the current {@link MFAStatus}, or null until fetched.
 * - `isLoading`: true while a call is outstanding.
 * - `error`: the last `VaultError`, or null.
 * - `isVerified`: true after a successful `verifyTOTP()` in this composable's
 *   lifetime. It is local bookkeeping, reset by `setupTOTP()` and
 *   `disableTOTP()`, and is not a reading of server state; use `mfaStatus`.
 * - `setupTOTP`, `verifyTOTP`, `disableTOTP`, `generateBackupCodes`,
 *   `fetchMFAStatus`: the actions. Each of the first four refreshes
 *   `mfaStatus` on success.
 *
 * Only `verifyTOTP` rethrows, so an enrolment form can await it and keep the
 * user on the step when the code is wrong. The others record the failure in
 * `error` and return. `fetchMFAStatus` swallows its error entirely and leaves
 * `mfaStatus` untouched, since a stale status must not block the screen.
 *
 * @throws Error if `createVaultPlugin` was never installed.
 */
export function use2FA() {
  const client = useVaultClient()
  const totpSetup: Ref<TOTPSetupResult | null> = ref(null)
  const backupCodes: Ref<string[]> = ref([])
  const mfaStatus: Ref<MFAStatus | null> = ref(null)
  const isLoading: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)
  const isVerified: Ref<boolean> = ref(false)

  async function fetchMFAStatus(): Promise<void> {
    try {
      mfaStatus.value = await client.getMFAStatus()
    } catch {
      // Non-critical — status may not be available
    }
  }

  async function setupTOTP(): Promise<void> {
    isLoading.value = true
    error.value = null
    isVerified.value = false
    try {
      totpSetup.value = await client.setupTOTP()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  async function verifyTOTP(code: string): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      await client.verifyTOTP(code)
      isVerified.value = true
      await fetchMFAStatus()
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      isLoading.value = false
    }
  }

  async function disableTOTP(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      await client.disableTOTP()
      isVerified.value = false
      await fetchMFAStatus()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  async function generateBackupCodes(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      backupCodes.value = await client.generateBackupCodes()
      await fetchMFAStatus()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  return {
    totpSetup,
    backupCodes,
    mfaStatus,
    isLoading,
    error,
    isVerified,
    setupTOTP,
    verifyTOTP,
    disableTOTP,
    generateBackupCodes,
    fetchMFAStatus,
  }
}
