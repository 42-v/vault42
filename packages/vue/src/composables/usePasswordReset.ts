import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { VaultError } from '../types'

/**
 * Password recovery for signed-out users, and password change for signed-in ones.
 *
 * State is created per call and is not shared between callers.
 *
 * Calls `POST /auth/password/reset`, `POST /auth/password/reset/confirm` and
 * `POST /user/password`.
 *
 * @returns
 * - `isLoading`: true while a call is outstanding.
 * - `error`: the last `VaultError`, or null.
 * - `requested`: true after `requestReset()` completed without error.
 * - `confirmed`: true after `confirmReset()` succeeded.
 * - `requestReset(email)`: asks the server to email a reset link. Never
 *   throws. `requested` turning true means the request was accepted, **not**
 *   that the address exists: the server answers identically either way so the
 *   endpoint cannot be used to enumerate accounts. UI copy must not imply an
 *   email was definitely sent.
 * - `confirmReset(token, password)`: completes the reset with the emailed
 *   token. Sets `error` and rethrows, so a form can keep the user on the step
 *   for an expired token or a rejected password.
 * - `changePassword(current, newPassword)`: changes the password for the
 *   signed-in user. Sets `error` and rethrows.
 *
 * @throws Error if `createVaultPlugin` was never installed.
 */
export function usePasswordReset() {
  const client = useVaultClient()
  const isLoading: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)
  const requested: Ref<boolean> = ref(false)
  const confirmed: Ref<boolean> = ref(false)

  async function requestReset(email: string): Promise<void> {
    isLoading.value = true
    error.value = null
    requested.value = false
    try {
      await client.requestPasswordReset(email)
      requested.value = true
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  async function confirmReset(token: string, password: string): Promise<void> {
    isLoading.value = true
    error.value = null
    confirmed.value = false
    try {
      await client.confirmPasswordReset(token, password)
      confirmed.value = true
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      isLoading.value = false
    }
  }

  async function changePassword(current: string, newPassword: string): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      await client.changePassword(current, newPassword)
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      isLoading.value = false
    }
  }

  return {
    isLoading,
    error,
    requested,
    confirmed,
    requestReset,
    confirmReset,
    changePassword,
  }
}
