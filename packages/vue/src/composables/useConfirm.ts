import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { VaultError } from '../types'

const confirmed: Ref<boolean> = ref(false)
const confirmExpiresAt: Ref<number> = ref(0)

let confirmTimer: ReturnType<typeof setTimeout> | null = null

/**
 * Password re-confirmation, the short-lived elevation gate in front of
 * sensitive operations such as disabling MFA or deleting stored identity.
 *
 * The confirmation itself is module-level and shared: `confirmed`, its expiry
 * and the expiry timer live for the module's lifetime, so confirming in one
 * component satisfies the gate everywhere and survives unmounting. Only
 * `isLoading` and `error` are per call.
 *
 * Calls `POST /auth/confirm`.
 *
 * @returns
 * - `confirmed`: the raw flag. It is set on success and cleared by a timer, but
 *   does **not** account for the deadline on read; prefer `isConfirmed()`.
 * - `isConfirmed()`: a plain function, not a computed. It compares
 *   `Date.now()` against the deadline, so it is accurate but not reactive:
 *   calling it in a template does not re-render the component when the window
 *   lapses. Drive time-sensitive UI from your own interval.
 * - `isLoading`: true while a confirmation is outstanding.
 * - `error`: the last `VaultError`, or null.
 * - `confirm(password)`: confirms and returns whether it succeeded. Never
 *   throws: a wrong password and a network failure both return false, the
 *   latter also setting `error`.
 * - `clearConfirmation()`: drops the confirmation and cancels the timer. Call
 *   this on sign-out, since nothing else does, and the elevation would
 *   otherwise outlive the session for the rest of the window.
 *
 * The deadline is enforced locally from the server's `expires_in`. It is a UI
 * affordance only; the server re-checks elevation on every sensitive route.
 *
 * @throws Error if `createVaultPlugin` was never installed.
 */
export function useConfirm() {
  const client = useVaultClient()
  const isLoading: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)

  const isConfirmed = (): boolean => {
    return confirmed.value && Date.now() < confirmExpiresAt.value
  }

  async function confirm(password: string): Promise<boolean> {
    isLoading.value = true
    error.value = null
    try {
      const result = await client.confirmPassword(password)
      if (result.confirmed) {
        confirmed.value = true
        confirmExpiresAt.value = Date.now() + result.expires_in * 1000
        // Auto-expire locally
        if (confirmTimer) clearTimeout(confirmTimer)
        confirmTimer = setTimeout(() => {
          confirmed.value = false
          confirmExpiresAt.value = 0
        }, result.expires_in * 1000)
      }
      return result.confirmed
    } catch (e: unknown) {
      error.value = e as VaultError
      return false
    } finally {
      isLoading.value = false
    }
  }

  function clearConfirmation() {
    confirmed.value = false
    confirmExpiresAt.value = 0
    if (confirmTimer) {
      clearTimeout(confirmTimer)
      confirmTimer = null
    }
  }

  return {
    confirmed,
    isConfirmed,
    isLoading,
    error,
    confirm,
    clearConfirmation,
  }
}
