import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { VaultError } from '../types'

const confirmed: Ref<boolean> = ref(false)
const confirmExpiresAt: Ref<number> = ref(0)

let confirmTimer: ReturnType<typeof setTimeout> | null = null

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
