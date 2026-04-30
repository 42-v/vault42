import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { VaultError } from '../types'

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
