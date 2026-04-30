import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { IdentityData, VaultError } from '../types'

export function useIdentity() {
  const client = useVaultClient()
  const identity: Ref<IdentityData | null> = ref(null)
  const isLoading: Ref<boolean> = ref(false)
  const isSaving: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)

  async function fetchIdentity(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      identity.value = await client.getIdentity()
    } catch (e: unknown) {
      const err = e as VaultError
      if (err.status === 404) {
        identity.value = null
      } else {
        error.value = err
      }
    } finally {
      isLoading.value = false
    }
  }

  async function saveIdentity(data: Partial<IdentityData>): Promise<boolean> {
    isSaving.value = true
    error.value = null
    try {
      await client.putIdentity(data)
      identity.value = { ...identity.value, ...data } as IdentityData
      return true
    } catch (e: unknown) {
      error.value = e as VaultError
      return false
    } finally {
      isSaving.value = false
    }
  }

  async function deleteIdentity(): Promise<boolean> {
    isSaving.value = true
    error.value = null
    try {
      await client.deleteIdentity()
      identity.value = null
      return true
    } catch (e: unknown) {
      error.value = e as VaultError
      return false
    } finally {
      isSaving.value = false
    }
  }

  return { identity, isLoading, isSaving, error, fetchIdentity, saveIdentity, deleteIdentity }
}
