import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { UserProfile, VaultError } from '../types'

export function useProfile() {
  const client = useVaultClient()
  const profile: Ref<UserProfile | null> = ref(null)
  const isLoading: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)

  async function fetchProfile(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      profile.value = await client.getProfile()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  return { profile, isLoading, error, fetchProfile }
}
