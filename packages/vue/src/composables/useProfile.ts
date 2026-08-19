import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { UserProfile, VaultError } from '../types'

/**
 * Loads the signed-in user's profile.
 *
 * State is created per call, so two components each calling `useProfile()` hold
 * independent `profile` refs and each must run its own `fetchProfile()`. Use the
 * shared `user` ref from {@link useAuth} when several components need to observe
 * one profile.
 *
 * Calls `GET /user/profile`.
 *
 * @returns
 * - `profile`: the loaded {@link UserProfile}, or null before the first
 *   successful fetch. A failed fetch leaves the previous value in place.
 * - `isLoading`: true while a fetch is outstanding.
 * - `error`: the last `VaultError`, or null.
 * - `fetchProfile`: loads the profile. Never throws; failures land in `error`,
 *   so callers must check it rather than relying on a rejected promise.
 *
 * @throws Error if `createVaultPlugin` was never installed.
 */
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
