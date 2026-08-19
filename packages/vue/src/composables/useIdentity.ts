import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { IdentityData, VaultError } from '../types'

/**
 * Reads and writes the user's stored identity record: name, country, date of
 * birth and billing address.
 *
 * State is created per call and is not shared between callers.
 *
 * Calls `GET`/`PUT`/`DELETE /user/identity`.
 *
 * @returns
 * - `identity`: the stored {@link IdentityData}, or null when the user has
 *   none.
 * - `isLoading`: true while a fetch is outstanding.
 * - `isSaving`: true while a save or delete is outstanding. Saves and deletes
 *   share this flag; reads use `isLoading`.
 * - `error`: the last `VaultError`, or null.
 * - `fetchIdentity()`: loads the record. A 404 is treated as "no identity
 *   stored yet", setting `identity` to null and leaving `error` clear, so a
 *   first-time user does not surface as an error.
 * - `saveIdentity(data)`: writes a partial update and returns whether it
 *   succeeded. On success the local `identity` is merged optimistically from
 *   the submitted fields rather than refetched, so any server-side
 *   normalisation is not reflected until the next `fetchIdentity()`.
 * - `deleteIdentity()`: erases the record and returns whether it succeeded.
 *
 * None of these throw; each returns a boolean or leaves the failure in `error`.
 *
 * @throws Error if `createVaultPlugin` was never installed.
 */
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
