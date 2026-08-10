import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { Session, Device, VaultError } from '../types'

/**
 * Lists and revokes the user's active sessions and known devices.
 *
 * State is created per call; separate `useSessions()` callers do not share
 * lists, and each must fetch its own.
 *
 * Calls `GET`/`DELETE /user/sessions`, `DELETE /user/sessions/{id}`,
 * `GET /user/devices`, `PATCH`/`DELETE /user/devices/{id}`.
 *
 * @returns
 * - `sessions`: the active {@link Session} list, empty until fetched.
 * - `devices`: the known {@link Device} list, empty until fetched.
 * - `isLoading`: true while a fetch is outstanding. It is a boolean, not a
 *   counter, so a `fetchSessions` and a `fetchDevices` running concurrently
 *   clear it as soon as the first of them finishes.
 * - `error`: the last `VaultError`, or null.
 * - `fetchSessions`, `fetchDevices`: load the respective list.
 * - `revokeSession`: revokes one session by id, then refetches **both** lists,
 *   because revoking a session also revokes that device's tokens.
 * - `revokeAllSessions`: revokes every session and empties both lists locally.
 *   This includes the caller's own session, so the current token stops working
 *   and the app must send the user back to sign-in.
 * - `renameDevice`: renames a device and patches the local list in place
 *   without refetching.
 * - `removeDevice`: removes a device, then refetches both lists.
 *
 * None of these throw. Every failure lands in `error` and leaves the lists at
 * their previous values, so a revoke that silently failed looks like a revoke
 * that changed nothing; check `error` after each call.
 *
 * @throws Error if `createVaultPlugin` was never installed.
 */
export function useSessions() {
  const client = useVaultClient()
  const sessions: Ref<Session[]> = ref([])
  const devices: Ref<Device[]> = ref([])
  const isLoading: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)

  async function fetchSessions(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      sessions.value = await client.getSessions()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  async function revokeSession(id: string): Promise<void> {
    error.value = null
    try {
      await client.revokeSession(id)
      // Refetch both — revoking a session also revokes that device's tokens
      await Promise.all([fetchSessions(), fetchDevices()])
    } catch (e: unknown) {
      error.value = e as VaultError
    }
  }

  async function revokeAllSessions(): Promise<void> {
    error.value = null
    try {
      await client.revokeAllSessions()
      sessions.value = []
      devices.value = []
    } catch (e: unknown) {
      error.value = e as VaultError
    }
  }

  async function fetchDevices(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      devices.value = await client.getDevices()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  async function renameDevice(id: string, name: string): Promise<void> {
    error.value = null
    try {
      await client.renameDevice(id, name)
      const device = devices.value.find((d) => d.id === id)
      if (device) device.friendly_name = name
    } catch (e: unknown) {
      error.value = e as VaultError
    }
  }

  async function removeDevice(id: string): Promise<void> {
    error.value = null
    try {
      await client.removeDevice(id)
      // Refetch both — removing a device also revokes its tokens
      await Promise.all([fetchSessions(), fetchDevices()])
    } catch (e: unknown) {
      error.value = e as VaultError
    }
  }

  return {
    sessions,
    devices,
    isLoading,
    error,
    fetchSessions,
    revokeSession,
    revokeAllSessions,
    fetchDevices,
    renameDevice,
    removeDevice,
  }
}
