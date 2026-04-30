import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { Session, Device, VaultError } from '../types'

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
