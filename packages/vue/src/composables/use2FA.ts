import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { TOTPSetupResult, MFAStatus, VaultError } from '../types'

export function use2FA() {
  const client = useVaultClient()
  const totpSetup: Ref<TOTPSetupResult | null> = ref(null)
  const backupCodes: Ref<string[]> = ref([])
  const mfaStatus: Ref<MFAStatus | null> = ref(null)
  const isLoading: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)
  const isVerified: Ref<boolean> = ref(false)

  async function fetchMFAStatus(): Promise<void> {
    try {
      mfaStatus.value = await client.getMFAStatus()
    } catch {
      // Non-critical — status may not be available
    }
  }

  async function setupTOTP(): Promise<void> {
    isLoading.value = true
    error.value = null
    isVerified.value = false
    try {
      totpSetup.value = await client.setupTOTP()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  async function verifyTOTP(code: string): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      await client.verifyTOTP(code)
      isVerified.value = true
      await fetchMFAStatus()
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      isLoading.value = false
    }
  }

  async function disableTOTP(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      await client.disableTOTP()
      isVerified.value = false
      await fetchMFAStatus()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  async function generateBackupCodes(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      backupCodes.value = await client.generateBackupCodes()
      await fetchMFAStatus()
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  return {
    totpSetup,
    backupCodes,
    mfaStatus,
    isLoading,
    error,
    isVerified,
    setupTOTP,
    verifyTOTP,
    disableTOTP,
    generateBackupCodes,
    fetchMFAStatus,
  }
}
