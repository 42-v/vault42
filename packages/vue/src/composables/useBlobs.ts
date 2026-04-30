import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { BlobMeta, BlobQuota, VaultError } from '../types'

export function useBlobs() {
  const client = useVaultClient()
  const blobs: Ref<BlobMeta[]> = ref([])
  const quota: Ref<BlobQuota | null> = ref(null)
  const isLoading: Ref<boolean> = ref(false)
  const isUploading: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)

  async function fetchBlobs(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      const result = await client.listBlobs()
      blobs.value = result.blobs || []
      quota.value = result.quota
    } catch (e: unknown) {
      error.value = e as VaultError
    } finally {
      isLoading.value = false
    }
  }

  async function uploadBlob(data: Blob | ArrayBuffer | Uint8Array, label?: string): Promise<boolean> {
    isUploading.value = true
    error.value = null
    try {
      await client.uploadBlob(data, label)
      await fetchBlobs()
      return true
    } catch (e: unknown) {
      error.value = e as VaultError
      return false
    } finally {
      isUploading.value = false
    }
  }

  async function uploadNamedBlob(name: string, data: Blob | ArrayBuffer | Uint8Array): Promise<boolean> {
    isUploading.value = true
    error.value = null
    try {
      await client.uploadNamedBlob(name, data)
      await fetchBlobs()
      return true
    } catch (e: unknown) {
      error.value = e as VaultError
      return false
    } finally {
      isUploading.value = false
    }
  }

  async function downloadBlob(id: string): Promise<{ data: ArrayBuffer; label?: string } | null> {
    error.value = null
    try {
      return await client.downloadBlob(id)
    } catch (e: unknown) {
      error.value = e as VaultError
      return null
    }
  }

  async function downloadNamedBlob(name: string): Promise<{ data: ArrayBuffer; label?: string } | null> {
    error.value = null
    try {
      return await client.downloadNamedBlob(name)
    } catch (e: unknown) {
      error.value = e as VaultError
      return null
    }
  }

  async function deleteBlob(id: string): Promise<boolean> {
    error.value = null
    try {
      await client.deleteBlob(id)
      blobs.value = blobs.value.filter(b => b.id !== id)
      return true
    } catch (e: unknown) {
      error.value = e as VaultError
      return false
    }
  }

  async function deleteNamedBlob(name: string): Promise<boolean> {
    error.value = null
    try {
      await client.deleteNamedBlob(name)
      await fetchBlobs()
      return true
    } catch (e: unknown) {
      error.value = e as VaultError
      return false
    }
  }

  return {
    blobs, quota, isLoading, isUploading, error,
    fetchBlobs, uploadBlob, uploadNamedBlob,
    downloadBlob, downloadNamedBlob,
    deleteBlob, deleteNamedBlob,
  }
}
