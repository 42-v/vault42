import { ref, type Ref } from 'vue'
import { useVaultClient } from '../plugin'
import type { BlobMeta, BlobQuota, VaultError } from '../types'

/**
 * Encrypted binary storage: upload, download, list and delete.
 *
 * Blobs come in two flavours. Anonymous blobs are addressed by a
 * server-assigned id and carry an optional label; named blobs are addressed by
 * a caller-chosen name and overwrite in place, which makes them the right
 * choice for a document that has one current version.
 *
 * State is created per call and is not shared between callers.
 *
 * Calls `GET`/`POST /user/blobs`, `GET`/`DELETE /user/blobs/{id}` and
 * `PUT`/`GET`/`DELETE /user/blobs/named/{name}`.
 *
 * @returns
 * - `blobs`: the {@link BlobMeta} list, empty until fetched.
 * - `quota`: the {@link BlobQuota}, or null until fetched. Populated by
 *   `fetchBlobs()`, so check it before a large upload rather than after the
 *   rejection.
 * - `isLoading`: true while a list fetch is outstanding.
 * - `isUploading`: true while an upload is outstanding.
 * - `error`: the last `VaultError`, or null.
 * - `fetchBlobs()`: loads the list and the quota.
 * - `uploadBlob(data, label?)`: uploads an anonymous blob. `label` travels in
 *   an HTTP header and is therefore limited to printable ASCII and 255
 *   characters; a name with an accent or a newline is rejected before the
 *   request leaves, surfacing as `invalid_blob_label` in `error`. Encode such
 *   names yourself.
 * - `uploadNamedBlob(name, data)`: creates or replaces the blob at `name`.
 *   `name` must match `[A-Za-z0-9_-]+`; anything else is rejected locally as
 *   `invalid_resource_id`.
 * - `downloadBlob(id)` / `downloadNamedBlob(name)`: return `{ data, label }`,
 *   or null on failure.
 * - `deleteBlob(id)`: deletes and drops the entry from the local list without
 *   refetching, so `quota` stays stale until the next `fetchBlobs()`.
 * - `deleteNamedBlob(name)`: deletes and refetches, so both the list and the
 *   quota are current afterwards.
 *
 * Uploads and deletes return a boolean; downloads return null on failure. None
 * of them throw, so an ignored return value silently loses the failure.
 *
 * @throws Error if `createVaultPlugin` was never installed.
 */
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
