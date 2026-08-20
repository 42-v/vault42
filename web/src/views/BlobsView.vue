<script setup lang="ts">
import { onMounted, ref, computed, useTemplateRef } from 'vue'
import { useBlobs, VaultAuthGuard, useT } from '@vault42/vue'
import { friendlyError } from '../errorMessages'
import { useModalFocus } from '../composables/useModalFocus'

const { blobs, quota, isLoading, isUploading, error, fetchBlobs, uploadBlob, downloadBlob, deleteBlob } = useBlobs()
const { t, formatDate } = useT()

const fileInput = ref<HTMLInputElement | null>(null)
const label = ref('')
const deleteConfirmId = ref<string | null>(null)
const dialogRef = useTemplateRef('dialog')
useModalFocus(deleteConfirmId, () => { deleteConfirmId.value = null }, dialogRef)

const quotaPercent = computed(() => {
  if (!quota.value || !quota.value.max_bytes) return 0
  return Math.round((quota.value.used_bytes / quota.value.max_bytes) * 100)
})

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function sanitizeFilename(name: string): string {
  // eslint-disable-next-line no-control-regex -- intentional: strip filesystem-illegal control chars
  return name.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').slice(0, 255) || 'download'
}

onMounted(() => fetchBlobs())

async function handleUpload() {
  const file = fileInput.value?.files?.[0]
  if (!file) return

  const data = await file.arrayBuffer()
  const ok = await uploadBlob(data, label.value || file.name)
  if (ok) {
    label.value = ''
    if (fileInput.value) fileInput.value.value = ''
  }
}

async function handleDownload(id: string, blobLabel?: string) {
  const result = await downloadBlob(id)
  if (!result) return

  const blob = new Blob([result.data])
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = sanitizeFilename(result.label || blobLabel || id)
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

async function handleDelete(id: string) {
  deleteConfirmId.value = null
  await deleteBlob(id)
}
</script>

<template>
  <VaultAuthGuard>
    <template #default>
      <div class="max-w-3xl mx-auto px-4 sm:px-6 py-8">
        <h1 class="text-2xl font-bold mb-6">{{ t('blobs.title') }}</h1>

        <div v-if="isLoading" class="flex justify-center py-12">
          <div class="vault42-spinner vault42-spinner-lg"></div>
        </div>

        <div v-else class="space-y-6">
          <div v-if="error" class="vault42-alert-error" role="alert">{{ friendlyError(error.code) }}</div>

          <!-- Quota bar -->
          <div v-if="quota" class="vault42-card">
            <div class="flex justify-between text-sm mb-2">
              <span class="text-vault42-muted">
                {{ t('blobs.files', { used: quota.used_count, max: quota.max_count }) }}
              </span>
              <span class="text-vault42-muted">
                {{ formatBytes(quota.used_bytes) }} / {{ formatBytes(quota.max_bytes) }}
              </span>
            </div>
            <div class="w-full bg-vault42-surface rounded-full h-2">
              <div
                class="h-2 rounded-full transition-all duration-300"
                :class="quotaPercent > 90 ? 'bg-vault42-error' : 'bg-vault42-accent'"
                :style="{ width: quotaPercent + '%' }"
              ></div>
            </div>
          </div>

          <!-- Upload -->
          <div class="vault42-card space-y-4">
            <h3 class="text-sm font-semibold text-vault42-muted uppercase tracking-wider">{{ t('blobs.uploadFile') }}</h3>
            <form class="space-y-3" @submit.prevent="handleUpload">
              <div>
                <label for="blob-file" class="vault42-label">{{ t('blobs.file') }}</label>
                <input id="blob-file" ref="fileInput" type="file" class="vault42-input" required />
              </div>
              <div>
                <label for="blob-label" class="vault42-label">{{ t('blobs.labelOptional') }}</label>
                <input id="blob-label" v-model="label" type="text" class="vault42-input" placeholder="my-document.pdf" maxlength="255" />
              </div>
              <button type="submit" :disabled="isUploading" class="vault42-btn-primary">
                <span v-if="isUploading" class="vault42-spinner vault42-spinner-sm mr-2"></span>
                {{ t('common.upload') }}
              </button>
            </form>
          </div>

          <!-- File list -->
          <div class="vault42-card">
            <h3 class="text-sm font-semibold text-vault42-muted uppercase tracking-wider mb-4">{{ t('blobs.yourFiles') }}</h3>
            <div v-if="blobs.length === 0" class="text-sm text-vault42-muted py-4 text-center">
              {{ t('blobs.noFiles') }}
            </div>
            <div v-else class="divide-y divide-vault42-border">
              <div v-for="blob in blobs" :key="blob.id" class="py-3 flex items-center justify-between gap-4">
                <div class="min-w-0 flex-1">
                  <p class="text-sm font-medium truncate">{{ blob.label || blob.id }}</p>
                  <p class="text-xs text-vault42-muted">
                    {{ formatBytes(blob.size_bytes) }}
                    <span class="mx-1">&middot;</span>
                    {{ formatDate(new Date(blob.created_at)) }}
                  </p>
                </div>
                <div class="flex gap-2 flex-shrink-0">
                  <button class="vault42-btn-secondary vault42-btn-sm" @click="handleDownload(blob.id, blob.label)">
                    {{ t('common.download') }}
                  </button>
                  <button class="vault42-btn-danger vault42-btn-sm" @click="deleteConfirmId = blob.id">
                    {{ t('common.delete') }}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Delete confirmation -->
        <Teleport to="body">
          <div v-if="deleteConfirmId" class="vault42-modal-overlay" @click.self="deleteConfirmId = null">
            <div ref="dialog" class="vault42-modal" role="dialog" aria-modal="true" aria-labelledby="delete-dialog-title">
              <h3 id="delete-dialog-title" class="text-lg font-semibold mb-2">{{ t('blobs.deleteFile') }}</h3>
              <p class="text-sm text-vault42-muted mb-4">{{ t('blobs.deleteConfirm') }}</p>
              <div class="flex gap-3">
                <button class="vault42-btn-danger" @click="handleDelete(deleteConfirmId!)">{{ t('common.delete') }}</button>
                <button class="vault42-btn-secondary" @click="deleteConfirmId = null">{{ t('common.cancel') }}</button>
              </div>
            </div>
          </div>
        </Teleport>
      </div>
    </template>

    <template #loading>
      <div class="flex justify-center py-20">
        <div class="vault42-spinner vault42-spinner-lg"></div>
      </div>
    </template>
  </VaultAuthGuard>
</template>
