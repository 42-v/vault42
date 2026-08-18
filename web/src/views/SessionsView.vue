<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useSessions, VaultAuthGuard, useT } from '@vault42/vue'
import { friendlyError } from '../errorMessages'

const {
  sessions, devices, isLoading, error,
  fetchSessions, fetchDevices,
  revokeSession, revokeAllSessions, renameDevice, removeDevice,
} = useSessions()

const { t, formatDate } = useT()
const editingId = ref<string | null>(null)
const editName = ref('')

function startEdit(id: string, currentName: string) {
  editingId.value = id
  editName.value = currentName
}

function cancelEdit() {
  editingId.value = null
  editName.value = ''
}

async function saveEdit(id: string) {
  const name = editName.value.trim()
  if (!name || name.length > 100) return
  try {
    await renameDevice(id, name)
    editingId.value = null
    editName.value = ''
  } catch {
    // Error is surfaced via the composable's error ref
  }
}

onMounted(() => {
  fetchSessions()
  fetchDevices()
})
</script>

<template>
  <VaultAuthGuard>
    <template #default>
      <div class="max-w-3xl mx-auto px-4 sm:px-6 py-8 space-y-8">
        <!-- Sessions -->
        <div>
          <div class="flex items-center justify-between mb-4">
            <div>
              <h1 class="text-2xl font-bold">{{ t('sessions.title') }}</h1>
              <p class="text-sm text-vault42-muted mt-0.5">{{ t('sessions.subtitle') }}</p>
            </div>
            <button
              v-if="sessions.length > 0"
              class="vault42-btn-danger vault42-btn-sm"
              @click="revokeAllSessions"
            >
              {{ t('sessions.revokeAll') }}
            </button>
          </div>

          <div v-if="error" class="vault42-alert-error mb-4" role="alert">{{ friendlyError(error.code) }}</div>

          <div v-if="isLoading" class="flex justify-center py-8">
            <div class="vault42-spinner"></div>
          </div>
          <div v-else-if="sessions.length === 0" class="vault42-card text-center py-8">
            <p class="text-vault42-muted">{{ t('sessions.noActive') }}</p>
          </div>
          <div v-else class="space-y-2">
            <div
              v-for="s in sessions"
              :key="s.id"
              class="vault42-card flex items-center justify-between gap-4 !p-4"
            >
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2">
                  <div class="w-2 h-2 rounded-full bg-vault42-success vault42-pulse flex-shrink-0"></div>
                  <p class="text-sm font-medium truncate">
                    {{ s.friendly_name || s.user_agent?.slice(0, 60) || t('sessions.unknownSession') }}
                  </p>
                </div>
                <div class="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-vault42-muted">
                  <span>{{ s.ip }}</span>
                  <span v-if="s.last_seen_at">&middot; {{ t('sessions.lastSeen', { date: formatDate(new Date(s.last_seen_at)) }) }}</span>
                  <span v-if="s.first_seen_at">&middot; {{ t('sessions.since', { date: formatDate(new Date(s.first_seen_at)) }) }}</span>
                </div>
              </div>
              <button
                class="text-xs text-vault42-error hover:text-red-300 transition-colors flex-shrink-0"
                @click="revokeSession(s.id)"
              >
                {{ t('common.revoke') }}
              </button>
            </div>
          </div>
        </div>

        <!-- Devices -->
        <div>
          <div class="mb-4">
            <h2 class="text-xl font-bold">{{ t('devices.title') }}</h2>
            <p class="text-sm text-vault42-muted mt-0.5">{{ t('devices.subtitle') }}</p>
          </div>

          <div v-if="devices.length === 0 && !isLoading" class="vault42-card text-center py-8">
            <p class="text-vault42-muted">{{ t('devices.noDevices') }}</p>
          </div>
          <div v-else class="space-y-2">
            <div
              v-for="d in devices"
              :key="d.id"
              class="vault42-card flex items-center justify-between gap-4 !p-4"
            >
              <div class="flex-1 min-w-0">
                <!-- Editing mode -->
                <template v-if="editingId === d.id">
                  <div class="flex items-center gap-2">
                    <input
                      v-model="editName"
                      maxlength="100"
                      class="vault42-input !py-1.5 text-sm flex-1"
                      :placeholder="t('devices.deviceName')"
                      autofocus
                      @keyup.enter="saveEdit(d.id)"
                      @keyup.escape="cancelEdit"
                    />
                    <button class="text-xs text-vault42-success hover:text-green-400 transition-colors" @click="saveEdit(d.id)">{{ t('common.save') }}</button>
                    <button class="text-xs text-vault42-muted hover:text-vault42-text transition-colors" @click="cancelEdit">{{ t('common.cancel') }}</button>
                  </div>
                </template>

                <!-- Display mode -->
                <template v-else>
                  <div class="flex items-center gap-2">
                    <p class="text-sm font-medium truncate">
                      {{ d.friendly_name || d.user_agent?.slice(0, 60) || t('devices.unknownDevice') }}
                    </p>
                    <button
                      class="text-vault42-muted hover:text-vault42-text transition-colors flex-shrink-0"
                      :title="t('devices.renameDevice')"
                      @click="startEdit(d.id, d.friendly_name || '')"
                    >
                      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                      </svg>
                    </button>
                    <span v-if="d.trusted" class="vault42-badge-success flex-shrink-0">{{ t('common.trusted') }}</span>
                  </div>
                </template>

                <div class="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-vault42-muted">
                  <span>{{ d.ip }}</span>
                  <span v-if="d.last_seen_at">&middot; {{ t('sessions.lastSeen', { date: formatDate(new Date(d.last_seen_at)) }) }}</span>
                </div>
              </div>

              <button
                class="text-xs text-vault42-error hover:text-red-300 transition-colors flex-shrink-0"
                @click="removeDevice(d.id)"
              >
                {{ t('common.remove') }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </template>

    <template #loading>
      <div class="flex justify-center py-20">
        <div class="vault42-spinner vault42-spinner-lg"></div>
      </div>
    </template>
  </VaultAuthGuard>
</template>
