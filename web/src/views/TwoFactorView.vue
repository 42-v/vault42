<script setup lang="ts">
import { ref, onMounted, watch, useTemplateRef } from 'vue'
import { use2FA, useWebAuthn, useConfirm, VaultAuthGuard, useT } from '@vault42/vue'
import QRCode from 'qrcode'
import { friendlyError } from '../errorMessages'
import { useModalFocus } from '../composables/useModalFocus'

const { totpSetup, backupCodes, mfaStatus, isLoading, error, isVerified, setupTOTP, verifyTOTP, disableTOTP, generateBackupCodes, fetchMFAStatus } = use2FA()
const {
  isSupported: webauthnSupported,
  isLoading: webauthnLoading,
  error: webauthnError,
  credentials,
  register: registerWebAuthn,
  listCredentials,
  deleteCredential,
} = useWebAuthn()
const { isConfirmed, isLoading: confirmLoading, error: confirmError, confirm } = useConfirm()
const { t } = useT()

const code = ref('')
const codesCopied = ref(false)
const copyFailed = ref(false)
const backupCodesRef = ref<HTMLElement | null>(null)
const qrDataUrl = ref('')
const confirmPassword = ref('')
const showConfirmDialog = ref(false)
const pendingAction = ref<(() => Promise<void>) | null>(null)

// Security key management
const credentialLoading = ref(false)

watch(totpSetup, async (setup) => {
  if (setup?.otp_url) {
    try {
      // Dark modules on an opaque white quiet zone, which is the only
      // combination every decoder accepts. This used to be the app's palette
      // -- light modules on full transparency -- which reads correctly on the
      // dark card behind it and is undecodable anywhere else: saved, exported
      // or screenshotted onto white it becomes light grey on white, and an
      // inverted code is outside what several scanners (iOS Camera among them)
      // will read at all. The cantScan disclosure below hands over the secret to
      // type, so this is not a dead end -- but a code that silently fails to
      // scan pushes every enrolling user onto a 32-character manual entry, on
      // the screen they are least likely to come back to.
      qrDataUrl.value = await QRCode.toDataURL(setup.otp_url, {
        width: 200,
        margin: 2,
        color: { dark: '#0a0a0f', light: '#ffffff' },
      })
    } catch {
      qrDataUrl.value = ''
    }
  } else {
    qrDataUrl.value = ''
  }
})

onMounted(async () => {
  await fetchMFAStatus()
  await loadCredentials()
})

async function loadCredentials() {
  await listCredentials()
}

// Wraps a sensitive action with confirmation check
async function withConfirmation(action: () => Promise<void>) {
  if (isConfirmed()) {
    await action()
    return
  }
  pendingAction.value = action
  confirmPassword.value = ''
  showConfirmDialog.value = true
}

async function handleConfirm() {
  if (!confirmPassword.value) return
  const ok = await confirm(confirmPassword.value)
  if (ok && pendingAction.value) {
    showConfirmDialog.value = false
    await pendingAction.value()
    pendingAction.value = null
  }
}

function cancelConfirm() {
  showConfirmDialog.value = false
  pendingAction.value = null
  confirmPassword.value = ''
}

const dialogRef = useTemplateRef('dialog')
useModalFocus(showConfirmDialog, cancelConfirm, dialogRef)

async function handleVerify() {
  if (code.value.length !== 6) return
  await verifyTOTP(code.value)
}

async function handleSetupTOTP() {
  await withConfirmation(async () => {
    await setupTOTP()
  })
}

async function handleWebAuthnRegister() {
  await withConfirmation(async () => {
    try {
      await registerWebAuthn()
      await fetchMFAStatus()
      await loadCredentials()
    } catch {
      // Error is captured in webauthnError
    }
  })
}

async function handleDeleteCredential(id: string) {
  await withConfirmation(async () => {
    credentialLoading.value = true
    try {
      await deleteCredential(id)
      await fetchMFAStatus()
    } catch {
      // Error captured in webauthnError
    } finally {
      credentialLoading.value = false
    }
  })
}

async function handleDisableTOTP() {
  await withConfirmation(async () => {
    await disableTOTP()
  })
}

async function handleGenerateBackupCodes() {
  await withConfirmation(async () => {
    await generateBackupCodes()
  })
}

/**
 * Selects the rendered codes so they can still be copied by hand.
 *
 * The only fallback that works when the Clipboard API is unavailable, which is
 * exactly when the user needs one.
 */
function selectBackupCodes() {
  const node = backupCodesRef.value
  const selection = window.getSelection?.()
  if (!node || !selection) return

  const range = document.createRange()
  range.selectNodeContents(node)
  selection.removeAllRanges()
  selection.addRange(range)
}

async function copyBackupCodes() {
  copyFailed.value = false

  try {
    await navigator.clipboard.writeText(backupCodes.value.join('\n'))
  } catch {
    // writeText rejects in a non-secure context, when the document is not
    // focused, and when clipboard permission is denied; on an insecure origin
    // `navigator.clipboard` is not even defined. The promise used to be dropped
    // on the floor and "Copied!" shown unconditionally, so a user could believe
    // their recovery codes were saved with nothing on the clipboard — on the one
    // path that exists to stop them being locked out of the account.
    copyFailed.value = true
    selectBackupCodes()
    return
  }

  codesCopied.value = true
  setTimeout(() => { codesCopied.value = false }, 2000)
}
</script>

<template>
  <VaultAuthGuard>
    <template #default>
      <div class="max-w-lg mx-auto px-4 sm:px-6 py-8 space-y-6">
        <div>
          <h1 class="text-2xl font-bold">{{ t('twoFactor.title') }}</h1>
          <p class="text-sm text-vault42-muted mt-1">{{ t('twoFactor.subtitle') }}</p>
        </div>

        <div v-if="error" class="vault42-alert-error" role="alert">{{ friendlyError(error.code) }}</div>

        <!-- Confirmation Dialog -->
        <Teleport to="body">
          <div v-if="showConfirmDialog" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
            <div ref="dialog" class="vault42-card w-full max-w-sm space-y-4" role="dialog" aria-modal="true" aria-labelledby="confirm-dialog-title">
              <h3 id="confirm-dialog-title" class="text-lg font-semibold">{{ t('twoFactor.confirmPassword') }}</h3>
              <p class="text-sm text-vault42-muted">
                {{ t('twoFactor.confirmPasswordDesc') }}
              </p>
              <div v-if="confirmError" class="vault42-alert-error text-sm" role="alert">
                {{ friendlyError(confirmError.code) }}
              </div>
              <div>
                <label for="confirm-password" class="vault42-label">{{ t('twoFactor.enterPassword') }}</label>
                <input
                  id="confirm-password"
                  v-model="confirmPassword"
                  type="password"
                  autocomplete="current-password"
                  :aria-invalid="confirmError ? 'true' : undefined"
                  :placeholder="t('twoFactor.enterPassword')"
                  class="vault42-input w-full"
                  @keyup.enter="handleConfirm"
                />
              </div>
              <div class="flex gap-3 justify-end">
                <button class="vault42-btn-outline vault42-btn-sm" @click="cancelConfirm">{{ t('common.cancel') }}</button>
                <button
                  :disabled="confirmLoading || !confirmPassword"
                  class="vault42-btn vault42-btn-sm"
                  @click="handleConfirm"
                >
                  <span v-if="confirmLoading" class="vault42-spinner mr-2"></span>
                  {{ confirmLoading ? t('twoFactor.verifying') : t('common.confirm') }}
                </button>
              </div>
            </div>
          </div>
        </Teleport>

        <!-- Security Keys (WebAuthn) -->
        <div class="vault42-card">
          <div class="flex items-start gap-4">
            <div class="w-10 h-10 rounded-lg bg-vault42-primary/15 flex items-center justify-center shrink-0">
              <svg class="w-5 h-5 text-vault42-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
              </svg>
            </div>
            <div class="flex-1">
              <h3 class="text-sm font-semibold mb-1">{{ t('twoFactor.webauthn.title') }}</h3>
              <p v-if="!webauthnSupported" class="text-xs text-vault42-muted">
                {{ t('twoFactor.webauthn.notSupported') }}
              </p>
              <template v-else>
                <!-- Registered credentials list -->
                <div v-if="credentials.length > 0" class="space-y-2 mb-4">
                  <div
                    v-for="cred in credentials"
                    :key="cred.id"
                    class="flex items-center justify-between bg-vault42-bg rounded-lg px-3 py-2"
                  >
                    <div>
                      <p class="text-sm font-medium">{{ t('twoFactor.webauthn.key', { id: cred.id.substring(0, 8) }) }}</p>
                      <p class="text-xs text-vault42-muted">
                        {{ t('twoFactor.webauthn.added', { date: new Date(cred.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) }) }}
                        &middot; {{ t('twoFactor.webauthn.used', { count: cred.sign_count }) }}
                      </p>
                    </div>
                    <button
                      :disabled="credentialLoading"
                      class="text-xs text-vault42-error hover:text-red-300 transition-colors"
                      @click="handleDeleteCredential(cred.id)"
                    >
                      {{ t('common.remove') }}
                    </button>
                  </div>
                </div>

                <div v-if="webauthnError" class="vault42-alert-error text-xs mb-3" role="alert">{{ friendlyError(webauthnError.code) }}</div>
                <button
                  :disabled="webauthnLoading"
                  :class="credentials.length > 0 ? 'vault42-btn-outline vault42-btn-sm' : 'vault42-btn vault42-btn-sm'"
                  @click="handleWebAuthnRegister"
                >
                  <span v-if="webauthnLoading" class="vault42-spinner mr-2"></span>
                  {{ webauthnLoading ? t('twoFactor.webauthn.waitingForKey') : (credentials.length > 0 ? t('twoFactor.webauthn.addAnother') : t('twoFactor.webauthn.register')) }}
                </button>
              </template>
            </div>
          </div>
        </div>

        <!-- TOTP: Setup button -->
        <div v-if="!totpSetup && !isVerified && !mfaStatus?.totp_enabled" class="vault42-card">
          <div class="flex items-start gap-4">
            <div class="w-10 h-10 rounded-lg bg-vault42-primary/15 flex items-center justify-center shrink-0">
              <svg class="w-5 h-5 text-vault42-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div class="flex-1">
              <h3 class="text-sm font-semibold mb-1">{{ t('twoFactor.totp.title') }}</h3>
              <p class="text-xs text-vault42-muted mb-4">
                {{ t('twoFactor.totp.description') }}
              </p>
              <button :disabled="isLoading" class="vault42-btn vault42-btn-sm" @click="handleSetupTOTP">
                <span v-if="isLoading" class="vault42-spinner mr-2"></span>
                {{ isLoading ? t('twoFactor.totp.generating') : t('twoFactor.totp.beginSetup') }}
              </button>
            </div>
          </div>
        </div>

        <!-- TOTP: Scan QR / Enter secret -->
        <div v-if="totpSetup && !isVerified" class="vault42-card space-y-5">
          <div>
            <h3 class="text-sm font-semibold mb-1">{{ t('twoFactor.totp.step1') }}</h3>
            <p class="text-xs text-vault42-muted mb-3">{{ t('twoFactor.totp.step1Desc') }}</p>
          </div>

          <div class="flex flex-col items-center gap-4">
            <!-- The only white surface in the app, and it is white because a
                 scanner needs the quiet zone to be white. -->
            <div v-if="qrDataUrl" class="bg-white rounded-xl p-3">
              <img :src="qrDataUrl" alt="TOTP QR Code" width="200" height="200" class="block" />
            </div>
            <div v-else class="w-[200px] h-[200px] bg-vault42-bg rounded-xl flex items-center justify-center">
              <div class="vault42-spinner"></div>
            </div>
            <details class="w-full text-xs">
              <summary class="text-vault42-muted cursor-pointer hover:text-vault42-text transition-colors">
                {{ t('twoFactor.totp.cantScan') }}
              </summary>
              <div class="mt-2 bg-vault42-bg rounded-lg px-3 py-2.5 font-mono text-sm break-all select-all">
                {{ totpSetup.secret }}
              </div>
            </details>
          </div>

          <div class="border-t border-vault42-border pt-5">
            <h3 class="text-sm font-semibold mb-1">{{ t('twoFactor.totp.step2') }}</h3>
            <p class="text-xs text-vault42-muted mb-3">{{ t('twoFactor.totp.step2Desc') }}</p>
            <div class="flex gap-3">
              <input
                v-model="code"
                :aria-label="t('login.2fa.authenticationCode')"
                type="text"
                inputmode="numeric"
                pattern="[0-9]{6}"
                maxlength="6"
                placeholder="000000"
                class="vault42-input flex-1 text-center text-lg tracking-[0.3em] font-mono"
                @keyup.enter="handleVerify"
              />
              <button
                :disabled="isLoading || code.length !== 6"
                class="vault42-btn"
                @click="handleVerify"
              >
                {{ isLoading ? t('twoFactor.totp.verifying') : t('twoFactor.totp.verify') }}
              </button>
            </div>
          </div>
        </div>

        <!-- TOTP: Active (with disable option) -->
        <div v-if="isVerified || mfaStatus?.totp_enabled" class="vault42-card">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-full bg-vault42-success/15 flex items-center justify-center shrink-0">
                <svg class="w-5 h-5 text-vault42-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div>
                <h3 class="text-sm font-semibold text-vault42-success">{{ t('twoFactor.totp.active') }}</h3>
                <p class="text-xs text-vault42-muted">{{ t('twoFactor.totp.activeDesc') }}</p>
              </div>
            </div>
            <button
              class="text-xs text-vault42-error hover:text-red-300 transition-colors"
              @click="handleDisableTOTP"
            >
              {{ t('twoFactor.totp.disable') }}
            </button>
          </div>
        </div>

        <!-- Backup codes -->
        <div class="vault42-card">
          <div class="flex items-start gap-4">
            <div class="w-10 h-10 rounded-lg bg-vault42-border flex items-center justify-center shrink-0">
              <svg class="w-5 h-5 text-vault42-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <div class="flex-1">
              <h3 class="text-sm font-semibold mb-1">{{ t('twoFactor.backup.title') }}</h3>
              <p v-if="mfaStatus?.backup_codes_remaining" class="text-xs text-vault42-muted mb-2">
                {{ t('twoFactor.backup.remaining', { count: mfaStatus.backup_codes_remaining }) }}
              </p>
              <p class="text-xs text-vault42-muted mb-4">
                {{ t('twoFactor.backup.description') }}
              </p>
              <button
                :disabled="isLoading"
                class="vault42-btn-outline vault42-btn-sm"
                @click="handleGenerateBackupCodes"
              >
                {{ isLoading ? t('twoFactor.backup.generating') : t('twoFactor.backup.generate') }}
              </button>
            </div>
          </div>

          <div v-if="backupCodes.length > 0" class="mt-5 pt-5 border-t border-vault42-border">
            <div class="bg-yellow-500/10 border border-yellow-500/30 rounded-lg px-3 py-2.5 mb-3">
              <p class="text-xs text-yellow-500 font-semibold">{{ t('twoFactor.backup.saveWarning') }}</p>
              <p class="text-xs text-yellow-500/80 mt-0.5">{{ t('twoFactor.backup.storeOffline') }}</p>
            </div>
            <div class="flex justify-end mb-2">
              <button
                class="text-xs transition-colors"
                :class="copyFailed ? 'text-vault42-error' : 'text-vault42-accent hover:text-vault42-text'"
                aria-live="polite"
                @click="copyBackupCodes"
              >
                {{ copyFailed ? t('common.error') : codesCopied ? t('twoFactor.backup.copied') : t('twoFactor.backup.copyAll') }}
              </button>
            </div>
            <div ref="backupCodesRef" class="grid grid-cols-2 gap-2">
              <code
                v-for="c in backupCodes"
                :key="c"
                class="bg-vault42-bg rounded-lg px-3 py-2 text-center text-sm font-mono"
              >
                {{ c }}
              </code>
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
