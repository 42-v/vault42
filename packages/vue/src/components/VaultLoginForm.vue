<script setup lang="ts">
import { ref, computed } from 'vue'

import { useAuth } from '../composables/useAuth'
import { useWebAuthn } from '../composables/useWebAuthn'
import { useVaultClient } from '../plugin'

const props = defineProps<{
  redirectUrl?: string
  showRegisterLink?: boolean
  errorMessages?: Record<string, string>
}>()

const emit = defineEmits<{
  success: [user: unknown]
  error: [err: unknown]
  'register-click': []
  'forgot-password-click': []
}>()

const { login, verify2FA, verify2FABackupCode, verify2FAEmailOTP, verify2FAWebAuthn, requires2FA, challengeToken, availableMethods, error, isLoading, user } = useAuth()
const { isSupported: webauthnSupported, isLoading: webauthnLoading, verify: webauthnVerify } = useWebAuthn()

const hasWebAuthn = computed(() => availableMethods.value.includes('webauthn') && webauthnSupported.value)
const hasTOTP = computed(() => availableMethods.value.includes('totp'))
const hasBackupCode = computed(() => availableMethods.value.includes('backup_code'))
const hasEmailOTP = computed(() => availableMethods.value.includes('email_otp'))
const showTOTPFallback = ref(false)
const showBackupCodeFallback = ref(false)

const client = useVaultClient()

const defaultErrorMessages: Record<string, string> = {
  invalid_credentials: 'Invalid email or password',
  account_locked: 'Account temporarily locked. Please try again later.',
  email_not_verified: 'Please verify your email before logging in',
  invalid_code: 'Invalid verification code',
  rate_limited: 'Too many attempts. Please wait and try again.',
  password_too_short: 'Password is too short',
  internal_error: 'Something went wrong. Please try again.',
  webauthn_failed: 'Security key verification failed. Please try again.',
}

const messages = computed(() => ({ ...defaultErrorMessages, ...props.errorMessages }))

function friendlyError(code: string): string {
  return messages.value[code] || code
}

const email = ref('')
const password = ref('')
const rememberMe = ref(false)
const totpCode = ref('')
const backupCode = ref('')
const emailOTPCode = ref('')
const emailOTPResending = ref(false)
const webauthnError = ref<string | null>(null)

async function handleLogin() {
  try {
    await login(email.value, password.value, rememberMe.value)
    if (!requires2FA.value) {
      emit('success', user.value)
    }
  } catch (e) {
    emit('error', e)
  }
}

async function handleVerify2FA() {
  try {
    await verify2FA(totpCode.value)
    emit('success', user.value)
  } catch (e) {
    emit('error', e)
  }
}

async function handleVerifyBackupCode() {
  try {
    await verify2FABackupCode(backupCode.value)
    emit('success', user.value)
  } catch (e) {
    emit('error', e)
  }
}

async function handleVerifyEmailOTP() {
  try {
    await verify2FAEmailOTP(emailOTPCode.value)
    emit('success', user.value)
  } catch (e) {
    emit('error', e)
  }
}

async function handleResendEmailOTP() {
  emailOTPResending.value = true
  try {
    await client.resendEmailOTP()
  } catch {
    // Resend errors are non-critical
  } finally {
    emailOTPResending.value = false
  }
}

async function handleWebAuthnVerify() {
  webauthnError.value = null
  try {
    await webauthnVerify(challengeToken.value || undefined)
    await verify2FAWebAuthn()
    emit('success', user.value)
  } catch (e: unknown) {
    if (e && typeof e === 'object' && 'code' in e) {
      webauthnError.value = (e as { code: string }).code
    } else {
      webauthnError.value = 'webauthn_failed'
    }
    emit('error', e)
  }
}
</script>

<template>
  <div class="vault42-login-form">
    <slot name="header">
      <h2>Sign In</h2>
    </slot>

    <div v-if="error" class="vault42-login-form__error">
      <slot name="error" :error="error">
        <p>{{ error.code ? friendlyError(error.code) : 'Login failed' }}</p>
      </slot>
    </div>

    <!-- 2FA verification step -->
    <div v-if="requires2FA">
      <!-- Backup code form -->
      <div v-if="showBackupCodeFallback">
        <form @submit.prevent="handleVerifyBackupCode">
          <div class="vault42-login-form__field">
            <label for="vault42-backup-code">Backup Code</label>
            <input
              id="vault42-backup-code"
              v-model="backupCode"
              type="text"
              autocomplete="off"
              placeholder="Enter backup code"
              required
            />
          </div>
          <button type="submit" :disabled="isLoading || !backupCode.trim()">
            {{ isLoading ? 'Verifying...' : 'Verify Backup Code' }}
          </button>
        </form>
        <p class="vault42-login-form__2fa-link">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showBackupCodeFallback = false">Back to other methods</a>
        </p>
      </div>

      <!-- WebAuthn primary (when user has security keys) -->
      <div v-else-if="hasWebAuthn && !showTOTPFallback" class="vault42-login-form__2fa-section">
        <p v-if="webauthnError" class="vault42-login-form__error">{{ friendlyError(webauthnError) }}</p>
        <button
          type="button"
          :disabled="webauthnLoading"
          class="vault42-login-form__2fa-button"
          @click="handleWebAuthnVerify"
        >
          {{ webauthnLoading ? 'Waiting for key...' : 'Use Security Key' }}
        </button>
        <p v-if="hasTOTP" class="vault42-login-form__2fa-link">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showTOTPFallback = true">Use authenticator code instead</a>
        </p>
        <p v-if="hasBackupCode" class="vault42-login-form__2fa-link vault42-login-form__2fa-link--compact">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showBackupCodeFallback = true">Use a backup code</a>
        </p>
      </div>

      <!-- TOTP (primary when no WebAuthn, fallback when both) -->
      <div v-else-if="(hasTOTP && !hasWebAuthn) || showTOTPFallback">
        <form @submit.prevent="handleVerify2FA">
          <div class="vault42-login-form__field">
            <label for="vault42-totp-code">Authentication Code</label>
            <input
              id="vault42-totp-code"
              v-model="totpCode"
              type="text"
              inputmode="numeric"
              pattern="[0-9]{6}"
              maxlength="6"
              autocomplete="one-time-code"
              placeholder="000000"
              required
            />
          </div>
          <button type="submit" :disabled="isLoading || totpCode.length !== 6">
            {{ isLoading ? 'Verifying...' : 'Verify' }}
          </button>
        </form>
        <p v-if="hasWebAuthn && showTOTPFallback" class="vault42-login-form__2fa-link">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showTOTPFallback = false">Use security key instead</a>
        </p>
        <p v-if="hasBackupCode" class="vault42-login-form__2fa-link vault42-login-form__2fa-link--compact">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showBackupCodeFallback = true">Use a backup code</a>
        </p>
      </div>

      <!-- Email OTP (fallback when no TOTP/WebAuthn configured) -->
      <div v-else-if="hasEmailOTP">
        <p class="vault42-login-form__2fa-hint">Check your email for a verification code.</p>
        <form @submit.prevent="handleVerifyEmailOTP">
          <div class="vault42-login-form__field">
            <label for="vault42-email-otp-code">Email Verification Code</label>
            <input
              id="vault42-email-otp-code"
              v-model="emailOTPCode"
              type="text"
              inputmode="numeric"
              pattern="[0-9]{6}"
              maxlength="6"
              autocomplete="one-time-code"
              placeholder="000000"
              required
            />
          </div>
          <button type="submit" :disabled="isLoading || emailOTPCode.length !== 6">
            {{ isLoading ? 'Verifying...' : 'Verify Code' }}
          </button>
        </form>
        <p class="vault42-login-form__2fa-link">
          <a
            href="#"
            class="vault42-login-form__2fa-action"
            :class="{ 'vault42-login-form__2fa-action--disabled': emailOTPResending }"
            @click.prevent="handleResendEmailOTP"
          >
            {{ emailOTPResending ? 'Sending...' : 'Resend code' }}
          </a>
        </p>
      </div>
    </div>

    <!-- Login form -->
    <form v-else @submit.prevent="handleLogin">
      <div class="vault42-login-form__field">
        <label for="vault42-login-email">Email</label>
        <input
          id="vault42-login-email"
          v-model="email"
          type="email"
          autocomplete="email"
          required
        />
      </div>
      <div class="vault42-login-form__field">
        <label for="vault42-login-password">Password</label>
        <input
          id="vault42-login-password"
          v-model="password"
          type="password"
          autocomplete="current-password"
          required
        />
      </div>
      <div class="vault42-login-form__field vault42-login-form__field--row">
        <label class="vault42-login-form__field--checkbox">
          <input v-model="rememberMe" type="checkbox" />
          Remember me
        </label>
        <a href="#" class="vault42-login-form__forgot-link" @click.prevent="emit('forgot-password-click')">
          Forgot password?
        </a>
      </div>
      <button type="submit" :disabled="isLoading">
        {{ isLoading ? 'Signing in...' : 'Sign In' }}
      </button>
      <p v-if="showRegisterLink !== false" class="vault42-login-form__register-link">
        <a href="#" @click.prevent="emit('register-click')">Create an account</a>
      </p>
    </form>

    <slot name="footer" />
  </div>
</template>

<style scoped>
.vault42-login-form__2fa-section {
  margin-bottom: 1rem;
}

.vault42-login-form__2fa-button {
  width: 100%;
}

.vault42-login-form__2fa-link {
  text-align: center;
  margin: 0.75rem 0;
  font-size: 0.85em;
  opacity: 0.6;
}

.vault42-login-form__2fa-link--compact {
  margin: 0.25rem 0;
}

.vault42-login-form__2fa-action {
  opacity: 0.8;
}

.vault42-login-form__2fa-action--disabled {
  opacity: 0.4;
  pointer-events: none;
}

.vault42-login-form__2fa-hint {
  margin: 0 0 1rem;
  font-size: 0.9em;
  opacity: 0.8;
}
</style>
