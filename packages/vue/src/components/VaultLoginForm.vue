<!--
  VaultLoginForm: a ready-made sign-in form covering the password step and all
  four second factors (TOTP, WebAuthn, backup code, email OTP).

  Props:
    redirectUrl        where to send the user after a completed sign-in
    showRegisterLink   render the "create account" link (default true)
    errorMessages      per-code copy overrides, merged over the built-in map

  Emits:
    success               (user)  sign-in completed, second factor included
    error                 (err)   sign-in failed
    register-click                the register link was activated
    forgot-password-click         the reset link was activated

  The form drives the whole two-step flow itself: on a `requires_2fa` response
  it switches to the factor the server offered, so `success` fires only once the
  user is fully authenticated. Which factors appear is decided by the server's
  `available_methods`, with WebAuthn additionally gated on browser support.

  Translates through the i18n plugin when one is installed and falls back to
  built-in English copy otherwise, so it renders standalone.

  Server error codes are mapped to fixed copy and the raw code is never
  rendered. The account-state codes deliberately share one neutral message, so
  the form does not disclose a distinction the server withheld.
-->
<script setup lang="ts">
import { ref, computed, inject } from 'vue'

import { useAuth } from '../composables/useAuth'
import { useWebAuthn } from '../composables/useWebAuthn'
import { useVaultClient } from '../plugin'
import { I18N_KEY } from '../i18n/plugin'

const props = withDefaults(
  defineProps<{
    redirectUrl?: string
    showRegisterLink?: boolean
    errorMessages?: Record<string, string>
  }>(),
  // `redirectUrl` and `errorMessages` are optional by design, but Vue compiles a
  // prop with no declared default to `undefined` at runtime while the type says
  // it may be absent. Declaring them keeps the runtime and the published .d.ts
  // saying the same thing, and `errorMessages` gets a factory so every instance
  // holds its own object rather than sharing one.
  {
    redirectUrl: undefined,
    showRegisterLink: true,
    errorMessages: () => ({}),
  },
)

// Optional: the form renders standalone, without app.use(createI18nPlugin(...)).
const i18n = inject(I18N_KEY, null)

/**
 * Translates `key`, falling back to the English copy when no i18n plugin is
 * installed or the active locale has no entry for the key (createI18n returns
 * the key itself in that case).
 */
function t(key: string, fallback: string, params?: Record<string, string | number>): string {
  if (!i18n) return fallback
  const translated = i18n.t(key, params)
  return translated === key ? fallback : translated
}

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

// Generic copy for any code that is not mapped below. The raw code is never
// rendered: it is server-controlled text and carries no meaning for the user.
const GENERIC_ERROR = 'Something went wrong. Please try again.'

// Every code POST /auth/login, the 2FA verification routes, the WebAuthn
// routes and the rate-limit middleware can return. Account state codes share
// one neutral message so the UI does not add detail the server withheld.
const ACCOUNT_UNAVAILABLE = 'This account is not available. Please contact support.'
const SESSION_EXPIRED = 'Your session has expired. Please sign in again.'
const TOO_MANY_ATTEMPTS = 'Too many attempts. Please wait and try again.'
const WEBAUTHN_FAILED = 'Security key verification failed. Please try again.'

const defaultErrorMessages: Record<string, string> = {
  invalid_credentials: 'Invalid email or password',
  invalid_password: 'Invalid email or password',
  password_required: 'Please enter your password',
  password_too_short: 'Password is too short',
  account_locked: 'Account temporarily locked. Please try again later.',
  account_banned: ACCOUNT_UNAVAILABLE,
  account_disabled: ACCOUNT_UNAVAILABLE,
  account_unavailable: ACCOUNT_UNAVAILABLE,
  email_not_verified: 'Please verify your email before logging in',
  invalid_code: 'Invalid verification code',
  invalid_or_expired_code: 'That code has expired. Please request a new one.',
  code_required: 'Enter the verification code to continue',
  invalid_backup_code: 'Invalid backup code',
  backup_code_already_used: 'That backup code has already been used. Try another one.',
  totp_code_already_used: 'That code has already been used. Wait for the next one.',
  rate_limited: TOO_MANY_ATTEMPTS,
  rate_limit_exceeded: TOO_MANY_ATTEMPTS,
  too_many_attempts: 'Too many failed attempts. Please try again later.',
  too_many_sessions: 'Too many active sessions. Sign out on another device and try again.',
  server_busy: 'The server is busy right now. Please try again in a moment.',
  rate_limiter_unavailable: 'The server is busy right now. Please try again in a moment.',
  session_expired: SESSION_EXPIRED,
  token_expired: SESSION_EXPIRED,
  invalid_token: SESSION_EXPIRED,
  invalid_or_expired_token: SESSION_EXPIRED,
  unauthorized: SESSION_EXPIRED,
  replay_detected: 'Your session was ended for security reasons. Please sign in again.',
  challenge_consumed: 'That verification attempt was already used. Please sign in again.',
  no_pending_verification: 'That verification attempt has expired. Please sign in again.',
  access_denied: 'Access to this account is not allowed from here.',
  forbidden: 'Access to this account is not allowed from here.',
  invalid_input: 'Please check the details you entered and try again.',
  invalid_request: 'Please check the details you entered and try again.',
  webauthn_failed: WEBAUTHN_FAILED,
  webauthn_error: WEBAUTHN_FAILED,
  webauthn_verification_failed: WEBAUTHN_FAILED,
  webauthn_cancelled: 'Security key prompt was dismissed. Please try again.',
  webauthn_not_configured: 'Security keys are not available for this account.',
  no_webauthn_credentials: 'No security key is registered on this account.',
  credential_not_found: 'That security key is not registered on this account.',
  cloned_authenticator_detected: 'This security key was rejected for security reasons. Please contact support.',
  internal_error: GENERIC_ERROR,
  unknown_error: GENERIC_ERROR,
}

const messages = computed(() => ({ ...defaultErrorMessages, ...props.errorMessages }))

function friendlyError(code: string): string {
  return messages.value[code] || GENERIC_ERROR
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
  // The disabled default button is not a guard: a submit event dispatched on
  // the form (or a custom button in the header/footer slot) reaches this
  // handler regardless.
  if (isLoading.value || !email.value || !password.value) return
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
      <h2>{{ t('common.signIn', 'Sign In') }}</h2>
    </slot>

    <div v-if="error" id="vault42-login-form-error" class="vault42-login-form__error" role="alert">
      <slot name="error" :error="error">
        <p>{{ error.code ? friendlyError(error.code) : t('login.failed', 'Login failed') }}</p>
      </slot>
    </div>

    <!-- 2FA verification step -->
    <div v-if="requires2FA">
      <!-- Backup code form -->
      <div v-if="showBackupCodeFallback">
        <form @submit.prevent="handleVerifyBackupCode">
          <div class="vault42-login-form__field">
            <label for="vault42-backup-code">{{ t('login.2fa.backupCode', 'Backup Code') }}</label>
            <input
              id="vault42-backup-code"
              v-model="backupCode"
              type="text"
              autocomplete="off"
              :placeholder="t('login.2fa.enterBackupCode', 'Enter backup code')"
              required
            />
          </div>
          <button type="submit" :disabled="isLoading || !backupCode.trim()">
            {{ isLoading ? t('login.2fa.verifying', 'Verifying...') : t('login.2fa.verifyBackupCode', 'Verify Backup Code') }}
          </button>
        </form>
        <p class="vault42-login-form__2fa-link">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showBackupCodeFallback = false">{{ t('login.2fa.backToOtherMethods', 'Back to other methods') }}</a>
        </p>
      </div>

      <!-- WebAuthn primary (when user has security keys) -->
      <div v-else-if="hasWebAuthn && !showTOTPFallback" class="vault42-login-form__2fa-section">
        <p v-if="webauthnError" class="vault42-login-form__error" role="alert">{{ friendlyError(webauthnError) }}</p>
        <button
          type="button"
          :disabled="webauthnLoading"
          class="vault42-login-form__2fa-button"
          @click="handleWebAuthnVerify"
        >
          {{ webauthnLoading ? t('login.2fa.waitingForKey', 'Waiting for key...') : t('login.2fa.useSecurityKey', 'Use Security Key') }}
        </button>
        <p v-if="hasTOTP" class="vault42-login-form__2fa-link">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showTOTPFallback = true">{{ t('login.2fa.useAuthenticatorInstead', 'Use authenticator code instead') }}</a>
        </p>
        <p v-if="hasBackupCode" class="vault42-login-form__2fa-link vault42-login-form__2fa-link--compact">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showBackupCodeFallback = true">{{ t('login.2fa.useBackupCode', 'Use a backup code') }}</a>
        </p>
      </div>

      <!-- TOTP (primary when no WebAuthn, fallback when both) -->
      <div v-else-if="(hasTOTP && !hasWebAuthn) || showTOTPFallback">
        <form @submit.prevent="handleVerify2FA">
          <div class="vault42-login-form__field">
            <label for="vault42-totp-code">{{ t('login.2fa.authenticationCode', 'Authentication Code') }}</label>
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
            {{ isLoading ? t('login.2fa.verifying', 'Verifying...') : t('login.2fa.verify', 'Verify') }}
          </button>
        </form>
        <p v-if="hasWebAuthn && showTOTPFallback" class="vault42-login-form__2fa-link">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showTOTPFallback = false">{{ t('login.2fa.useSecurityKeyInstead', 'Use security key instead') }}</a>
        </p>
        <p v-if="hasBackupCode" class="vault42-login-form__2fa-link vault42-login-form__2fa-link--compact">
          <a href="#" class="vault42-login-form__2fa-action" @click.prevent="showBackupCodeFallback = true">{{ t('login.2fa.useBackupCode', 'Use a backup code') }}</a>
        </p>
      </div>

      <!-- Email OTP (fallback when no TOTP/WebAuthn configured) -->
      <div v-else-if="hasEmailOTP">
        <p class="vault42-login-form__2fa-hint">{{ t('login.2fa.checkEmail', 'Check your email for a verification code.') }}</p>
        <form @submit.prevent="handleVerifyEmailOTP">
          <div class="vault42-login-form__field">
            <label for="vault42-email-otp-code">{{ t('login.2fa.emailVerificationCode', 'Email Verification Code') }}</label>
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
            {{ isLoading ? t('login.2fa.verifying', 'Verifying...') : t('login.2fa.verifyCode', 'Verify Code') }}
          </button>
        </form>
        <p class="vault42-login-form__2fa-link">
          <a
            href="#"
            class="vault42-login-form__2fa-action"
            :class="{ 'vault42-login-form__2fa-action--disabled': emailOTPResending }"
            @click.prevent="handleResendEmailOTP"
          >
            {{ emailOTPResending ? t('login.2fa.sending', 'Sending...') : t('login.2fa.resendCode', 'Resend code') }}
          </a>
        </p>
      </div>
    </div>

    <!-- Login form -->
    <form v-else @submit.prevent="handleLogin">
      <div class="vault42-login-form__field">
        <label for="vault42-login-email">{{ t('login.email', 'Email') }}</label>
        <input
          id="vault42-login-email"
          v-model="email"
          type="email"
          autocomplete="email"
          :aria-invalid="error ? 'true' : undefined"
          :aria-describedby="error ? 'vault42-login-form-error' : undefined"
          required
        />
      </div>
      <div class="vault42-login-form__field">
        <label for="vault42-login-password">{{ t('login.password', 'Password') }}</label>
        <input
          id="vault42-login-password"
          v-model="password"
          type="password"
          autocomplete="current-password"
          :aria-invalid="error ? 'true' : undefined"
          :aria-describedby="error ? 'vault42-login-form-error' : undefined"
          required
        />
      </div>
      <div class="vault42-login-form__field vault42-login-form__field--row">
        <label class="vault42-login-form__field--checkbox">
          <input v-model="rememberMe" type="checkbox" />
          {{ t('login.rememberMe', 'Remember me') }}
        </label>
        <a href="#" class="vault42-login-form__forgot-link" @click.prevent="emit('forgot-password-click')">
          {{ t('login.forgotPassword', 'Forgot password?') }}
        </a>
      </div>
      <button type="submit" :disabled="isLoading">
        {{ isLoading ? t('login.signingIn', 'Signing in...') : t('login.submit', 'Sign In') }}
      </button>
      <p v-if="showRegisterLink" class="vault42-login-form__register-link">
        <a href="#" @click.prevent="emit('register-click')">{{ t('login.createAccount', 'Create an account') }}</a>
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
