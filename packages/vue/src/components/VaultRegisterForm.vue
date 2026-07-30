<script setup lang="ts">
import { ref, computed, inject } from 'vue'
import { useAuth } from '../composables/useAuth'
import { I18N_KEY } from '../i18n/plugin'

const props = withDefaults(
  defineProps<{
    minPasswordLength?: number
  }>(),
  { minPasswordLength: 15 },
)

const emit = defineEmits<{
  success: [result: unknown]
  error: [err: unknown]
}>()

const { register, error, isLoading } = useAuth()

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

// Generic copy for any code that is not mapped below. The raw code is never
// rendered: it is server-controlled text and carries no meaning for the user.
const GENERIC_ERROR = 'Something went wrong. Please try again.'
const TOO_MANY_ATTEMPTS = 'Too many attempts. Please try again later'

// Codes POST /auth/register, the registration gate and the rate-limit
// middleware can return. There is deliberately no entry for email_taken or
// email_already_registered: the server answers a duplicate registration with
// the same 201 it sends for a new account, and naming the conflict here would
// hand an attacker the account-enumeration oracle the server refuses to give.
const errorMessages = computed<Record<string, string>>(() => ({
  password_too_short: `Password must be at least ${props.minPasswordLength} characters`,
  password_breached: 'This password has been found in a data breach',
  password_required: 'Please choose a password',
  invalid_email: 'Please enter a valid email address',
  invalid_password: 'Password does not meet requirements',
  invalid_input: 'Please check the details you entered and try again',
  invalid_request: 'Please check the details you entered and try again',
  registration_disabled: 'Registration is currently closed.',
  rate_limited: TOO_MANY_ATTEMPTS,
  rate_limit_exceeded: TOO_MANY_ATTEMPTS,
  too_many_attempts: TOO_MANY_ATTEMPTS,
  server_busy: 'The server is busy right now. Please try again in a moment.',
  rate_limiter_unavailable: 'The server is busy right now. Please try again in a moment.',
  internal_error: GENERIC_ERROR,
  unknown_error: GENERIC_ERROR,
}))

function friendlyError(code: string): string {
  return errorMessages.value[code] || GENERIC_ERROR
}

const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const displayName = ref('')

const passwordMismatch = computed(
  () => confirmPassword.value !== '' && password.value !== confirmPassword.value,
)
const passwordTooShort = computed(
  () => password.value !== '' && password.value.length < props.minPasswordLength,
)
const canSubmit = computed(
  () =>
    email.value &&
    password.value.length >= props.minPasswordLength &&
    password.value === confirmPassword.value &&
    !isLoading.value,
)

async function handleRegister() {
  // The disabled default button is not a guard: a submit event dispatched on
  // the form (or a custom button in the header/footer slot) reaches this
  // handler with a short or mismatched password otherwise.
  if (!canSubmit.value) return
  try {
    await register(email.value, password.value, displayName.value || undefined)
    emit('success', { email: email.value })
  } catch (e) {
    emit('error', e)
  }
}
</script>

<template>
  <div class="vault42-register-form">
    <slot name="header">
      <h2>{{ t('register.header', 'Create Account') }}</h2>
    </slot>

    <div v-if="error" class="vault42-register-form__error">
      <slot name="error" :error="error">
        <p>{{ error.code ? friendlyError(error.code) : t('register.failed', 'Registration failed') }}</p>
      </slot>
    </div>

    <form @submit.prevent="handleRegister">
      <div class="vault42-register-form__field">
        <label for="vault42-reg-name">{{ t('register.displayName', 'Display Name') }}</label>
        <input
          id="vault42-reg-name"
          v-model="displayName"
          type="text"
          autocomplete="name"
        />
      </div>
      <div class="vault42-register-form__field">
        <label for="vault42-reg-email">{{ t('register.email', 'Email') }}</label>
        <input
          id="vault42-reg-email"
          v-model="email"
          type="email"
          autocomplete="email"
          required
        />
      </div>
      <div class="vault42-register-form__field">
        <label for="vault42-reg-password">{{ t('register.password', 'Password') }}</label>
        <input
          id="vault42-reg-password"
          v-model="password"
          type="password"
          autocomplete="new-password"
          :minlength="minPasswordLength"
          required
        />
        <p v-if="passwordTooShort" class="vault42-register-form__hint vault42-register-form__hint--error">
          {{ t('register.minChars', `Minimum ${minPasswordLength} characters`, { count: minPasswordLength }) }}
        </p>
      </div>
      <div class="vault42-register-form__field">
        <label for="vault42-reg-confirm">{{ t('register.confirmPassword', 'Confirm Password') }}</label>
        <input
          id="vault42-reg-confirm"
          v-model="confirmPassword"
          type="password"
          autocomplete="new-password"
          required
        />
        <p v-if="passwordMismatch" class="vault42-register-form__hint vault42-register-form__hint--error">
          {{ t('register.passwordsDoNotMatch', 'Passwords do not match') }}
        </p>
      </div>
      <button type="submit" :disabled="!canSubmit">
        {{ isLoading ? t('register.creating', 'Creating account...') : t('register.submit', 'Create Account') }}
      </button>
    </form>

    <slot name="footer" />
  </div>
</template>
