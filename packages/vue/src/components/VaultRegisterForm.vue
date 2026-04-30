<script setup lang="ts">
import { ref, computed } from 'vue'
import { useAuth } from '../composables/useAuth'

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

const errorMessages: Record<string, string> = {
  email_taken: 'An account with this email already exists',
  password_too_short: 'Password must be at least 15 characters',
  password_breached: 'This password has been found in a data breach',
  invalid_email: 'Please enter a valid email address',
  rate_limited: 'Too many attempts. Please try again later',
  invalid_password: 'Password does not meet requirements',
  internal_error: 'Something went wrong. Please try again.',
}

function friendlyError(code: string): string {
  return errorMessages[code] || code
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
      <h2>Create Account</h2>
    </slot>

    <div v-if="error" class="vault42-register-form__error">
      <slot name="error" :error="error">
        <p>{{ error.code ? friendlyError(error.code) : 'Registration failed' }}</p>
      </slot>
    </div>

    <form @submit.prevent="handleRegister">
      <div class="vault42-register-form__field">
        <label for="vault42-reg-name">Display Name</label>
        <input
          id="vault42-reg-name"
          v-model="displayName"
          type="text"
          autocomplete="name"
        />
      </div>
      <div class="vault42-register-form__field">
        <label for="vault42-reg-email">Email</label>
        <input
          id="vault42-reg-email"
          v-model="email"
          type="email"
          autocomplete="email"
          required
        />
      </div>
      <div class="vault42-register-form__field">
        <label for="vault42-reg-password">Password</label>
        <input
          id="vault42-reg-password"
          v-model="password"
          type="password"
          autocomplete="new-password"
          :minlength="minPasswordLength"
          required
        />
        <p v-if="passwordTooShort" class="vault42-register-form__hint vault42-register-form__hint--error">
          Minimum {{ minPasswordLength }} characters
        </p>
      </div>
      <div class="vault42-register-form__field">
        <label for="vault42-reg-confirm">Confirm Password</label>
        <input
          id="vault42-reg-confirm"
          v-model="confirmPassword"
          type="password"
          autocomplete="new-password"
          required
        />
        <p v-if="passwordMismatch" class="vault42-register-form__hint vault42-register-form__hint--error">
          Passwords do not match
        </p>
      </div>
      <button type="submit" :disabled="!canSubmit">
        {{ isLoading ? 'Creating account...' : 'Create Account' }}
      </button>
    </form>

    <slot name="footer" />
  </div>
</template>
