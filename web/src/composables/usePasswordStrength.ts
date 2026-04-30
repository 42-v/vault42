import { computed, type Ref } from 'vue'

interface PasswordStrength {
  labelKey: string
  color: string
  width: string
}

export function usePasswordStrength(password: Ref<string>) {
  const passwordLength = computed(() => password.value.length)

  const passwordStrength = computed<PasswordStrength | null>(() => {
    const len = passwordLength.value
    if (len === 0) return null
    if (len < 15) return { labelKey: 'password.tooShort', color: 'text-vault42-error', width: 'w-1/4' }
    if (len < 20) return { labelKey: 'password.acceptable', color: 'text-yellow-500', width: 'w-2/4' }
    if (len < 30) return { labelKey: 'password.strong', color: 'text-vault42-success', width: 'w-3/4' }
    return { labelKey: 'password.excellent', color: 'text-vault42-success', width: 'w-full' }
  })

  const strengthBarColor = computed(() => {
    const len = passwordLength.value
    if (len < 15) return 'bg-vault42-error'
    if (len < 20) return 'bg-yellow-500'
    return 'bg-vault42-success'
  })

  return { passwordLength, passwordStrength, strengthBarColor }
}
