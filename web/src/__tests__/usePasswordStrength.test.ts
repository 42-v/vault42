import { describe, it, expect } from 'vitest'
import { ref, nextTick } from 'vue'
import { usePasswordStrength } from '../composables/usePasswordStrength'
import en from '../locales/en.json'

const copy = en as Record<string, string>

function withPassword(value: string) {
  const password = ref(value)
  return { password, ...usePasswordStrength(password) }
}

describe('usePasswordStrength', () => {
  it('reports no strength at all for an empty password', () => {
    const { passwordLength, passwordStrength } = withPassword('')
    expect(passwordLength.value).toBe(0)
    expect(passwordStrength.value).toBeNull()
  })

  it('tracks the raw character count', () => {
    expect(withPassword('a'.repeat(23)).passwordLength.value).toBe(23)
  })

  // The NIST 15-character minimum is the whole point of this widget: 14 must read
  // as a failure and 15 must read as a pass. An off-by-one here silently tells a
  // user their password is fine when the server will reject it.
  it('treats 14 characters as too short and 15 as acceptable (NIST minimum)', () => {
    expect(withPassword('a'.repeat(14)).passwordStrength.value).toEqual({
      labelKey: 'password.tooShort',
      color: 'text-vault42-error',
      width: 'w-1/4',
    })
    expect(withPassword('a'.repeat(15)).passwordStrength.value).toEqual({
      labelKey: 'password.acceptable',
      color: 'text-yellow-500',
      width: 'w-2/4',
    })
  })

  it('promotes to strong at 20 characters and excellent at 30', () => {
    expect(withPassword('a'.repeat(19)).passwordStrength.value?.labelKey).toBe('password.acceptable')
    expect(withPassword('a'.repeat(20)).passwordStrength.value).toEqual({
      labelKey: 'password.strong',
      color: 'text-vault42-success',
      width: 'w-3/4',
    })
    expect(withPassword('a'.repeat(29)).passwordStrength.value?.labelKey).toBe('password.strong')
    expect(withPassword('a'.repeat(30)).passwordStrength.value).toEqual({
      labelKey: 'password.excellent',
      color: 'text-vault42-success',
      width: 'w-full',
    })
  })

  it('never leaves the label untranslated: every band maps to real English copy', () => {
    const bands = [1, 15, 20, 30].map(n => withPassword('a'.repeat(n)).passwordStrength.value!)
    const seen = new Set<string>()
    for (const band of bands) {
      expect(copy[band.labelKey], `missing en.json copy for ${band.labelKey}`).toBeTruthy()
      seen.add(band.labelKey)
    }
    expect(seen.size).toBe(4)
  })

  it('drives the progress bar colour from the same thresholds as the label', () => {
    expect(withPassword('a'.repeat(14)).strengthBarColor.value).toBe('bg-vault42-error')
    expect(withPassword('a'.repeat(15)).strengthBarColor.value).toBe('bg-yellow-500')
    expect(withPassword('a'.repeat(19)).strengthBarColor.value).toBe('bg-yellow-500')
    expect(withPassword('a'.repeat(20)).strengthBarColor.value).toBe('bg-vault42-success')
    expect(withPassword('a'.repeat(60)).strengthBarColor.value).toBe('bg-vault42-success')
  })

  it('does not show a success colour for an empty password', () => {
    // passwordStrength is null at length 0, so the bar must not be able to read
    // as "good" if a template ever renders it unconditionally.
    expect(withPassword('').strengthBarColor.value).toBe('bg-vault42-error')
  })

  it('recomputes when the password ref changes', async () => {
    const { password, passwordLength, passwordStrength, strengthBarColor } = withPassword('short')

    expect(passwordStrength.value?.labelKey).toBe('password.tooShort')

    password.value = 'a'.repeat(32)
    await nextTick()

    expect(passwordLength.value).toBe(32)
    expect(passwordStrength.value?.labelKey).toBe('password.excellent')
    expect(strengthBarColor.value).toBe('bg-vault42-success')

    password.value = ''
    await nextTick()

    expect(passwordStrength.value).toBeNull()
  })

  it('counts whitespace and symbols as characters rather than trimming them', () => {
    const spaced = 'correct horse battery staple'
    expect(withPassword(spaced).passwordLength.value).toBe(spaced.length)
    expect(withPassword('   ').passwordStrength.value?.labelKey).toBe('password.tooShort')
  })
})
