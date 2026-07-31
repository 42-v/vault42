import { describe, it, expect } from 'vitest'
import { readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve as resolvePath } from 'node:path'
import { createI18n } from '@vault42/vue'
import { messages, detectLocale } from '../i18n'
import en from '../locales/en.json'

const localesDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '../locales')
const localeFiles = readdirSync(localesDir)
  .filter(f => f.endsWith('.json'))
  .map(f => f.replace(/\.json$/, ''))
  .sort()

const enCopy = en as Record<string, string>
const enKeys = Object.keys(enCopy).sort()

function placeholdersIn(value: string): string[] {
  return [...value.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort()
}

function i18n(locale: string) {
  return createI18n({ locale, fallbackLocale: 'en', messages })
}

describe('i18n bundle', () => {
  it('registers every locale file that ships in src/locales', () => {
    expect(Object.keys(messages).sort()).toEqual(localeFiles)
    expect(localeFiles.length).toBe(38)
  })

  it('re-exports detectLocale so main.ts has a single i18n entry point', () => {
    expect(typeof detectLocale).toBe('function')
  })

  it('gives every locale the exact key set of en.json', () => {
    const drift: string[] = []

    for (const [locale, bundle] of Object.entries(messages)) {
      const keys = Object.keys(bundle).sort()
      const missing = enKeys.filter(k => !(k in bundle))
      const extra = keys.filter(k => !(k in enCopy))
      if (missing.length) drift.push(`${locale} is missing: ${missing.join(', ')}`)
      if (extra.length) drift.push(`${locale} has stale keys: ${extra.join(', ')}`)
    }

    expect(drift).toEqual([])
  })

  it('has no blank translations that would render an empty label', () => {
    const blanks: string[] = []

    for (const [locale, bundle] of Object.entries(messages)) {
      for (const [key, value] of Object.entries(bundle)) {
        if (typeof value !== 'string') {
          blanks.push(`${locale}.${key} is ${typeof value}, not a string`)
        } else if (value.trim() === '') {
          blanks.push(`${locale}.${key} is empty`)
        }
      }
    }

    expect(blanks).toEqual([])
  })

  it('keeps the same interpolation placeholders in every translation', () => {
    // A translator dropping {count} silently renders "characters" with no number,
    // and a typo like {cout} renders the literal braces to the user.
    const drift: string[] = []

    for (const [locale, bundle] of Object.entries(messages)) {
      for (const key of enKeys) {
        const expected = placeholdersIn(enCopy[key])
        const actual = placeholdersIn(bundle[key] as string)
        if (expected.join(',') !== actual.join(',')) {
          drift.push(`${locale}.${key}: expected {${expected.join('} {')}} got {${actual.join('} {')}}`)
        }
      }
    }

    expect(drift).toEqual([])
  })
})

describe('i18n lookup', () => {
  it('resolves a key to the copy of the active locale', () => {
    expect(i18n('en').t('common.save')).toBe('Save')
    expect(i18n('sk').t('common.save')).toBe('Uložiť')
    expect(i18n('zh-Hant').t('common.save')).toBe('儲存')
  })

  it('interpolates named params into the translated string', () => {
    expect(i18n('en').t('password.characters', { count: 18 })).toBe('18 characters')
    expect(i18n('en').t('blobs.files', { used: 3, max: 50 })).toBe('3 / 50 files')
  })

  it('leaves the placeholder visible when a param is not supplied', () => {
    // Better a visible {count} in QA than a silently mangled sentence in prod.
    expect(i18n('en').t('password.characters')).toBe('{count} characters')
    expect(i18n('en').t('password.characters', { wrong: 1 })).toBe('{count} characters')
  })

  it('interpolates a zero value instead of dropping it', () => {
    expect(i18n('en').t('twoFactor.backup.remaining', { count: 0 })).toContain('0')
  })

  it('returns the key itself for a missing key rather than throwing', () => {
    const t = i18n('en').t
    expect(() => t('no.such.key')).not.toThrow()
    expect(t('no.such.key')).toBe('no.such.key')
    expect(t('')).toBe('')
  })

  it('falls back to English when the active locale has no bundle', () => {
    expect(i18n('kl-GL').t('common.save')).toBe('Save')
  })

  it('switches copy when the locale changes', () => {
    const inst = i18n('en')
    expect(inst.t('common.save')).toBe('Save')

    inst.setLocale('hu')
    expect(inst.locale.value).toBe('hu')
    expect(inst.t('common.save')).toBe(messages.hu['common.save'])
  })

  it('refuses to switch to a locale that has no messages', () => {
    const inst = i18n('en')
    inst.setLocale('kl-GL')

    expect(inst.locale.value).toBe('en')
    expect(inst.t('common.save')).toBe('Save')
  })

  it('exposes every shipped locale as available', () => {
    expect(i18n('en').availableLocales.sort()).toEqual(localeFiles)
  })

  it('formats dates in the active locale', () => {
    const date = new Date(Date.UTC(2026, 6, 30, 12, 0, 0))
    const opts: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' }

    expect(i18n('en').formatDate(date, opts)).toBe('July 30, 2026')
    expect(i18n('de').formatDate(date, opts)).toBe('30. Juli 2026')

    const inst = i18n('en')
    inst.setLocale('fr')
    expect(inst.formatDate(date, opts)).toBe('30 juillet 2026')
  })

  it('formats dates for every shipped locale without falling over', () => {
    // Intl throws RangeError on a malformed locale tag, which would take down any
    // view that renders a timestamp.
    const date = new Date(Date.UTC(2026, 0, 2, 0, 0, 0))
    for (const locale of Object.keys(messages)) {
      expect(() => createI18n({ locale, messages }).formatDate(date), `formatDate broke for ${locale}`).not.toThrow()
      expect(createI18n({ locale, messages }).formatDate(date).length).toBeGreaterThan(0)
    }
  })
})
