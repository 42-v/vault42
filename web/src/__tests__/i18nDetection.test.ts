import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { detectLocale } from '../i18n/detection'
import { messages } from '../i18n'

const AVAILABLE = Object.keys(messages)
const STORAGE_KEY = 'vault42-locale'

/** Replaces navigator.languages/language for the duration of one test. */
function setBrowserLanguages(languages: readonly string[] | undefined) {
  Object.defineProperty(navigator, 'languages', {
    value: languages,
    configurable: true,
    writable: true,
  })
  Object.defineProperty(navigator, 'language', {
    value: languages?.[0] ?? 'en-US',
    configurable: true,
    writable: true,
  })
}

describe('detectLocale', () => {
  beforeEach(() => {
    localStorage.clear()
    setBrowserLanguages(['en-US'])
  })

  afterEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  it('honours a stored preference over the browser language', () => {
    localStorage.setItem(STORAGE_KEY, 'ja')
    setBrowserLanguages(['de-DE', 'de'])

    expect(detectLocale(AVAILABLE, 'en')).toBe('ja')
  })

  it('ignores a stored preference that is no longer shipped', () => {
    // A locale removed in a later release must not strand the user on a blank UI.
    localStorage.setItem(STORAGE_KEY, 'kl-GL')
    setBrowserLanguages(['fr-FR'])

    expect(detectLocale(AVAILABLE, 'en')).toBe('fr')
  })

  it('ignores an empty stored preference', () => {
    localStorage.setItem(STORAGE_KEY, '')
    setBrowserLanguages(['sk-SK'])

    expect(detectLocale(AVAILABLE, 'en')).toBe('sk')
  })

  it('matches an exact browser locale before trying anything else', () => {
    setBrowserLanguages(['zh-Hant', 'zh-Hans'])
    expect(detectLocale(AVAILABLE, 'en')).toBe('zh-Hant')

    setBrowserLanguages(['zh-Hans', 'zh-Hant'])
    expect(detectLocale(AVAILABLE, 'en')).toBe('zh-Hans')
  })

  it('falls back from a regional tag to its base language', () => {
    const cases: Array<[string, string]> = [
      ['pt-BR', 'pt'],
      ['en-GB', 'en'],
      ['de-AT', 'de'],
      ['es-419', 'es'],
      ['fr-CA', 'fr'],
      ['sr-Latn-RS', 'sr'],
    ]

    for (const [browser, expected] of cases) {
      setBrowserLanguages([browser])
      expect(detectLocale(AVAILABLE, 'en'), `${browser} should resolve to ${expected}`).toBe(expected)
    }
  })

  it('walks the preference list in order and skips languages it cannot serve', () => {
    setBrowserLanguages(['kl-GL', 'xh', 'hu-HU', 'de'])
    expect(detectLocale(AVAILABLE, 'en')).toBe('hu')
  })

  it('respects preference order rather than picking the first available locale', () => {
    setBrowserLanguages(['pl', 'de'])
    expect(detectLocale(AVAILABLE, 'en')).toBe('pl')

    setBrowserLanguages(['de', 'pl'])
    expect(detectLocale(AVAILABLE, 'en')).toBe('de')
  })

  it('resolves a bare language to a script-tagged locale when that is all we ship', () => {
    // We ship zh-Hans/zh-Hant but no plain "zh", so a bare "zh" must still land on
    // a Chinese bundle instead of dropping the user to English.
    setBrowserLanguages(['zh'])
    const resolved = detectLocale(AVAILABLE, 'en')
    expect(['zh-Hans', 'zh-Hant']).toContain(resolved)
  })

  it('returns the fallback when nothing in the preference list is available', () => {
    setBrowserLanguages(['kl-GL', 'xh-ZA', 'gn'])
    expect(detectLocale(AVAILABLE, 'en')).toBe('en')
  })

  it('returns the fallback when no locales are available at all', () => {
    setBrowserLanguages(['sk-SK'])
    expect(detectLocale([], 'en')).toBe('en')
  })

  it('returns the fallback when the browser reports no languages', () => {
    setBrowserLanguages([])
    expect(detectLocale(AVAILABLE, 'en')).toBe('en')
  })

  it('falls back to navigator.language when navigator.languages is unavailable', () => {
    // Older/embedded webviews expose only navigator.language.
    Object.defineProperty(navigator, 'languages', { value: undefined, configurable: true, writable: true })
    Object.defineProperty(navigator, 'language', { value: 'it-IT', configurable: true, writable: true })

    expect(detectLocale(AVAILABLE, 'en')).toBe('it')
  })

  it('only ever returns a locale that actually has messages', () => {
    const probes = ['pt-BR', 'zh-Hant', 'nb-NO', 'kl-GL', 'en-US', 'ar-EG', 'he-IL']
    for (const probe of probes) {
      setBrowserLanguages([probe])
      const resolved = detectLocale(AVAILABLE, 'en')
      expect(messages[resolved], `${probe} resolved to unshipped locale ${resolved}`).toBeDefined()
    }
  })

  it('does not treat a prefix collision as a match', () => {
    // "no" (Norwegian) must not swallow a request for a different language whose
    // tag merely starts with the same letters.
    setBrowserLanguages(['nom'])
    expect(detectLocale(['no', 'en'], 'en')).toBe('en')
  })
})
