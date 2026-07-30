import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, h, nextTick } from 'vue'
import { createI18n } from '../i18n/i18n'
import type { LocaleMessages } from '../i18n/types'

const en: LocaleMessages = {
  'common.signIn': 'Sign In',
  'auth.welcome': 'Welcome back, {name}',
  'auth.attempts': '{used} of {total} attempts used',
  'auth.repeat': '{name}, is that you {name}?',
  nested: { title: 'Nested Title' },
  'nested.title': 'Flat Wins',
  group: { deep: 'Deep Value' },
}

const de: LocaleMessages = {
  'common.signIn': 'Anmelden',
  // auth.* deliberately untranslated: this locale is partial.
}

function i18n(overrides: Partial<Parameters<typeof createI18n>[0]> = {}) {
  return createI18n({
    locale: 'en',
    messages: { en, de },
    ...overrides,
  })
}

describe('createI18n key lookup', () => {
  it('returns the message for the active locale', () => {
    expect(i18n().t('common.signIn')).toBe('Sign In')
  })

  it('resolves dot-notation through nested objects', () => {
    expect(i18n().t('group.deep')).toBe('Deep Value')
  })

  it('prefers a flat key over the nested path of the same name', () => {
    // en has both "nested.title" (flat) and nested: { title }.
    expect(i18n().t('nested.title')).toBe('Flat Wins')
  })

  it('returns the key itself for a missing key instead of throwing', () => {
    expect(() => i18n().t('does.not.exist')).not.toThrow()
    expect(i18n().t('does.not.exist')).toBe('does.not.exist')
  })

  it('returns the key when the path resolves to an object rather than a string', () => {
    // "group" is an object; a partial path must not leak "[object Object]".
    expect(i18n().t('group')).toBe('group')
  })

  it('does not interpolate the key it falls back to', () => {
    expect(i18n().t('missing.{name}', { name: 'Mallory' })).toBe('missing.{name}')
  })

  it('does not resolve keys through the prototype chain', () => {
    // messages is a plain object literal, so "constructor"/"toString" are
    // reachable via [] lookup; neither may produce a translation.
    const t = i18n().t
    expect(t('toString')).toBe('toString')
    expect(t('constructor.name')).toBe('constructor.name')
    expect(t('__proto__.toString')).toBe('__proto__.toString')
  })
})

describe('createI18n interpolation', () => {
  it('substitutes a named parameter', () => {
    expect(i18n().t('auth.welcome', { name: 'Jane' })).toBe('Welcome back, Jane')
  })

  it('substitutes every occurrence of a repeated parameter', () => {
    expect(i18n().t('auth.repeat', { name: 'Jane' })).toBe('Jane, is that you Jane?')
  })

  it('substitutes multiple distinct parameters and stringifies numbers', () => {
    expect(i18n().t('auth.attempts', { used: 0, total: 5 })).toBe('0 of 5 attempts used')
  })

  it('leaves the placeholder intact when the parameter is absent', () => {
    // Must not render the string "undefined" into UI copy.
    expect(i18n().t('auth.welcome', {})).toBe('Welcome back, {name}')
    expect(i18n().t('auth.welcome')).toBe('Welcome back, {name}')
    expect(
      i18n().t('auth.welcome', { name: undefined as unknown as string }),
    ).toBe('Welcome back, {name}')
  })

  it('does not re-scan a substituted value for further placeholders', () => {
    // A value carrying "{total}" must stay literal, or one attacker-controlled
    // field could pull another parameter's value into its own position.
    expect(i18n().t('auth.attempts', { used: '{total}', total: 'secret' })).toBe(
      '{total} of secret attempts used',
    )
  })

  it('returns an interpolated value verbatim, never as markup', () => {
    const payload = '<img src=x onerror=alert(1)>'
    expect(i18n().t('auth.welcome', { name: payload })).toBe(`Welcome back, ${payload}`)
  })

  it('renders an interpolated value as text, creating no elements', () => {
    const inst = i18n()
    const payload = '<img src=x onerror=alert(1)>'
    const wrapper = mount(
      defineComponent({
        setup: () => () => h('span', inst.t('auth.welcome', { name: payload })),
      }),
    )

    expect(wrapper.element.querySelector('img')).toBeNull()
    expect(wrapper.element.children).toHaveLength(0)
    expect(wrapper.text()).toBe(`Welcome back, ${payload}`)
  })
})

describe('createI18n fallback chain', () => {
  it('falls back per key, not per locale, for a partially translated locale', () => {
    const inst = i18n({ locale: 'de' })
    expect(inst.t('common.signIn')).toBe('Anmelden')
    expect(inst.t('auth.welcome', { name: 'Jane' })).toBe('Welcome back, Jane')
  })

  it('falls back for the initial locale when it has no messages at all', () => {
    const inst = i18n({ locale: 'fr' })
    expect(inst.t('common.signIn')).toBe('Sign In')
  })

  it('defaults the fallback locale to en', () => {
    const inst = createI18n({ locale: 'de', messages: { en, de } })
    expect(inst.t('auth.welcome', { name: 'Jane' })).toBe('Welcome back, Jane')
  })

  it('honours an explicit non-en fallback locale', () => {
    const inst = createI18n({
      locale: 'fr',
      fallbackLocale: 'de',
      messages: { en, de, fr: {} },
    })
    expect(inst.t('common.signIn')).toBe('Anmelden')
    // de has no auth.* and the chain is a single hop, so en is not consulted.
    expect(inst.t('auth.welcome', { name: 'Jane' })).toBe('auth.welcome')
  })

  it('returns the key when the fallback locale itself is missing', () => {
    const inst = createI18n({ locale: 'de', fallbackLocale: 'nope', messages: { de } })
    expect(inst.t('auth.welcome')).toBe('auth.welcome')
  })
})

describe('createI18n locale switching', () => {
  it('switches to a known locale', () => {
    const inst = i18n()
    inst.setLocale('de')
    expect(inst.locale.value).toBe('de')
    expect(inst.t('common.signIn')).toBe('Anmelden')
  })

  it('silently ignores an unknown locale, keeping the current one', () => {
    // DEFECT (minor): setLocale returns void and gives the caller no signal
    // that the switch was refused.
    const inst = i18n()
    inst.setLocale('xx')
    expect(inst.locale.value).toBe('en')
    expect(inst.t('common.signIn')).toBe('Sign In')
  })

  it('re-renders a component that calls t() when the locale changes', async () => {
    const inst = i18n()
    const wrapper = mount(
      defineComponent({
        setup: () => () => h('span', inst.t('common.signIn')),
      }),
    )

    expect(wrapper.text()).toBe('Sign In')
    inst.setLocale('de')
    await nextTick()
    expect(wrapper.text()).toBe('Anmelden')
  })

  it('exposes availableLocales from the messages supplied at construction', () => {
    expect(i18n().availableLocales).toEqual(['en', 'de'])
  })

  it('DEFECT: availableLocales goes stale when a locale is added lazily', () => {
    // 38 locales invite lazy loading. t() and setLocale read the messages map
    // live, but availableLocales was snapshotted at construction, so a
    // locale picker driven by it never shows the newly loaded locale.
    const messages: Record<string, LocaleMessages> = { en }
    const inst = createI18n({ locale: 'en', messages })

    messages.sk = { 'common.signIn': 'Prihlasit sa' }

    inst.setLocale('sk')
    expect(inst.t('common.signIn')).toBe('Prihlasit sa')
    expect(inst.availableLocales).toEqual(['en'])
  })
})

describe('createI18n formatting', () => {
  it('formats a date in the active locale', () => {
    const inst = createI18n({ locale: 'en', messages: { en, 'pt-BR': {} } })
    const date = new Date(Date.UTC(2026, 0, 2, 12))

    expect(inst.formatDate(date)).toBe('1/2/2026')
    inst.setLocale('pt-BR')
    expect(inst.formatDate(date)).toBe('02/01/2026')
  })

  it('passes Intl options through to the formatter', () => {
    const inst = i18n()
    expect(inst.formatDate(new Date(Date.UTC(2026, 0, 2, 12)), { year: 'numeric' })).toBe('2026')
  })

  it('formats a number in the active locale', () => {
    const inst = createI18n({ locale: 'en', messages: { en, 'de-DE': {} } })

    expect(inst.formatNumber(1234.5)).toBe('1,234.5')
    inst.setLocale('de-DE')
    expect(inst.formatNumber(1234.5)).toBe('1.234,5')
  })

  it('DEFECT: a message-bundle key that is not a BCP-47 tag makes formatting throw', () => {
    // The bundle key doubles as the Intl locale with no validation. A bundle
    // named "en_US" (or any non-tag) translates fine and then crashes every
    // date/number in the UI.
    const inst = createI18n({ locale: 'en_US', messages: { en, en_US: en } })

    expect(inst.t('common.signIn')).toBe('Sign In')
    expect(() => inst.formatDate(new Date(0))).toThrow(RangeError)
    expect(() => inst.formatNumber(1)).toThrow(RangeError)
  })

  it('DEFECT: the exposed locale ref is writable and bypasses setLocale validation', () => {
    // setLocale refuses unknown locales, but the same ref is public, so a
    // caller (or a v-model on a locale picker) can set anything.
    const inst = i18n()

    inst.locale.value = 'not a tag!'
    expect(inst.t('common.signIn')).toBe('Sign In') // falls back, still safe
    expect(() => inst.formatDate(new Date(0))).toThrow(RangeError)
  })
})
