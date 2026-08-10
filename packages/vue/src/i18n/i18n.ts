import { ref, computed } from 'vue'
import type { I18nOptions, I18nInstance, LocaleMessages } from './types'

function resolve(messages: LocaleMessages, key: string): string | undefined {
  const val = messages[key]
  if (typeof val === 'string') return val
  // Support nested dot-notation: "login.title" -> messages["login"]["title"]
  const parts = key.split('.')
  let cur: unknown = messages
  for (const part of parts) {
    if (cur == null || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[part]
  }
  return typeof cur === 'string' ? cur : undefined
}

function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template
  return template.replace(/\{(\w+)\}/g, (_, name: string) => {
    const val = params[name]
    return val != null ? String(val) : `{${name}}`
  })
}

/**
 * Creates a standalone i18n instance: message lookup with interpolation, plus
 * locale-aware date and number formatting.
 *
 * Use this directly when you want translation without the Vue plugin, for
 * example in a test or a non-component module. To make `t` available to
 * components and as `$t` in templates, use {@link createI18nPlugin}.
 *
 * @param options - Initial locale, fallback locale and the message catalogues.
 * @returns An {@link I18nInstance}.
 *
 * Keys resolve either flat or by dot path, so a catalogue may hold
 * `'login.title'` as a single key or nest `login: { title }`; both answer
 * `t('login.title')`. Placeholders are `{name}` and are replaced from `params`;
 * a placeholder with no matching param is left in the output verbatim rather
 * than blanked, which makes the gap visible instead of silent.
 *
 * A missing key falls back to the fallback locale and then returns **the key
 * itself**. Translation therefore never throws and never renders empty, and a
 * caller that needs to detect a miss compares the result against the key, which
 * is what the bundled components do to fall back to their English copy.
 *
 * `t` is reactive: it reads the locale ref on every call, so a template calling
 * it re-renders on `setLocale`. Calling it once and caching the string does not.
 *
 * `setLocale` ignores a locale that has no catalogue, leaving the current one
 * in place rather than switching to a locale that would render only keys.
 *
 * @example
 * ```ts
 * const i18n = createI18n({
 *   locale: 'en',
 *   messages: { en: { greeting: 'Hello, {name}' } },
 * })
 * i18n.t('greeting', { name: 'Ada' })
 * ```
 */
export function createI18n(options: I18nOptions): I18nInstance {
  const locale = ref(options.locale)
  const fallbackLocale = options.fallbackLocale ?? 'en'
  const messages = options.messages
  const availableLocales = Object.keys(messages)

  // Reactive trigger: computed ref that changes identity when locale changes.
  // Components that call t() in their templates read this during render,
  // ensuring Vue tracks the locale dependency and re-renders on change.
  const currentLocale = computed(() => locale.value)

  function t(key: string, params?: Record<string, string | number>): string {
    // Read the computed to establish reactive dependency in the calling context
    const loc = currentLocale.value
    const currentMessages = messages[loc]
    if (currentMessages) {
      const val = resolve(currentMessages, key)
      if (val != null) return interpolate(val, params)
    }
    if (loc !== fallbackLocale) {
      const fbMessages = messages[fallbackLocale]
      if (fbMessages) {
        const val = resolve(fbMessages, key)
        if (val != null) return interpolate(val, params)
      }
    }
    return key
  }

  function setLocale(newLocale: string): void {
    if (messages[newLocale]) {
      locale.value = newLocale
    }
  }

  function formatDate(date: Date, options?: Intl.DateTimeFormatOptions): string {
    return new Intl.DateTimeFormat(currentLocale.value, options).format(date)
  }

  function formatNumber(num: number, options?: Intl.NumberFormatOptions): string {
    return new Intl.NumberFormat(currentLocale.value, options).format(num)
  }

  return { locale, t, setLocale, availableLocales, formatDate, formatNumber }
}
