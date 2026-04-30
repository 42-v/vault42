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
