import type { Ref } from 'vue'

/**
 * A single locale's catalogue. Values are either the message itself or one
 * level of nesting, so `{ 'login.title': '…' }` and `{ login: { title: '…' } }`
 * are both valid and both resolve for `t('login.title')`.
 */
export type LocaleMessages = Record<string, string | Record<string, string>>

/**
 * The translation function. Returns the message for `key` with `{placeholder}`
 * tokens replaced from `params`, or the key itself when no catalogue has it.
 */
export type MessageResolver = (key: string, params?: Record<string, string | number>) => string

/** Options for {@link createI18n} and {@link createI18nPlugin}. */
export interface I18nOptions {
  /** Initial locale. Must be a key of `messages` or every lookup falls back. */
  locale: string
  /** Locale consulted when a key is missing from the active one. Defaults to `en`. */
  fallbackLocale?: string
  /** Catalogues keyed by locale. Its keys become `availableLocales`. */
  messages: Record<string, LocaleMessages>
}

/** The translation and formatting surface returned by {@link createI18n}. */
export interface I18nInstance {
  /** The active locale. Reactive; assign through `setLocale` so unknown locales are rejected. */
  locale: Ref<string>
  /** Translate a key. Reads `locale` on every call, so templates re-render on a locale change. */
  t: MessageResolver
  /** Switch locale. A locale with no catalogue is ignored and the current one is kept. */
  setLocale: (locale: string) => void
  /** The locales that have a catalogue. Captured at construction and not updated afterwards. */
  availableLocales: string[]
  /** Format a date with `Intl.DateTimeFormat` in the active locale. */
  formatDate: (date: Date, options?: Intl.DateTimeFormatOptions) => string
  /** Format a number with `Intl.NumberFormat` in the active locale. */
  formatNumber: (num: number, options?: Intl.NumberFormatOptions) => string
}
