import type { Ref } from 'vue'

export type LocaleMessages = Record<string, string | Record<string, string>>
export type MessageResolver = (key: string, params?: Record<string, string | number>) => string

export interface I18nOptions {
  locale: string
  fallbackLocale?: string
  messages: Record<string, LocaleMessages>
}

export interface I18nInstance {
  locale: Ref<string>
  t: MessageResolver
  setLocale: (locale: string) => void
  availableLocales: string[]
  formatDate: (date: Date, options?: Intl.DateTimeFormatOptions) => string
  formatNumber: (num: number, options?: Intl.NumberFormatOptions) => string
}
