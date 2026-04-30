import type { App, InjectionKey } from 'vue'
import { createI18n } from './i18n'
import type { I18nOptions, I18nInstance, MessageResolver } from './types'

export const I18N_KEY: InjectionKey<I18nInstance> = Symbol('VaultI18n')

export function createI18nPlugin(options: I18nOptions) {
  const i18n = createI18n(options)

  return {
    instance: i18n,
    install(app: App) {
      app.provide(I18N_KEY, i18n)
      app.config.globalProperties.$t = i18n.t
    },
  }
}

// Augment Vue types for $t
declare module 'vue' {
  interface ComponentCustomProperties {
    $t: MessageResolver
  }
}
