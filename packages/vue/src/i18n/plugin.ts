import type { App, InjectionKey } from 'vue'
import { createI18n } from './i18n'
import type { I18nOptions, I18nInstance, MessageResolver } from './types'

/**
 * Injection key for the shared {@link I18nInstance}.
 *
 * Exported so a component can `inject(I18N_KEY, null)` and degrade gracefully
 * when no plugin is installed, which is what the bundled forms do. Prefer
 * {@link useT} when the plugin is a hard requirement.
 */
export const I18N_KEY: InjectionKey<I18nInstance> = Symbol('VaultI18n')

/**
 * Creates the Vue plugin that provides an i18n instance to the app and
 * registers `$t` as a global template property.
 *
 * @param options - Initial locale, fallback locale and the message catalogues.
 * @returns A Vue plugin to pass to `app.use()`. Its `instance` property is the
 * underlying {@link I18nInstance}, so the locale can be switched from outside
 * a component without an injection context.
 *
 * `$t` is installed on `app.config.globalProperties`, which is app-wide: two
 * apps in one page each get their own. The declaration merging that types `$t`
 * in templates comes with this module, so importing anything from the package's
 * i18n entry point is enough to get it.
 *
 * @example
 * ```ts
 * const i18n = createI18nPlugin({ locale: 'en', messages: { en, sk } })
 * app.use(i18n)
 * i18n.instance.setLocale('sk')
 * ```
 */
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
