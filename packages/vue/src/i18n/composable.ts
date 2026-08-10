import { inject } from 'vue'
import { I18N_KEY } from './plugin'
import type { I18nInstance } from './types'

/**
 * Resolves the i18n instance provided by {@link createI18nPlugin}.
 *
 * Injection-based, so it must be called during `setup()`.
 *
 * @returns The shared {@link I18nInstance}: `t`, `locale`, `setLocale`,
 * `availableLocales`, `formatDate` and `formatNumber`.
 * @throws Error if `createI18nPlugin` was never installed. The bundled
 * components avoid this by injecting the key with a null default and falling
 * back to their built-in English copy, so they render without the plugin;
 * application code calling this does not get that leniency.
 */
export function useT(): I18nInstance {
  const i18n = inject(I18N_KEY)
  if (!i18n) {
    throw new Error(
      '[@vault42/vue] I18n not provided. Did you call app.use(createI18nPlugin({ ... }))?',
    )
  }
  return i18n
}
