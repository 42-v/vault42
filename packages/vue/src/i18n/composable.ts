import { inject } from 'vue'
import { I18N_KEY } from './plugin'
import type { I18nInstance } from './types'

export function useT(): I18nInstance {
  const i18n = inject(I18N_KEY)
  if (!i18n) {
    throw new Error(
      '[@vault42/vue] I18n not provided. Did you call app.use(createI18nPlugin({ ... }))?',
    )
  }
  return i18n
}
