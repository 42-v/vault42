import { createApp } from 'vue'
import { createVaultPlugin, createI18nPlugin } from '@vault42/vue'
import App from './App.vue'
import { router } from './router'
import { messages, availableLocales, detectLocale, loadLocale, applyDocumentLocale } from './i18n'
import { resolveVaultURL } from './config'
import './style.css'

const vaultURL = resolveVaultURL(import.meta.env, window.location.origin)

/**
 * Mounts the dashboard once its copy is in hand.
 *
 * Locale catalogues are fetched lazily (see `./i18n`), so `en` — the fallback
 * every other locale resolves through — and the detected locale have to land
 * before the first paint. Two small chunks in parallel, against the 844 KB of
 * translations the entry chunk used to carry.
 */
async function bootstrap(): Promise<void> {
  const initialLocale = detectLocale(availableLocales, 'en')
  applyDocumentLocale(initialLocale)

  await Promise.all([loadLocale('en'), loadLocale(initialLocale)])

  const app = createApp(App)

  app.use(router)
  app.use(
    createVaultPlugin({
      baseURL: vaultURL,
    }),
  )
  app.use(
    createI18nPlugin({
      locale: initialLocale,
      fallbackLocale: 'en',
      messages,
    }),
  )

  app.mount('#app')
}

void bootstrap()
