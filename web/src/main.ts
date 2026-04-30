import { createApp } from 'vue'
import { createVaultPlugin, createI18nPlugin } from '@vault42/vue'
import App from './App.vue'
import { router } from './router'
import { messages, detectLocale } from './i18n'
import './style.css'

const vaultURL = import.meta.env.VITE_VAULT_URL || window.location.origin

const app = createApp(App)

app.use(router)
app.use(
  createVaultPlugin({
    baseURL: vaultURL,
  }),
)

const initialLocale = detectLocale(Object.keys(messages), 'en')

app.use(
  createI18nPlugin({
    locale: initialLocale,
    fallbackLocale: 'en',
    messages,
  }),
)

app.mount('#app')
