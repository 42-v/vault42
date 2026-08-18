/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<object, object, unknown>
  export default component
}

interface ImportMetaEnv {
  /** API origin override. Dev-only unless VITE_VAULT_URL_ALLOW_PRODUCTION is set. */
  readonly VITE_VAULT_URL?: string
  /** Opts a production build into honouring VITE_VAULT_URL. Must be the string 'true'. */
  readonly VITE_VAULT_URL_ALLOW_PRODUCTION?: string
}
