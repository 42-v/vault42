import { inject, type App, type InjectionKey } from 'vue'
import { VaultClient } from './client'
import type { VaultClientOptions } from './types'

const VAULT_CLIENT_KEY: InjectionKey<VaultClient> = Symbol('VaultClient')

export interface VaultPluginOptions {
  baseURL: string
  clientOptions?: VaultClientOptions
}

export function createVaultPlugin(options: VaultPluginOptions) {
  const client = new VaultClient(options.baseURL, options.clientOptions)

  return {
    install(app: App) {
      app.provide(VAULT_CLIENT_KEY, client)
    },
  }
}

export function useVaultClient(): VaultClient {
  const client = inject(VAULT_CLIENT_KEY)
  if (!client) {
    throw new Error(
      '[@vault42/vue] VaultClient not provided. Did you call app.use(createVaultPlugin({ baseURL: "..." }))?',
    )
  }
  return client
}
