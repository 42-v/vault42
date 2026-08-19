import { inject, type App, type InjectionKey } from 'vue'
import { VaultClient } from './client'
import type { VaultClientOptions } from './types'

const VAULT_CLIENT_KEY: InjectionKey<VaultClient> = Symbol('VaultClient')

/** Options for {@link createVaultPlugin}. */
export interface VaultPluginOptions {
  /**
   * Origin of the Vault server, e.g. `https://vault.example.com`. Trailing
   * slashes are stripped. Every request is resolved against this, and an
   * absolute URL whose origin differs is refused rather than followed.
   */
  baseURL: string
  /** Extra client behaviour, such as the per-request header hook. */
  clientOptions?: VaultClientOptions
}

/**
 * Creates the Vue plugin that provides a single shared {@link VaultClient} to
 * the app.
 *
 * Install it before mounting. Every composable in this package resolves its
 * client by injection and throws without it.
 *
 * One client is constructed per plugin, so the access token and the in-flight
 * refresh deduplication are shared by the whole app. Installing the plugin on
 * two apps in one page gives them independent sessions.
 *
 * @param options - Server origin and optional client behaviour.
 * @returns A Vue plugin to pass to `app.use()`.
 *
 * @example
 * ```ts
 * app.use(createVaultPlugin({ baseURL: 'https://vault.example.com' }))
 * ```
 */
export function createVaultPlugin(options: VaultPluginOptions) {
  const client = new VaultClient(options.baseURL, options.clientOptions)

  return {
    install(app: App) {
      app.provide(VAULT_CLIENT_KEY, client)
    },
  }
}

/**
 * Resolves the shared {@link VaultClient} provided by {@link createVaultPlugin}.
 *
 * Use this only to reach client methods the composables do not wrap. Prefer the
 * composables for anything they cover, since they also maintain the reactive
 * session state that the raw client does not.
 *
 * Injection-based, so it must be called during `setup()`. Calling it from a
 * callback, a route guard or a module top level resolves nothing and throws.
 *
 * @returns The shared client instance.
 * @throws Error if `createVaultPlugin` was never installed, or if called
 * outside an active component instance.
 */
export function useVaultClient(): VaultClient {
  const client = inject(VAULT_CLIENT_KEY)
  if (!client) {
    throw new Error(
      '[@vault42/vue] VaultClient not provided. Did you call app.use(createVaultPlugin({ baseURL: "..." }))?',
    )
  }
  return client
}
