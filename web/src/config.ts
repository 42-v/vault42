/**
 * Resolves the Vault API origin this dashboard talks to.
 *
 * Same-origin is the only correct default: every shipped deployment serves the
 * SPA out of the Go binary (`internal/frontend`, `go:embed dist/*`), so the API
 * lives on the origin the page was loaded from. `VITE_VAULT_URL` exists for
 * `vite dev`, where the dashboard runs on :5173 and the API does not.
 *
 * The override used to win unconditionally. Vite loads a plain `.env` file in
 * every mode, production builds included, so a developer's local
 * `web/.env` was baked into `web/dist`, copied into `internal/frontend/dist` by
 * `scripts/build-all.sh`, and compiled into the Go binary and all three images:
 * a release that pointed every API call at `https://vault.localhost`. The dev
 * value now lives in `web/.env.development`, which Vite loads only for the dev
 * server, and a production bundle discards the override entirely unless
 * `VITE_VAULT_URL_ALLOW_PRODUCTION` says it was deliberate. `web/vite.config.ts`
 * then reads the emitted chunks back and fails the build if a dev origin
 * survived anyway.
 */
export interface VaultURLEnv {
  /** True in a production build. Vite defines it on `import.meta.env`. */
  readonly PROD?: boolean
  /** Explicit API origin. Honoured unconditionally in dev. */
  readonly VITE_VAULT_URL?: string
  /** Must be the string `'true'` for a production build to honour the override. */
  readonly VITE_VAULT_URL_ALLOW_PRODUCTION?: string
}

/**
 * Picks the API origin for the running bundle.
 *
 * @param env - `import.meta.env`, or an equivalent object in a test.
 * @param origin - The fallback, normally `window.location.origin`.
 * @returns The override when it is set and permitted, otherwise `origin`.
 */
export function resolveVaultURL(env: VaultURLEnv, origin: string): string {
  const override = env.VITE_VAULT_URL?.trim()
  if (!override) return origin

  if (env.PROD === true && env.VITE_VAULT_URL_ALLOW_PRODUCTION !== 'true') {
    // Loud rather than silent: a deployment that meant to point elsewhere needs
    // to know its override was dropped, and a leaked dev .env needs to be
    // visible in the console of whoever notices the dashboard is talking to the
    // wrong host.
    console.warn(
      '[vault42] VITE_VAULT_URL was ignored in this production build. ' +
        'Set VITE_VAULT_URL_ALLOW_PRODUCTION=true to opt in; otherwise the API ' +
        'origin is the origin this page was served from.',
    )
    return origin
  }

  return override
}
