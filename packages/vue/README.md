# @vault42/vue

Vue 3 client library for [Vault42](https://github.com/42-v/vault42), a production-grade Go JWT authentication server.

It gives you a typed HTTP client, ten composables covering the whole authentication surface, four drop-in components, and a small i18n plugin. Everything is tree-shakeable ESM with generated type declarations, so composable docs and parameter names show up in your editor.

## Status

**Not published to the npm registry.** The manifest declares `publishConfig`, but no release has been pushed. Today the package is consumed from inside this repository's pnpm workspace by `web/`.

To use it in another project right now, vendor it or reference it by git. Once it is published, the install below is what you will run.

```bash
pnpm add @vault42/vue    # not yet available
```

Inside this repository:

```jsonc
// package.json
"dependencies": {
  "@vault42/vue": "workspace:*"
}
```

## Requirements

| | |
|---|---|
| Vue | `^3.5.0` (peer dependency) |
| Runtime | A browser with `fetch`, `BroadcastChannel` and `crypto`. WebAuthn additionally needs a secure context. |
| Server | A reachable Vault42 instance |

The package is browser-targeted. It has no SSR entry point: composables touch `window` and `navigator`, and `useWebAuthn().isSupported` is false wherever `window` is absent.

## Quick start

Install the plugin once, before mounting. Every composable resolves its client by injection and throws without it.

```ts
// main.ts
import { createApp } from 'vue'
import { createVaultPlugin } from '@vault42/vue'
import App from './App.vue'

createApp(App)
  .use(createVaultPlugin({ baseURL: 'https://vault42.example.com' }))
  .mount('#app')
```

Then sign in, and restore the session on reload:

```vue
<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAuth } from '@vault42/vue'

const { user, isAuthenticated, initialized, error, login, logout, init } = useAuth()

const email = ref('')
const password = ref('')

// Restores the session from the refresh cookie. Nothing else calls this.
onMounted(init)

async function submit() {
  try {
    await login(email.value, password.value)
  } catch {
    // login() also records the failure in `error`
  }
}
</script>

<template>
  <p v-if="!initialized">Restoring session...</p>

  <template v-else-if="isAuthenticated">
    <p>Signed in as {{ user?.email }}</p>
    <button @click="logout">Sign out</button>
  </template>

  <form v-else @submit.prevent="submit">
    <input v-model="email" type="email" autocomplete="email" required />
    <input v-model="password" type="password" autocomplete="current-password" required />
    <button type="submit">Sign in</button>
    <p v-if="error">{{ error.code }}</p>
  </form>
</template>
```

A login can come back needing a second factor. When it does, `login()` resolves normally with `requires2FA` set to true and `availableMethods` listing what the server accepts; complete it with `verify2FA`, `verify2FABackupCode`, `verify2FAEmailOTP` or `verify2FAWebAuthn`. `VaultLoginForm` handles that whole sequence for you.

Route guards run outside a component, so they cannot inject. Use `getAuthState()`, which reads the same state:

```ts
router.beforeEach(async (to) => {
  if (!to.meta.requiresAuth) return

  const { isAuthenticated, initialized, init } = getAuthState()
  if (!initialized.value) await init()

  return isAuthenticated.value
    ? true
    : { path: '/login', query: { redirect: to.fullPath } }
})
```

Waiting for `initialized` matters. Before `init()` settles, `isAuthenticated` is false for a signed-in user, so a guard that skips the wait bounces them to the login page on every reload.

## API surface

### Composables

| Composable | Covers |
|---|---|
| `useAuth` | Session state, login, registration, logout, refresh, all four second factors |
| `getAuthState` | The same session state, readable outside a component (route guards) |
| `useProfile` | The signed-in user's profile |
| `useSessions` | Active sessions and known devices, with revocation |
| `use2FA` | Second-factor enrolment: TOTP setup and removal, backup codes |
| `usePasswordReset` | Reset request, reset confirmation, password change |
| `useWebAuthn` | Security key enrolment, assertion and management |
| `useOAuth` | Social login: authorize, parse the callback, exchange the code |
| `useConfirm` | Password re-confirmation, the elevation gate before sensitive actions |
| `useIdentity` | The stored identity record and billing details |
| `useBlobs` | Encrypted binary storage, anonymous and named |

### Components

| Component | Purpose |
|---|---|
| `VaultLoginForm` | Full sign-in form including every second-factor step |
| `VaultRegisterForm` | Registration form with local password checks |
| `VaultAuthGuard` | Renders its default slot only to a signed-in user, with `loading` and `fallback` slots |
| `VaultTokenDebug` | Development-only token inspector. Renders only when `enabled` is set **and** the build is a dev build |

The components ship essentially unstyled. They emit stable `vault42-*` BEM class names for you to target from your own stylesheet; the small bundled stylesheet only carries layout for the login form's second-factor section and is not exposed as a subpath import.

### i18n

`createI18nPlugin`, `createI18n`, `useT`, `I18N_KEY`. Dot-path keys, `{placeholder}` interpolation, a fallback locale, and locale-aware `formatDate` / `formatNumber`. A missing key returns the key itself rather than throwing or rendering empty.

The bundled components inject i18n optionally, so they render with built-in English copy when no plugin is installed.

### Client and types

`VaultClient` is the transport, exposed through `useVaultClient()` for endpoints the composables do not wrap. `VaultAPIError` is what every failed call rejects with; branch on its `code`, never on its `message`. All request and response shapes are exported as types.

## Behaviour worth knowing

**Most state is per call, but not all of it.** `useAuth` and `useConfirm` keep their state at module level and share it across the whole app, so signing in or confirming a password in one component is visible everywhere. Every other composable creates fresh refs per call, so two components each calling `useProfile()` hold independent state and each must fetch its own.

**Errors surface two different ways.** Some functions record the failure in `error` and rethrow, so a form can `await` them and branch on the throw: `login`, `register`, every `verify2FA*`, `confirmReset`, `changePassword`, `verifyTOTP`, and the `useWebAuthn` actions. The rest never throw; they record the failure in `error` and return a boolean or null. Ignoring their return value silently loses the failure. Each composable's TSDoc says which it is.

**A 401 refreshes and retries once, automatically.** Concurrent calls share a single in-flight refresh instead of each starting one. If the refresh fails, the token is dropped and the call rejects with `session_expired`, so a dead session cannot spin.

**The access token lives in memory only.** It does not survive a reload; `init()` restores the session from the HttpOnly refresh cookie. Because that cookie is the credential, every request is sent with `credentials: 'include'`, so a cross-origin deployment needs CORS configured to allow credentials.

**Logout is cross-tab.** `useAuth` opens a `BroadcastChannel`, so signing out in one tab clears the others. The listener is closed on unmount, which means `useAuth()` must be called from `setup()` for that cleanup to run.

## Development

```bash
pnpm -C packages/vue build          # vue-tsc --noEmit && vite build
pnpm -C packages/vue test           # vitest run
pnpm -C packages/vue test:coverage  # enforces 100% statements / functions / lines
```

This repository pins **pnpm 10.18.0**. pnpm 11 fails on the lockfile with `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`.

## License

MIT. See the repository root `LICENSE`.

## Security

Report vulnerabilities to **vault@42-v.com** (Tuta, end-to-end encrypted). Do not open a public GitHub issue. Full policy: [`SECURITY.md`](https://github.com/42-v/vault42/blob/main/SECURITY.md).
