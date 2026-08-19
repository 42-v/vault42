import { ref, computed, onUnmounted, type Ref, type ComputedRef } from 'vue'
import { useVaultClient } from '../plugin'
import type { VaultClient } from '../client'
import type { UserProfile, VaultError, DecodedJWT, LoginResult } from '../types'

function decodeJWT(token: string): DecodedJWT | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')))
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
    return { header, payload }
  } catch {
    return null
  }
}

const user: Ref<UserProfile | null> = ref(null)
const accessToken: Ref<string | null> = ref(null)
const loadingCount: Ref<number> = ref(0)
const isLoading: ComputedRef<boolean> = computed(() => loadingCount.value > 0)
const error: Ref<VaultError | null> = ref(null)
const requires2FA: Ref<boolean> = ref(false)
const challengeToken: Ref<string | null> = ref(null)
const availableMethods: Ref<string[]> = ref([])
const initialized: Ref<boolean> = ref(false)
const registrationEnabled: Ref<boolean> = ref(true)
let initPromise: Promise<void> | null = null
let _client: VaultClient | null = null

/**
 * Loads the profile once a credential has been adopted. A failed profile call
 * is non-critical on its own, but the client drops its own token when the
 * session expires during the call (it answers session_expired). Following it
 * down keeps the refs from advertising a credential the client no longer has,
 * which would render the app as signed in while every request goes out
 * anonymous.
 */
async function loadProfile(client: VaultClient): Promise<void> {
  try {
    user.value = await client.getProfile()
  } catch (e: unknown) {
    if (client.accessToken) return
    accessToken.value = null
    user.value = null
    error.value = e as VaultError
  }
}

/**
 * Restores the session on a cold start. Resolves only once every piece of
 * state a route guard reads has settled.
 */
async function runInit(client: VaultClient): Promise<void> {
  if (initialized.value) return
  if (initPromise) return initPromise
  initPromise = (async () => {
    loadingCount.value++
    // Runs alongside the refresh, but init() must not resolve before it
    // settles: the /register guard reads registrationEnabled the moment
    // init() returns and would otherwise see the default.
    const capabilities = client.getCapabilities().then(caps => {
      registrationEnabled.value = caps.registration_enabled
    }).catch(() => { /* leave the default in place */ })
    try {
      const result = await client.refresh()
      accessToken.value = result.access_token
      client.accessToken = result.access_token
      await loadProfile(client)
    } catch {
      // No valid refresh token — user is not logged in, this is expected
      accessToken.value = null
      client.accessToken = null
      user.value = null
    } finally {
      await capabilities
      initialized.value = true
      loadingCount.value--
    }
  })()
  return initPromise
}

/**
 * Returns the auth reactive state without requiring inject() context.
 * Safe to call from router guards and other non-component contexts.
 * Requires that useAuth() has been called at least once from a component
 * (which sets the module-level client reference).
 *
 * The refs are the same module-level ones {@link useAuth} exposes, so state
 * observed here and in components is always identical.
 *
 * @returns A subset of the auth state safe to read outside a component:
 * `isAuthenticated`, `initialized`, `user`, `isLoading`, `registrationEnabled`,
 * and an `init` that restores the session.
 *
 * Guards should await `init()` and then read `isAuthenticated`. Reading it
 * before `initialized` is true reports a signed-in user as anonymous, because
 * the refresh that restores the session has not resolved yet.
 *
 * Unlike {@link useAuth} this does not throw when the plugin is missing; the
 * returned `init` throws instead, and only when actually called.
 */
export function getAuthState() {
  const isAuthenticated = computed(() => !!accessToken.value)

  async function init(): Promise<void> {
    if (!_client) throw new Error('[@vault42/vue] Auth not initialized. Call useAuth() from a component first.')
    return runInit(_client)
  }

  return { isAuthenticated, initialized, init, user, isLoading, registrationEnabled }
}

/**
 * Session state and the full sign-in surface: password login, registration, the
 * five second-factor completions, logout and token refresh.
 *
 * All session state is module-level and shared. Every `useAuth()` call in the
 * app reads and writes the same refs, so a login in one component is visible
 * everywhere immediately, and unmounting a component does not reset anything.
 * That is deliberate: a per-call state would let two components disagree about
 * whether the user is signed in. The consequence is that the composable is a
 * singleton per module instance, not per component, and it is never garbage
 * collected. The only per-call state is the cross-tab `BroadcastChannel`, which
 * is opened here and closed on unmount, so this must be called from `setup()`
 * for that listener to be cleaned up.
 *
 * Errors are reported two ways and the split matters. `login`, `register` and
 * every `verify2FA*` set `error` **and** rethrow, so a form can await them and
 * branch on the throw. `refresh` and `logout` never throw: `refresh` records the
 * failure in `error` and clears the session, `logout` discards its error because
 * local sign-out has already happened.
 *
 * Calls `POST /auth/login`, `/auth/register`, `/auth/logout`, `/auth/refresh`,
 * the `/auth/2fa/…` verification routes, `GET /auth/capabilities` and
 * `GET /user/profile`.
 *
 * @returns Reactive session state and the actions that change it.
 * - `user`: the signed-in profile, or null. Loaded after login and on `init()`.
 * - `isAuthenticated`: computed, true while an access token is held.
 * - `isLoading`: computed, true while any in-flight call is outstanding. It is
 *   a counter underneath, so concurrent calls do not clear it early.
 * - `error`: the last `VaultError`, or null. Not cleared on success of an
 *   unrelated call.
 * - `accessToken`: the raw bearer, or null.
 * - `requires2FA`: true when the password step succeeded but a second factor is
 *   outstanding. No credential is held in this state.
 * - `challengeToken`: the short-lived token that authorises the second-factor
 *   call only.
 * - `availableMethods`: the factors the server will accept, e.g. `totp`,
 *   `webauthn`, `backup_code`, `email_otp`.
 * - `initialized`: true once `init()` has settled. Route guards must wait for
 *   this, not for `isAuthenticated`, which is false during startup.
 * - `registrationEnabled`: whether the server accepts new registrations.
 * - `decodedToken`, `tokenExpiresIn`, `isTokenExpired`: computed views of the
 *   token payload. `tokenExpiresIn` is evaluated on read and does not tick on
 *   its own; a live countdown needs its own timer.
 * - `login`, `register`, `logout`, `refresh`, `init`: session actions.
 * - `verify2FA`, `verify2FABackupCode`, `verify2FAEmailOTP`,
 *   `verify2FAWebAuthn`, `cancel2FA`: second-factor completion.
 *
 * @throws Error if called outside a component that can `inject()` the client,
 * i.e. when `createVaultPlugin` was never installed.
 */
export function useAuth() {
  const client = useVaultClient()
  _client = client

  // Cross-tab logout sync via BroadcastChannel
  let authChannel: BroadcastChannel | null = null
  try {
    authChannel = new BroadcastChannel('vault42-auth')
    authChannel.onmessage = (event: MessageEvent) => {
      if (event.data?.type === 'logout') {
        accessToken.value = null
        client.accessToken = null
        user.value = null
        initialized.value = false
        initPromise = null
      }
    }
  } catch {
    // BroadcastChannel not available in this environment
  }

  // Clean up BroadcastChannel on component unmount
  try {
    onUnmounted(() => {
      if (authChannel) {
        authChannel.close()
        authChannel = null
      }
    })
  } catch {
    // onUnmounted may fail if called outside setup context
  }

  const isAuthenticated: ComputedRef<boolean> = computed(() => !!accessToken.value)

  const decodedToken: ComputedRef<DecodedJWT | null> = computed(() => {
    if (!accessToken.value) return null
    return decodeJWT(accessToken.value)
  })

  const tokenExpiresIn: ComputedRef<number> = computed(() => {
    if (!decodedToken.value?.payload.exp) return 0
    const exp = decodedToken.value.payload.exp as number
    return Math.max(0, exp - Math.floor(Date.now() / 1000))
  })

  const isTokenExpired: ComputedRef<boolean> = computed(() => tokenExpiresIn.value <= 0)

  async function login(email: string, password: string, rememberMe?: boolean): Promise<void> {
    loadingCount.value++
    error.value = null
    requires2FA.value = false
    challengeToken.value = null
    availableMethods.value = []

    try {
      const result = await client.login(email, password, rememberMe)
      if (result.requires_2fa) {
        // The password step is not a credential. VaultClient.login() stores any
        // access_token the response carries, so a server answering with both
        // requires_2fa and a token would leave that token armed as the bearer
        // and the second factor skippable. Disarm it here.
        accessToken.value = null
        client.accessToken = null
        user.value = null
        requires2FA.value = true
        challengeToken.value = result.challenge_token || null
        availableMethods.value = result.available_methods || []
        return
      }
      accessToken.value = result.access_token
      client.accessToken = result.access_token
      // Fetch profile after login
      await loadProfile(client)
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      loadingCount.value--
    }
  }

  async function register(email: string, password: string, displayName?: string): Promise<void> {
    loadingCount.value++
    error.value = null
    try {
      await client.register(email, password, displayName)
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      loadingCount.value--
    }
  }

  async function logout(): Promise<void> {
    loadingCount.value++
    error.value = null
    try {
      await client.logout()
    } catch {
      // Logout errors are non-critical
    } finally {
      accessToken.value = null
      client.accessToken = null
      user.value = null
      requires2FA.value = false
      challengeToken.value = null
      availableMethods.value = []
      initialized.value = false
      initPromise = null
      loadingCount.value--
      // Notify other tabs
      try { authChannel?.postMessage({ type: 'logout' }) } catch { /* ignore */ }
    }
  }

  async function refresh(): Promise<void> {
    try {
      const result = await client.refresh()
      accessToken.value = result.access_token
      client.accessToken = result.access_token
    } catch (e: unknown) {
      accessToken.value = null
      client.accessToken = null
      user.value = null
      error.value = e as VaultError
    }
  }

  async function complete2FAVerification(apiCall: () => Promise<LoginResult>): Promise<void> {
    loadingCount.value++
    error.value = null
    try {
      // Use challenge token as temporary bearer for the 2FA verify call
      if (challengeToken.value) {
        client.accessToken = challengeToken.value
      }
      // Server returns tokens after successful 2FA verification + sets refresh cookie
      const result = await apiCall()
      if (!result.access_token) {
        // A 200 with no token is not a completed verification. Drop the
        // challenge bearer and keep the gate up rather than dismissing the
        // 2FA screen with nobody signed in. challengeToken survives, so a
        // retry re-arms it.
        client.accessToken = accessToken.value
        throw { code: 'mfa_incomplete', status: 0 } as VaultError
      }
      accessToken.value = result.access_token
      client.accessToken = result.access_token
      requires2FA.value = false
      challengeToken.value = null
      availableMethods.value = []
      await loadProfile(client)
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      loadingCount.value--
    }
  }

  async function verify2FA(code: string): Promise<void> {
    return complete2FAVerification(() => client.verifyTOTP(code))
  }

  async function verify2FABackupCode(code: string): Promise<void> {
    return complete2FAVerification(() => client.verifyBackupCode(code))
  }

  async function verify2FAEmailOTP(code: string): Promise<void> {
    return complete2FAVerification(() => client.verifyEmailOTP(code))
  }

  async function verify2FAWebAuthn(): Promise<void> {
    loadingCount.value++
    error.value = null
    try {
      // WebAuthn verify was handled by useWebAuthn().verify() which set the real token on the client
      const token = client.accessToken
      if (!token || token === challengeToken.value) {
        // useWebAuthn() left the challenge token in place, or nothing at all,
        // so no second factor was actually proven. Keep the gate up.
        client.accessToken = accessToken.value
        throw { code: 'mfa_incomplete', status: 0 } as VaultError
      }
      accessToken.value = token
      requires2FA.value = false
      challengeToken.value = null
      availableMethods.value = []
      await loadProfile(client)
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      loadingCount.value--
    }
  }

  /**
   * Explicit exit from a half-finished 2FA login. A failed verify keeps the
   * challenge token on the client so the user can retry, so abandoning the
   * screen has to drop it or it stays armed as the bearer for the rest of the
   * page's life.
   */
  function cancel2FA(): void {
    requires2FA.value = false
    challengeToken.value = null
    availableMethods.value = []
    error.value = null
    // Restores whatever real credential the composable holds, which is null
    // for the ordinary "logging in" case.
    client.accessToken = accessToken.value
  }

  async function init(): Promise<void> {
    return runInit(client)
  }

  return {
    user,
    isAuthenticated,
    isLoading,
    error,
    accessToken,
    requires2FA,
    challengeToken,
    availableMethods,
    initialized,
    registrationEnabled,
    login,
    register,
    logout,
    refresh,
    verify2FA,
    verify2FABackupCode,
    verify2FAEmailOTP,
    verify2FAWebAuthn,
    cancel2FA,
    init,
    decodedToken,
    tokenExpiresIn,
    isTokenExpired,
  }
}
