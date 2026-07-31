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
 */
export function getAuthState() {
  const isAuthenticated = computed(() => !!accessToken.value)

  async function init(): Promise<void> {
    if (!_client) throw new Error('[@vault42/vue] Auth not initialized. Call useAuth() from a component first.')
    return runInit(_client)
  }

  return { isAuthenticated, initialized, init, user, isLoading, registrationEnabled }
}

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
