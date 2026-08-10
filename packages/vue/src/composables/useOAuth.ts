import { useVaultClient } from '../plugin'
import type { LoginResult, OAuthProvider } from '../types'

/**
 * OAuth composable for social login flows.
 *
 * Security note: PKCE (Proof Key for Code Exchange) with S256 challenge method is
 * enforced server-side on all OAuth2 flows. The client does not need to generate or
 * manage PKCE parameters — the server handles code_verifier/code_challenge generation,
 * storage, and verification. This prevents authorization code interception attacks.
 *
 * This composable holds no reactive state at all. It returns three plain
 * functions, so there is nothing to watch and nothing to clean up; the session
 * refs that a completed OAuth login should update live on {@link useAuth}.
 *
 * Calls `GET /auth/oauth2/authorize` (by navigation) and
 * `POST /auth/oauth2/exchange`.
 *
 * @returns
 * - `authorize(provider)`: sends the browser to the provider. This is a full
 *   page navigation, so it does not return in any meaningful sense and no code
 *   after it runs; persist anything you need across the round trip first.
 * - `parseCallback(hash)`: parses the URL fragment the callback lands on.
 * - `exchangeCode(code)`: trades the one-time code for tokens.
 *
 * A callback can come back requiring a second factor. When `parseCallback`
 * yields `requires_2fa` with a `challenge_token`, there is no session yet and
 * the flow must continue through {@link useAuth}'s `verify2FA*` functions.
 */
export function useOAuth() {
  const client = useVaultClient()

  /**
   * Redirect the browser to the OAuth provider's authorization page.
   *
   * @param provider - The social provider to authenticate against.
   */
  function authorize(provider: OAuthProvider): void {
    window.location.href = client.getOAuthAuthorizeURL(provider)
  }

  /**
   * Parse the URL fragment returned by the OAuth callback redirect.
   * Returns the parsed fields or null if the fragment is empty.
   *
   * The result travels in the fragment rather than the query string so it is
   * never sent to a server or written to server logs. Clear it from the address
   * bar once consumed.
   *
   * @param hash - The raw fragment including its leading `#`, i.e.
   * `window.location.hash`.
   * @returns The recognised fields, or null when the fragment is empty or
   * carries none of them. `error` is set when the provider or the server
   * rejected the flow; `requires_2fa` with `challenge_token` means the login is
   * half-complete and needs a second factor.
   */
  function parseCallback(hash: string): {
    code?: string
    requires_2fa?: boolean
    challenge_token?: string
    error?: string
  } | null {
    if (!hash || hash.length < 2) return null
    const params = new URLSearchParams(hash.substring(1))
    const result: Record<string, string | boolean> = {}
    if (params.has('code')) result.code = params.get('code')!
    if (params.has('requires_2fa')) result.requires_2fa = params.get('requires_2fa') === 'true'
    if (params.has('challenge_token')) result.challenge_token = params.get('challenge_token')!
    if (params.has('error')) result.error = params.get('error')!
    return Object.keys(result).length > 0 ? result : null
  }

  /**
   * Exchange a one-time OAuth code for access tokens.
   *
   * On success the returned access token is armed on the shared client, so
   * subsequent requests are authenticated. It does **not** update
   * {@link useAuth}'s session refs, so the app still renders as signed out
   * until `useAuth().init()` or a `refresh()` runs.
   *
   * @param code - The single-use code from `parseCallback`.
   * @returns The {@link LoginResult}. A result with `requires_2fa` set carries
   * no usable access token and the second factor is still outstanding.
   * @throws VaultAPIError if the code is expired, already redeemed or invalid.
   */
  async function exchangeCode(code: string): Promise<LoginResult> {
    const result = await client.exchangeOAuthCode(code)
    if (result.access_token) {
      client.accessToken = result.access_token
    }
    return result
  }

  return {
    authorize,
    parseCallback,
    exchangeCode,
  }
}
