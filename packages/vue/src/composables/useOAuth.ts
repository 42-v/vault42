import { useVaultClient } from '../plugin'
import type { LoginResult, OAuthProvider } from '../types'

/**
 * OAuth composable for social login flows.
 *
 * Security note: PKCE (Proof Key for Code Exchange) with S256 challenge method is
 * enforced server-side on all OAuth2 flows. The client does not need to generate or
 * manage PKCE parameters — the server handles code_verifier/code_challenge generation,
 * storage, and verification. This prevents authorization code interception attacks.
 */
export function useOAuth() {
  const client = useVaultClient()

  /** Redirect the browser to the OAuth provider's authorization page. */
  function authorize(provider: OAuthProvider): void {
    window.location.href = client.getOAuthAuthorizeURL(provider)
  }

  /**
   * Parse the URL fragment returned by the OAuth callback redirect.
   * Returns the parsed fields or null if the fragment is empty.
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

  /** Exchange a one-time OAuth code for access tokens. */
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
