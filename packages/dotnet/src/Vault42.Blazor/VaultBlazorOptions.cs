namespace Vault42.Blazor;

/// <summary>
/// Where the refresh token is stored client-side.
/// </summary>
/// <remarks>
/// Only <see cref="HttpOnlyCookieOnly"/> can carry a session against a Vault server. The server
/// never puts a refresh token in a response body -- <c>RefreshResult.RefreshToken</c> and
/// <c>LoginResult.RefreshToken</c> are both <c>json:"-"</c> -- and <c>POST /auth/refresh</c> reads
/// the token only from the <c>__Host-refresh_token</c> cookie and decodes no body at all. The other
/// two modes therefore never receive a token to store, and an app configured with one of them gets
/// a session that ends at the next full page load. They remain for a deployment that fronts this
/// SDK with a different issuer.
/// </remarks>
public enum RefreshTokenStorage
{
    /// <summary>
    /// (Default -- the only mode a Vault server supports.) The Vault server issues the refresh
    /// token in an <c>HttpOnly + Secure + SameSite=Strict</c> cookie. The SDK never holds
    /// the refresh token in JS-reachable memory, so XSS in the Blazor app cannot
    /// exfiltrate it. Refresh requests rely on the browser auto-attaching the
    /// cookie. Only works when the Blazor app is same-origin or registered
    /// CORS-with-credentials origin of the Vault server.
    /// </summary>
    HttpOnlyCookieOnly = 0,

    /// <summary>
    /// Refresh token kept in process memory only. Survives navigation within the
    /// SPA but is lost on full page reload -- user must re-login. XSS-resistant
    /// (token is not in any <c>window.*</c> bag). Use when cookies are not
    /// available (cross-origin, no CORS credentials). A Vault server never issues a
    /// body-borne refresh token, so against one this mode holds nothing.
    /// </summary>
    InMemoryOnly = 1,

    /// <summary>
    /// Legacy behaviour -- refresh token persisted to <c>window.sessionStorage</c>.
    /// Survives reload, but is XSS-readable. Documented risk; opt-in only. A Vault
    /// server never issues a body-borne refresh token, so against one this mode
    /// stores nothing.
    /// </summary>
    SessionStorage = 2,
}

/// <summary>
/// Configuration options for the Vault Blazor authentication library.
/// </summary>
/// <remarks>
/// The five path defaults are routes <c>internal/server/server.go</c> registers, and
/// <c>EndpointPaths_AreRoutesTheVaultServerRegisters</c> pins them by reading that file. Until
/// 1.0.3 they named <c>/auth/authorize</c> and <c>/auth/token</c>, which the server has never
/// served: with <c>VAULT_SERVE_FRONTEND</c> the SPA catch-all answered the token POST with 200 and
/// an HTML page, so the exchange failed inside the JSON reader rather than at the status check and
/// login failed silently.
/// </remarks>
public class VaultBlazorOptions
{
    /// <summary>
    /// Gets or sets where to keep the refresh token. Default: <see cref="RefreshTokenStorage.HttpOnlyCookieOnly"/>.
    /// See the enum members for trade-offs. Changing away from the default
    /// increases XSS exfiltration risk and, against a Vault server, ends the session at the next
    /// full page load; document the choice in the consuming app.
    /// </summary>
    public RefreshTokenStorage RefreshStorage { get; set; } = RefreshTokenStorage.HttpOnlyCookieOnly;

    /// <summary>
    /// Gets or sets base URL of the Vault server (e.g., "https://vault.example.com").
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the upstream identity provider to sign in with, as registered on the Vault
    /// server (for example "google" or "github").
    /// </summary>
    /// <remarks>
    /// Sent as the <c>provider</c> query parameter, which is the only parameter
    /// <c>GET /auth/oauth2/authorize</c> reads. An unset or unregistered value is answered
    /// <c>400 unknown_provider</c> before any redirect is built, so this has to be set for
    /// <see cref="VaultAuthService.LoginAsync"/> to reach an IdP at all.
    /// </remarks>
    public string Provider { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets oAuth2 client ID registered with the Vault.
    /// </summary>
    /// <remarks>
    /// Not sent anywhere by this SDK. The Vault server drives the OAuth2 dance with the upstream
    /// IdP under its own registration, so the browser-facing flow has no client of its own:
    /// <c>GET /auth/oauth2/authorize</c> reads only <c>provider</c>, and
    /// <c>POST /auth/oauth2/exchange</c> reads only <c>code</c> and rejects any other field.
    /// Confidential clients authenticate at <c>POST /client/token</c> with HTTP Basic instead,
    /// which is a server-to-server route and not one a WASM app can hold a secret for.
    /// </remarks>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets uRI to redirect back to after authentication.
    /// </summary>
    /// <remarks>
    /// Not sent to the Vault server, and not honoured by it. The callback redirects to the
    /// server's own configured origin plus <c>/oauth/callback</c>, so the page hosting
    /// <see cref="VaultAuthCallback"/> has to be served at exactly that address. Setting this to
    /// anything else does not move where the browser lands.
    /// </remarks>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets uRI to redirect to after logout. Defaults to the application root.
    /// </summary>
    public string PostLogoutRedirectUri { get; set; } = "/";

    /// <summary>
    /// Gets or sets scopes to request. Defaults to ["read", "write"].
    /// </summary>
    /// <remarks>
    /// Not sent to the Vault server, and not negotiable. Every user-issuance path in the server
    /// hardcodes read and write; a scope only a client-credentials token can hold is not reachable
    /// through the browser flow at all.
    /// </remarks>
    public string[] Scopes { get; set; } = ["read", "write"];

    /// <summary>
    /// Gets or sets seconds before token expiry to trigger a proactive refresh.
    /// Default: 60 seconds.
    /// </summary>
    public int RefreshBeforeExpirySecs { get; set; } = 60;

    /// <summary>
    /// Gets or sets a value indicating whether whether to automatically refresh the access token before it expires.
    /// Default: true.
    /// </summary>
    public bool AutoRefresh { get; set; } = true;

    /// <summary>
    /// Gets or sets authorization endpoint path on the Vault server.
    /// Default: "/auth/oauth2/authorize".
    /// </summary>
    /// <remarks>
    /// The server redirects this straight on to the upstream IdP named by <see cref="Provider"/>.
    /// It reads no other query parameter: <c>client_id</c>, <c>redirect_uri</c>,
    /// <c>code_challenge</c>, <c>scope</c> and <c>state</c> are all ignored, because the server
    /// mints its own PKCE verifier and its own HMAC-signed state and binds the flow to the
    /// initiating browser with a <c>__Host-oauth_state</c> cookie. Client-side PKCE sent here
    /// would prove nothing to anybody, which is why this SDK no longer generates any.
    /// </remarks>
    public string AuthorizePath { get; set; } = "/auth/oauth2/authorize";

    /// <summary>
    /// Gets or sets the one-time-code exchange endpoint path on the Vault server.
    /// Default: "/auth/oauth2/exchange".
    /// </summary>
    /// <remarks>
    /// Not an OAuth2 token endpoint. It takes <c>{"code": "..."}</c> and nothing else -- the
    /// server decodes with unknown fields disallowed, so a <c>grant_type</c> or
    /// <c>code_verifier</c> alongside it is a 400 -- and answers
    /// <c>{access_token, token_type, expires_in}</c>. The code lives 60 seconds, is deleted on
    /// first use, and is stored under a key that includes the request fingerprint, so the exchange
    /// must come from the same address, User-Agent and Accept-Language as the callback or it is
    /// refused as <c>invalid_or_expired_code</c>.
    /// </remarks>
    public string ExchangePath { get; set; } = "/auth/oauth2/exchange";

    /// <summary>
    /// Gets or sets refresh endpoint path on the Vault server.
    /// Default: "/auth/refresh".
    /// </summary>
    /// <remarks>
    /// Reads the refresh token only from the <c>__Host-refresh_token</c> cookie and decodes no
    /// request body, so the SDK sends none. This is why
    /// <see cref="RefreshTokenStorage.HttpOnlyCookieOnly"/> is the only mode that keeps a session
    /// alive against a Vault server.
    /// </remarks>
    public string RefreshPath { get; set; } = "/auth/refresh";

    /// <summary>
    /// Gets or sets logout endpoint path on the Vault server.
    /// Default: "/auth/logout".
    /// </summary>
    public string LogoutPath { get; set; } = "/auth/logout";

    /// <summary>
    /// Gets or sets user profile endpoint path.
    /// Default: "/user/profile".
    /// </summary>
    public string ProfilePath { get; set; } = "/user/profile";

    internal string EffectiveAuthority => Authority.TrimEnd('/');
}
