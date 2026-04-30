namespace Vault42.Blazor;

/// <summary>
/// Where the refresh token is stored client-side.
/// </summary>
public enum RefreshTokenStorage
{
    /// <summary>
    /// (Default — most secure.) The Vault server issues the refresh token in an
    /// <c>HttpOnly + Secure + SameSite=Strict</c> cookie. The SDK never holds
    /// the refresh token in JS-reachable memory, so XSS in the Blazor app cannot
    /// exfiltrate it. Refresh requests rely on the browser auto-attaching the
    /// cookie. Only works when the Blazor app is same-origin or registered
    /// CORS-with-credentials origin of the Vault server.
    /// </summary>
    HttpOnlyCookieOnly = 0,

    /// <summary>
    /// Refresh token kept in process memory only. Survives navigation within the
    /// SPA but is lost on full page reload — user must re-login. XSS-resistant
    /// (token is not in any <c>window.*</c> bag). Use when cookies are not
    /// available (cross-origin, no CORS credentials).
    /// </summary>
    InMemoryOnly = 1,

    /// <summary>
    /// Legacy behaviour — refresh token persisted to <c>window.sessionStorage</c>.
    /// Survives reload, but is XSS-readable. Documented risk; opt-in only.
    /// </summary>
    SessionStorage = 2,
}

/// <summary>
/// Configuration options for the Vault Blazor authentication library.
/// </summary>
public class VaultBlazorOptions
{
    /// <summary>
    /// Gets or sets where to keep the refresh token. Default: <see cref="RefreshTokenStorage.HttpOnlyCookieOnly"/>.
    /// See the enum members for trade-offs. Changing away from the default
    /// increases XSS exfiltration risk; document the choice in the consuming app.
    /// </summary>
    public RefreshTokenStorage RefreshStorage { get; set; } = RefreshTokenStorage.HttpOnlyCookieOnly;

    /// <summary>
    /// Gets or sets base URL of the Vault server (e.g., "https://vault.example.com").
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets oAuth2 client ID registered with the Vault.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets uRI to redirect back to after authentication.
    /// Must match exactly one of the client's registered redirect URIs.
    /// </summary>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets uRI to redirect to after logout. Defaults to the application root.
    /// </summary>
    public string PostLogoutRedirectUri { get; set; } = "/";

    /// <summary>
    /// Gets or sets scopes to request. Defaults to ["read", "write"].
    /// </summary>
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
    /// Default: "/auth/authorize".
    /// </summary>
    public string AuthorizePath { get; set; } = "/auth/authorize";

    /// <summary>
    /// Gets or sets token endpoint path on the Vault server.
    /// Default: "/auth/token".
    /// </summary>
    public string TokenPath { get; set; } = "/auth/token";

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
