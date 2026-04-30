using Microsoft.AspNetCore.Authentication;

namespace Vault42.AspNetCore;

/// <summary>
/// Options for configuring Vault JWT authentication.
/// </summary>
public class VaultAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets the Vault base URL (e.g. "https://vault.example.com").
    /// Used as default issuer and audience. Required.
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets expected JWT issuer claim. Defaults to <see cref="Authority"/>.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets expected JWT audience claim. Defaults to <see cref="Authority"/>.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Gets or sets how often to refresh the JWKS key set. Default: 5 minutes.
    /// </summary>
    public TimeSpan JwksRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets a value indicating whether when true, an unknown kid triggers an immediate JWKS refresh (rate-limited).
    /// Default: true.
    /// </summary>
    public bool RefreshOnUnknownKid { get; set; } = true;

    /// <summary>
    /// Gets or sets minimum time between forced JWKS refreshes. Default: 30 seconds.
    /// </summary>
    public TimeSpan MinimumJwksRefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets a value indicating whether when true, validate the fingerprint claim against the current HTTP request.
    /// Only enable when the ASP.NET app sees the same client IP/headers as The Vault.
    /// Default: false.
    /// </summary>
    public bool ValidateFingerprint { get; set; }

    /// <summary>
    /// Gets or sets hTTP header containing the TLS fingerprint (JA4), matching VAULT_TLS_FINGERPRINT_HEADER.
    /// Only used when <see cref="ValidateFingerprint"/> is true.
    /// </summary>
    public string? TlsFingerprintHeader { get; set; }

    /// <summary>
    /// Gets or sets maximum JWT token size in bytes. Default: 8192 (matching The Vault).
    /// </summary>
    public int MaxTokenSize { get; set; } = 8192;

    /// <summary>
    /// Gets or sets maximum JWKS response body size in bytes. Default: 1 MiB.
    /// A hostile or misconfigured JWKS endpoint cannot exhaust memory beyond this.
    /// </summary>
    public long MaxJwksBytes { get; set; } = 1L * 1024 * 1024;

    /// <summary>
    /// Gets or sets hTTP timeout for JWKS fetches. Default: 10 seconds.
    /// </summary>
    public TimeSpan JwksHttpTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Gets or sets a value indicating whether require <see cref="Authority"/> to use HTTPS. Default: true.
    /// Set to false for local development only — JWKS over HTTP is trivially MITM-able.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether map Vault "roles" claim to ClaimTypes.Role claims. Default: true.
    /// </summary>
    public bool MapRolesToClaims { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether map Vault "scopes" claim to "scope" claims. Default: true.
    /// </summary>
    public bool MapScopesToClaims { get; set; } = true;

    /// <summary>
    /// Gets or sets path a browser is redirected to when an authentication challenge
    /// fires on an interactive (text/html) request. Non-interactive clients
    /// (API consumers) still receive a clean 401. Default: "/login".
    /// </summary>
    public string LoginPath { get; set; } = "/login";

    /// <summary>
    /// Gets the effective issuer, falling back to Authority.
    /// </summary>
    internal string EffectiveIssuer => Issuer ?? Authority;

    /// <summary>
    /// Gets the effective audience, falling back to Authority.
    /// </summary>
    internal string EffectiveAudience => Audience ?? Authority;
}
