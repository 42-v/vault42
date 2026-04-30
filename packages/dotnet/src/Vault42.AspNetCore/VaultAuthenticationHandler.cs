using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Vault42.AspNetCore;

/// <summary>
/// ASP.NET Core authentication handler that validates Vault RS256 JWTs.
/// </summary>
public class VaultAuthenticationHandler : AuthenticationHandler<VaultAuthenticationOptions>
{
    private readonly VaultJwksManager _jwks;

    // Dangerous JWT headers that must be rejected to prevent key injection attacks
    private static readonly string[] DangerousHeaders = ["jku", "x5u", "x5c", "jwk"];

    public VaultAuthenticationHandler(
        IOptionsMonitor<VaultAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        VaultJwksManager jwks)
        : base(options, logger, encoder)
    {
        _jwks = jwks;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Extract Bearer token
        var authorization = Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        var token = authorization["Bearer ".Length..].Trim();
        if (string.IsNullOrEmpty(token))
            return AuthenticateResult.NoResult();

        // Enforce max token size
        if (token.Length > Options.MaxTokenSize)
            return AuthenticateResult.Fail("Token exceeds maximum size");

        // Pre-parse to inspect headers before full validation
        var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = Options.MaxTokenSize };
        if (!handler.CanReadToken(token))
            return AuthenticateResult.Fail("Invalid token format");

        JwtSecurityToken jwt;
        try
        {
            jwt = handler.ReadJwtToken(token);
        }
        catch
        {
            return AuthenticateResult.Fail("Invalid token format");
        }

        // Reject dangerous headers
        foreach (var h in DangerousHeaders)
        {
            if (jwt.Header.ContainsKey(h))
                return AuthenticateResult.Fail($"Rejected header: {h}");
        }

        // Validate kid presence
        if (string.IsNullOrEmpty(jwt.Header.Kid))
            return AuthenticateResult.Fail("Missing kid header");

        // Resolve signing key
        var signingKey = await _jwks.ResolveKeyAsync(jwt.Header.Kid, Context.RequestAborted);
        if (signingKey is null)
            return AuthenticateResult.Fail("Unknown signing key");

        // Full validation
        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = Options.EffectiveIssuer,
            ValidateAudience = true,
            ValidAudience = Options.EffectiveAudience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidAlgorithms = ["RS256"],
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "sub",
            RoleClaimType = ClaimTypes.Role,
        };

        ClaimsPrincipal principal;
        try
        {
            principal = handler.ValidateToken(token, validationParams, out _);
        }
        catch (SecurityTokenException ex)
        {
            // CS-3: Don't leak validator-specific reasons to the client. Log details server-side,
            // respond with a generic "invalid_token" so attackers can't distinguish "expired"
            // from "bad signature" from "wrong issuer".
            Logger.LogDebug(ex, "JWT validation failed");
            return AuthenticateResult.Fail("invalid_token");
        }

        // Reject 2FA challenge tokens — they are not full auth tokens
        var tokenTypeClaim = principal.FindFirst(VaultClaimTypes.TokenType);
        if (tokenTypeClaim is not null && tokenTypeClaim.Value != "Bearer")
            return AuthenticateResult.Fail("Invalid token type");

        // Fingerprint validation (optional)
        if (Options.ValidateFingerprint)
        {
            var fpClaim = principal.FindFirst(VaultClaimTypes.Fingerprint);
            if (fpClaim is not null && !string.IsNullOrEmpty(fpClaim.Value))
            {
                if (!VaultFingerprintValidator.Validate(Context, fpClaim.Value, Options.TlsFingerprintHeader))
                    return AuthenticateResult.Fail("Fingerprint mismatch");
            }
        }

        // Build enriched claims identity
        var identity = MapClaims(principal, jwt);
        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity),
            Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }

    /// <summary>
    /// Override the default 401 challenge with a browser-aware redirect.
    /// Interactive (Accept: text/html) clients get a 302 to <see cref="VaultAuthenticationOptions.LoginPath"/>
    /// so Blazor Server auth flows can render their own login UI. API clients
    /// still get a clean 401 + WWW-Authenticate header.
    /// </summary>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var accept = Request.Headers.Accept.ToString();
        var isHtml = accept.Contains("text/html", StringComparison.OrdinalIgnoreCase);

        // Framework-internal and auth-exempt paths never get redirected — we
        // don't want to loop the login page back to itself. Use boundary-aware
        // prefix match (CS-2) so /login does NOT match /login-other-route.
        var path = Request.Path.Value ?? "/";
        var isExempt = PathHasPrefix(path, Options.LoginPath)
                    || PathHasPrefix(path, "/_blazor")
                    || PathHasPrefix(path, "/_framework")
                    || PathHasPrefix(path, "/_content")
                    || PathHasPrefix(path, "/healthz");

        if (isHtml && !isExempt)
        {
            var returnUrl = Request.Path + Request.QueryString;
            var loginUrl = $"{Options.LoginPath}?returnUrl={Uri.EscapeDataString(returnUrl)}";
            Response.Redirect(loginUrl);
            return Task.CompletedTask;
        }

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = $"Bearer realm=\"{Options.EffectiveIssuer}\"";
        return Task.CompletedTask;
    }

    /// <summary>
    /// Boundary-aware case-insensitive prefix match. Returns true only when
    /// <paramref name="path"/> equals <paramref name="prefix"/> exactly or is
    /// followed by '/' or '?'. Prevents prefix-aliasing (e.g. /login matching /login-evil).
    /// </summary>
    private static bool PathHasPrefix(string path, string prefix)
    {
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;
        if (path.Length == prefix.Length)
            return true;
        var next = path[prefix.Length];
        return next == '/' || next == '?';
    }

    private ClaimsIdentity MapClaims(ClaimsPrincipal validated, JwtSecurityToken jwt)
    {
        var source = validated.Identity as ClaimsIdentity;
        var identity = new ClaimsIdentity(
            source?.Claims ?? [],
            Scheme.Name,
            source?.NameClaimType ?? "sub",
            ClaimTypes.Role);

        // Map roles array to individual Role claims
        if (Options.MapRolesToClaims)
        {
            var rolesClaim = jwt.Claims.FirstOrDefault(c => c.Type == VaultClaimTypes.Roles);
            if (rolesClaim is not null)
            {
                try
                {
                    var roles = JsonSerializer.Deserialize<string[]>(rolesClaim.Value);
                    if (roles is not null)
                    {
                        foreach (var role in roles)
                            identity.AddClaim(new Claim(ClaimTypes.Role, role));
                    }
                }
                catch
                { /* non-array roles claim, skip */
                }
            }
        }

        // Map scopes array to individual scope claims
        if (Options.MapScopesToClaims)
        {
            var scopesClaim = jwt.Claims.FirstOrDefault(c => c.Type == VaultClaimTypes.Scopes);
            if (scopesClaim is not null)
            {
                try
                {
                    var scopes = JsonSerializer.Deserialize<string[]>(scopesClaim.Value);
                    if (scopes is not null)
                    {
                        foreach (var scope in scopes)
                            identity.AddClaim(new Claim("scope", scope));
                    }
                }
                catch
                { /* non-array scopes claim, skip */
                }
            }
        }

        return identity;
    }
}
