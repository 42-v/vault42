using System.Security.Claims;

namespace Vault42.AspNetCore;

/// <summary>
/// Convenience extension methods for accessing Vault claims from a ClaimsPrincipal.
/// </summary>
public static class VaultClaimsPrincipalExtensions
{
    /// <summary>Get the user ID (sub claim).</summary>
    public static string? GetUserId(this ClaimsPrincipal principal) =>
        principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
        principal.FindFirst("sub")?.Value;

    /// <summary>Get all roles from the Vault roles claim.</summary>
    public static IReadOnlyList<string> GetRoles(this ClaimsPrincipal principal) =>
        principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();

    /// <summary>Get all scopes from the Vault scopes claim.</summary>
    public static IReadOnlyList<string> GetScopes(this ClaimsPrincipal principal) =>
        principal.FindAll("scope").Select(c => c.Value).ToArray();

    /// <summary>Get the client ID claim.</summary>
    public static string? GetClientId(this ClaimsPrincipal principal) =>
        principal.FindFirst(VaultClaimTypes.ClientId)?.Value;

    /// <summary>Get the fingerprint claim.</summary>
    public static string? GetFingerprint(this ClaimsPrincipal principal) =>
        principal.FindFirst(VaultClaimTypes.Fingerprint)?.Value;

    /// <summary>Get the JWT ID (jti claim).</summary>
    public static string? GetTokenId(this ClaimsPrincipal principal) =>
        principal.FindFirst("jti")?.Value;

    /// <summary>Check if the user has a specific scope.</summary>
    public static bool HasScope(this ClaimsPrincipal principal, string scope) =>
        principal.FindAll("scope").Any(c => c.Value == scope);

    /// <summary>Check if the user has a specific role.</summary>
    public static bool HasVaultRole(this ClaimsPrincipal principal, string role) =>
        principal.IsInRole(role);
}
