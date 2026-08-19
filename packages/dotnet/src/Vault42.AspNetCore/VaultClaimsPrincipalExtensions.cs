using System.Security.Claims;

namespace Vault42.AspNetCore;

/// <summary>
/// Convenience extension methods for accessing Vault claims from a ClaimsPrincipal.
/// </summary>
/// <remarks>
/// These read the principal built by <see cref="VaultAuthenticationHandler"/> after a token has
/// already been validated. They perform no validation of their own, so calling them on an
/// unauthenticated principal returns empty results rather than throwing.
/// </remarks>
public static class VaultClaimsPrincipalExtensions
{
    /// <summary>Get the user ID (sub claim).</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>
    /// The subject identifier, or <see langword="null"/> when the principal is unauthenticated or
    /// carries no <c>sub</c> claim. Prefers the <see cref="ClaimTypes.NameIdentifier"/> URI and
    /// falls back to the raw <c>sub</c> name.
    /// </returns>
    public static string? GetUserId(this ClaimsPrincipal principal) =>
        principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
        principal.FindFirst("sub")?.Value;

    /// <summary>Get all roles from the Vault roles claim.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>
    /// The role names, or an empty list when the token carried none. Reads the mapped
    /// <see cref="ClaimTypes.Role"/> claims, so this is empty when
    /// <see cref="VaultAuthenticationOptions.MapRolesToClaims"/> is disabled even if the token has
    /// a <c>roles</c> array.
    /// </returns>
    public static IReadOnlyList<string> GetRoles(this ClaimsPrincipal principal) =>
        principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();

    /// <summary>Get all scopes from the Vault scopes claim.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>
    /// The granted scopes, or an empty list when the token carried none. Reads the mapped
    /// <c>scope</c> claims, so this is empty when
    /// <see cref="VaultAuthenticationOptions.MapScopesToClaims"/> is disabled even if the token has
    /// a <c>scopes</c> array.
    /// </returns>
    public static IReadOnlyList<string> GetScopes(this ClaimsPrincipal principal) =>
        principal.FindAll("scope").Select(c => c.Value).ToArray();

    /// <summary>Get the client ID claim.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>
    /// The OAuth2 client the token was issued to, or <see langword="null"/>. Tokens from the
    /// first-party password login flow have no client and return null here.
    /// </returns>
    public static string? GetClientId(this ClaimsPrincipal principal) =>
        principal.FindFirst(VaultClaimTypes.ClientId)?.Value;

    /// <summary>Get the fingerprint claim.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>
    /// The device fingerprint bound at issuance, or <see langword="null"/> when the token carries
    /// none. A null result does not mean the request failed fingerprint validation: the check is
    /// skipped for tokens without the claim.
    /// </returns>
    public static string? GetFingerprint(this ClaimsPrincipal principal) =>
        principal.FindFirst(VaultClaimTypes.Fingerprint)?.Value;

    /// <summary>Get the JWT ID (jti claim).</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>The token's unique identifier, or <see langword="null"/> when absent.</returns>
    public static string? GetTokenId(this ClaimsPrincipal principal) =>
        principal.FindFirst("jti")?.Value;

    /// <summary>Check if the user has a specific scope.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <param name="scope">The exact scope name to look for.</param>
    /// <returns>
    /// <see langword="true"/> when the token granted <paramref name="scope"/>. The comparison is
    /// ordinal and exact: no prefix, wildcard or hierarchy rules apply, so <c>blobs</c> does not
    /// satisfy a check for <c>blobs:read</c>.
    /// </returns>
    public static bool HasScope(this ClaimsPrincipal principal, string scope) =>
        principal.FindAll("scope").Any(c => c.Value == scope);

    /// <summary>Check if the user has a specific role.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <param name="role">The exact role name to look for.</param>
    /// <returns>
    /// <see langword="true"/> when the principal holds <paramref name="role"/>. Roles are checked
    /// individually and are not nested here, so a check for a lower tier is not satisfied by a
    /// higher one.
    /// </returns>
    public static bool HasVaultRole(this ClaimsPrincipal principal, string role) =>
        principal.IsInRole(role);
}
