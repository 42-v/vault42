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
    /// The value of the token's <c>client_id</c> claim, or <see langword="null"/> when it carries
    /// none.
    /// </returns>
    /// <remarks>
    /// <para><strong>Not an authenticated identity, and must not be used as one.</strong> On the
    /// password path the value is whatever the caller put in the <c>client_id</c> field of the
    /// <c>POST /auth/login</c> request body, copied unverified into the claim; the server says so
    /// itself at <c>internal/service/auth.go:695</c> -- "ClientID above is self-asserted body text
    /// and proves nothing". Anyone able to log in can present any client id they like, including
    /// one belonging to a registered confidential client. An authorization rule written against
    /// this, such as trusting a first-party client id more than a third-party one, is defeated by
    /// editing a JSON field.</para>
    /// <para>The value is proven only for a token from <c>POST /client/token</c>, where the client
    /// authenticated with HTTP Basic against a stored secret before anything was issued. Nothing in
    /// the claim distinguishes the two cases, so where the distinction matters, gate on a scope
    /// only the client-credentials path can grant instead.</para>
    /// </remarks>
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
