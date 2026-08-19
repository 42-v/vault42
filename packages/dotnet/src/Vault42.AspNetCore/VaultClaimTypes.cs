namespace Vault42.AspNetCore;

/// <summary>
/// Claim type constants for Vault-specific JWT claims.
/// </summary>
/// <remarks>
/// These are the raw claim names as they appear in the token payload, not the
/// <see cref="System.Security.Claims.ClaimTypes"/> URIs. <c>roles</c> and <c>scopes</c> arrive as JSON
/// arrays and are expanded into one claim each by <see cref="VaultAuthenticationHandler"/> when
/// <see cref="VaultAuthenticationOptions.MapRolesToClaims"/> and
/// <see cref="VaultAuthenticationOptions.MapScopesToClaims"/> are enabled; read those through
/// <see cref="VaultClaimsPrincipalExtensions"/> rather than by name.
/// </remarks>
public static class VaultClaimTypes
{
    /// <summary>
    /// The <c>roles</c> claim: a JSON array of role names granted to the subject.
    /// </summary>
    /// <remarks>
    /// Present on the token as a single claim holding an array. After mapping, each element is a
    /// separate <see cref="System.Security.Claims.ClaimTypes.Role"/> claim, so
    /// <c>User.IsInRole(...)</c> and <see cref="VaultClaimsPrincipalExtensions.GetRoles"/> work as
    /// expected. Looking up this constant directly yields the unparsed JSON text.
    /// </remarks>
    public const string Roles = "roles";

    /// <summary>
    /// The <c>scopes</c> claim: a JSON array of OAuth2 scopes the token carries.
    /// </summary>
    /// <remarks>
    /// Mapped to one <c>scope</c> claim per element. Use
    /// <see cref="VaultClaimsPrincipalExtensions.HasScope"/> rather than reading this constant,
    /// which yields the unparsed JSON text.
    /// </remarks>
    public const string Scopes = "scopes";

    /// <summary>
    /// The <c>client_id</c> claim: the OAuth2 client the token was issued to.
    /// </summary>
    /// <remarks>
    /// Absent on tokens issued through the first-party password login flow; only tokens minted for
    /// a registered OAuth2 client carry it.
    /// </remarks>
    public const string ClientId = "client_id";

    /// <summary>
    /// The <c>fingerprint</c> claim: a SHA-256 device fingerprint bound to the token at issuance.
    /// </summary>
    /// <remarks>
    /// Validated against the live request by <see cref="VaultFingerprintValidator"/> when
    /// <see cref="VaultAuthenticationOptions.ValidateFingerprint"/> is set. The claim is optional:
    /// a token without it is accepted even with validation enabled, because the check can only
    /// compare a fingerprint that exists.
    /// </remarks>
    public const string Fingerprint = "fingerprint";

    /// <summary>
    /// The <c>token_type</c> claim: the class of credential the token represents.
    /// </summary>
    /// <remarks>
    /// The Vault server issues <c>Bearer</c> for a fully authenticated access token and
    /// <c>2fa_challenge</c> for the short-lived token handed out after a correct password but
    /// before the second factor. <see cref="VaultAuthenticationHandler"/> requires exactly
    /// <c>Bearer</c>, so a challenge token authenticates nothing; a missing claim is rejected the
    /// same way rather than defaulted.
    /// </remarks>
    public const string TokenType = "token_type";

    /// <summary>
    /// The <c>cnf</c> confirmation claim: the DPoP proof-of-possession binding (RFC 9449 §6.1).
    /// </summary>
    /// <remarks>
    /// When present the value is an object whose <c>jkt</c> member is the base64url SHA-256
    /// thumbprint of the JWK the holder must prove possession of. The Vault server does not
    /// populate it on any current issuance path, so tokens are bearer credentials in practice and
    /// a lookup of this claim returns null. Treat a token as sender-constrained only after
    /// confirming <c>cnf.jkt</c> is actually present; this library does not verify DPoP proofs.
    /// </remarks>
    public const string Confirmation = "cnf";
}
