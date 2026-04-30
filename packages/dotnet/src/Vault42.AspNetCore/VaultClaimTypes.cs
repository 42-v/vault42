namespace Vault42.AspNetCore;

/// <summary>
/// Claim type constants for Vault-specific JWT claims.
/// </summary>
public static class VaultClaimTypes
{
    public const string Roles = "roles";
    public const string Scopes = "scopes";
    public const string ClientId = "client_id";
    public const string Fingerprint = "fingerprint";
    public const string TokenType = "token_type";
    public const string Confirmation = "cnf";
}
