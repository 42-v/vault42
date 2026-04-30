namespace Vault42.AspNetCore;

/// <summary>
/// Default values for the Vault authentication scheme.
/// </summary>
public static class VaultDefaults
{
    /// <summary>Authentication scheme name.</summary>
    public const string AuthenticationScheme = "Vault";

    /// <summary>Display name shown in authentication challenges.</summary>
    public const string DisplayName = "The Vault";

    /// <summary>Default HttpClient name for JWKS fetching.</summary>
    public const string HttpClientName = "VaultJwks";
}
