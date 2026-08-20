using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// Every default on <see cref="VaultAuthenticationOptions"/> is a documented
/// figure, and three of them are limits the Vault server enforces on its own
/// side: 8 KiB of JWT, 1 MiB of JWKS, and HTTPS for the metadata fetch. A
/// default that drifts away from the server's is a silent divergence between
/// what the issuer will emit and what this handler will accept, so the numbers
/// are asserted rather than assumed.
/// </summary>
public class VaultAuthenticationOptionsTests
{
    [Fact]
    public void Defaults_MatchTheDocumentedFigures()
    {
        var options = new VaultAuthenticationOptions();

        Assert.Equal(8192, options.MaxTokenSize);
        Assert.Equal(1L * 1024 * 1024, options.MaxJwksBytes);
        Assert.Equal(TimeSpan.FromMinutes(5), options.JwksRefreshInterval);
        Assert.Equal(TimeSpan.FromSeconds(30), options.MinimumJwksRefreshInterval);
        Assert.Equal(TimeSpan.FromSeconds(10), options.JwksHttpTimeout);
        Assert.Equal("/login", options.LoginPath);
    }

    // The three defaults that decide how much an attacker gets for free. HTTPS on
    // by default is the one that matters most: it is the difference between
    // trusting the issuer's key set and trusting whoever is on the path.
    [Fact]
    public void SecurityRelevantDefaults_AreTheSafeSide()
    {
        var options = new VaultAuthenticationOptions();

        Assert.True(options.RequireHttpsMetadata);
        Assert.True(options.RefreshOnUnknownKid);

        // Fingerprint validation compares a claim minted from the Vault's view of
        // the client against this application's view. Behind a proxy the two
        // differ and every request fails, so it is opt-in and stays that way.
        Assert.False(options.ValidateFingerprint);
        Assert.Null(options.TlsFingerprintHeader);
    }

    [Fact]
    public void ClaimMapping_IsOnByDefault()
    {
        var options = new VaultAuthenticationOptions();

        Assert.True(options.MapRolesToClaims);
        Assert.True(options.MapScopesToClaims);
    }

    // Issuer and audience default to Authority, which is what makes a
    // single-setting configuration correct rather than merely short.
    [Fact]
    public void EffectiveIssuerAndAudience_FallBackToAuthority()
    {
        var options = new VaultAuthenticationOptions { Authority = "https://vault.example.com" };

        Assert.Equal("https://vault.example.com", options.EffectiveIssuer);
        Assert.Equal("https://vault.example.com", options.EffectiveAudience);
    }

    [Fact]
    public void EffectiveIssuerAndAudience_PreferTheExplicitValues()
    {
        var options = new VaultAuthenticationOptions
        {
            Authority = "https://vault.example.com",
            Issuer = "https://issuer.example.com",
            Audience = "api://orders",
        };

        Assert.Equal("https://issuer.example.com", options.EffectiveIssuer);
        Assert.Equal("api://orders", options.EffectiveAudience);
    }

    // An empty string is a configured value, not an absent one. Collapsing it to
    // Authority would turn a blank AUDIENCE setting into a silent default instead
    // of the validation failure it should be.
    [Fact]
    public void EffectiveIssuerAndAudience_TreatEmptyStringAsConfigured()
    {
        var options = new VaultAuthenticationOptions
        {
            Authority = "https://vault.example.com",
            Issuer = string.Empty,
            Audience = string.Empty,
        };

        Assert.Equal(string.Empty, options.EffectiveIssuer);
        Assert.Equal(string.Empty, options.EffectiveAudience);
    }
}
