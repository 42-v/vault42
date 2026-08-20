using Vault42.Blazor;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// The defaults on <see cref="VaultBlazorOptions"/> are the four endpoint paths
/// the SDK concatenates onto Authority and the refresh behaviour it arms without
/// being asked. A path default that drifts from the Vault's routes produces a
/// 404 at the token endpoint and nothing else to go on, so the strings are
/// asserted rather than assumed.
/// </summary>
public class VaultBlazorOptionsTests
{
    [Fact]
    public void EndpointPaths_MatchTheVaultRoutes()
    {
        var options = new VaultBlazorOptions();

        Assert.Equal("/auth/authorize", options.AuthorizePath);
        Assert.Equal("/auth/token", options.TokenPath);
        Assert.Equal("/auth/logout", options.LogoutPath);
        Assert.Equal("/user/profile", options.ProfilePath);
        Assert.Equal("/", options.PostLogoutRedirectUri);
    }

    [Fact]
    public void RefreshDefaults_AreProactiveAndOn()
    {
        var options = new VaultBlazorOptions();

        Assert.True(options.AutoRefresh);
        Assert.Equal(60, options.RefreshBeforeExpirySecs);
        Assert.Equal(new[] { "read", "write" }, options.Scopes);
    }

    // Authority is concatenated with a path that already starts with '/', so a
    // trailing slash on the configured value would produce "//auth/token".
    [Theory]
    [InlineData("https://vault.example.com", "https://vault.example.com")]
    [InlineData("https://vault.example.com/", "https://vault.example.com")]
    [InlineData("https://vault.example.com///", "https://vault.example.com")]
    public void EffectiveAuthority_DropsTrailingSlashes(string configured, string expected)
    {
        var options = new VaultBlazorOptions { Authority = configured };

        Assert.Equal(expected, options.EffectiveAuthority);
    }

    // The default is the only mode where the refresh token never enters
    // JS-reachable memory. It is asserted in the hardening suite as well; the
    // duplicate is deliberate, because this is the value most likely to be
    // changed by someone working around a CORS problem.
    [Fact]
    public void RefreshStorage_DefaultsToTheCookieOnlyMode()
    {
        Assert.Equal(RefreshTokenStorage.HttpOnlyCookieOnly, new VaultBlazorOptions().RefreshStorage);
        Assert.Equal(0, (int)RefreshTokenStorage.HttpOnlyCookieOnly);
    }
}
