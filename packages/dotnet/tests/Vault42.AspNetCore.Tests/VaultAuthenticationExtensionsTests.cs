using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// AddVault is where a misconfiguration is supposed to become a startup failure
/// rather than a runtime one, and it was the only entry point in the package
/// with no test at all. Two of its checks are security decisions and not
/// ergonomics: an empty Authority means the JWKS URI is
/// "/.well-known/jwks.json" against no host, and an http:// Authority means the
/// signing keys arrive over a channel anyone on the path can rewrite.
/// </summary>
public class VaultAuthenticationExtensionsTests
{
    [Fact]
    public void EmptyAuthority_IsRefused()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            Build(o => o.Authority = string.Empty));

        Assert.Contains("Authority is required", ex.Message, StringComparison.Ordinal);
    }

    // The whole trust chain hangs off the JWKS fetch. Over plain HTTP an
    // on-path attacker substitutes their own key set and mints tokens the
    // application accepts, so this refuses by default rather than warning.
    [Fact]
    public void HttpAuthority_IsRefusedByDefault()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            Build(o => o.Authority = "http://vault.example.com"));

        Assert.Contains("must be HTTPS", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void HttpAuthority_IsAllowedOnlyWhenTheOperatorOptsOut()
    {
        var services = Build(o =>
        {
            o.Authority = "http://localhost:8080";
            o.RequireHttpsMetadata = false;
        });

        Assert.NotNull(services.GetRequiredService<VaultJwksManager>());
    }

    // Case is not a way around the check.
    [Theory]
    [InlineData("HTTPS://vault.example.com")]
    [InlineData("HttPs://vault.example.com")]
    public void HttpsCheck_IsCaseInsensitive(string authority)
    {
        var services = Build(o => o.Authority = authority);

        Assert.NotNull(services.GetRequiredService<VaultJwksManager>());
    }

    [Fact]
    public void AddVault_RegistersTheJwksManagerAsASingleton()
    {
        var services = Build(o => o.Authority = "https://vault.example.com");

        var first = services.GetRequiredService<VaultJwksManager>();
        var second = services.GetRequiredService<VaultJwksManager>();

        Assert.Same(first, second);
    }

    // The named client is what bounds every JWKS fetch. A client without the
    // configured timeout inherits HttpClient's 100-second default, so an
    // unresponsive Vault holds a request thread for that long on the unknown-kid
    // refresh path.
    [Fact]
    public void AddVault_ConfiguresTheNamedJwksClient()
    {
        var services = Build(o =>
        {
            o.Authority = "https://vault.example.com/";
            o.JwksHttpTimeout = TimeSpan.FromSeconds(3);
        });

        var client = services.GetRequiredService<IHttpClientFactory>()
            .CreateClient(VaultDefaults.HttpClientName);

        Assert.Equal(new Uri("https://vault.example.com"), client.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(3), client.Timeout);
        Assert.Contains("application/json", client.DefaultRequestHeaders.Accept.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void AddVault_RegistersTheDefaultSchemeName()
    {
        var services = Build(o => o.Authority = "https://vault.example.com");

        var schemes = services.GetRequiredService<IAuthenticationSchemeProvider>();
        var scheme = schemes.GetSchemeAsync(VaultDefaults.AuthenticationScheme).GetAwaiter().GetResult();

        Assert.NotNull(scheme);
        Assert.Equal(typeof(VaultAuthenticationHandler), scheme.HandlerType);
        Assert.Equal(VaultDefaults.DisplayName, scheme.DisplayName);
    }

    [Fact]
    public void AddVault_AcceptsACustomSchemeName()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication("SecondVault")
            .AddVault("SecondVault", o => o.Authority = "https://vault.example.com");
        var provider = services.BuildServiceProvider();

        var scheme = provider.GetRequiredService<IAuthenticationSchemeProvider>()
            .GetSchemeAsync("SecondVault").GetAwaiter().GetResult();

        Assert.NotNull(scheme);
    }

    // UseVaultAuthenticationAsync resolves the manager AddVault registers. Called
    // without it, the failure has to name the missing registration rather than
    // surfacing later as "Unknown signing key" on every request.
    [Fact]
    public async Task UseVaultAuthenticationAsync_WithoutAddVault_Throws()
    {
        var provider = new ServiceCollection().BuildServiceProvider();

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await provider.UseVaultAuthenticationAsync());
    }

    // The startup call itself: it must reach the JWKS endpoint and leave the
    // manager holding keys, because skipping it is the difference between an
    // application that authenticates and one that answers "Unknown signing key"
    // to everything until the first background refresh lands.
    [Fact]
    public async Task UseVaultAuthenticationAsync_FetchesTheInitialKeySet()
    {
        using var signer = new TestSigner();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication(VaultDefaults.AuthenticationScheme)
                .AddVault(o => o.Authority = TestSigner.Issuer);
        services.AddHttpClient(VaultDefaults.HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() =>
                    new StubHttpMessageHandler().Enqueue(System.Net.HttpStatusCode.OK, signer.JwksJson()));
        var provider = services.BuildServiceProvider();

        await provider.UseVaultAuthenticationAsync();

        Assert.Equal(new[] { "kid-1" }, provider.GetRequiredService<VaultJwksManager>().CachedKeyIds);
    }

    private static ServiceProvider Build(Action<VaultAuthenticationOptions> configure)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication(VaultDefaults.AuthenticationScheme).AddVault(configure);
        return services.BuildServiceProvider();
    }
}
