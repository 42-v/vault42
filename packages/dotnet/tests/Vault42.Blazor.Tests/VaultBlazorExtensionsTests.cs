using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// AddVaultAuth is the one line a consuming application writes, and it was
/// untested. Two things about it are load-bearing beyond "it registers some
/// services": the refresh-storage choice has to reach the TokenStore the rest of
/// the graph resolves, and the token-exchange HttpClient must not carry the
/// authorization handler. The second is a circularity -- refreshing would depend
/// on holding a valid token -- and it is the kind of thing a later refactor
/// "tidies up" by attaching the handler everywhere.
/// </summary>
public class VaultBlazorExtensionsTests
{
    [Theory]
    [InlineData("", "client", "https://app.example.com/cb", "Authority")]
    [InlineData("https://vault.example.com", "", "https://app.example.com/cb", "ClientId")]
    [InlineData("https://vault.example.com", "client", "", "RedirectUri")]
    public void MissingRequiredOptions_AreRefused(string authority, string clientId, string redirectUri, string expected)
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(() => services.AddVaultAuth(o =>
        {
            o.Authority = authority;
            o.ClientId = clientId;
            o.RedirectUri = redirectUri;
        }));

        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RegistersTheServiceGraphAsSingletons()
    {
        await using var provider = Build();

        Assert.Same(provider.GetRequiredService<VaultAuthService>(), provider.GetRequiredService<VaultAuthService>());
        Assert.Same(provider.GetRequiredService<TokenStore>(), provider.GetRequiredService<TokenStore>());
        Assert.Same(
            provider.GetRequiredService<VaultAuthenticationStateProvider>(),
            provider.GetRequiredService<AuthenticationStateProvider>());
    }

    // The message handler is transient because HttpClientFactory owns its
    // lifetime; a singleton here would be shared across every named client.
    [Fact]
    public async Task RegistersTheAuthorizationHandlerAsTransient()
    {
        await using var provider = Build();

        Assert.NotSame(
            provider.GetRequiredService<VaultAuthorizationMessageHandler>(),
            provider.GetRequiredService<VaultAuthorizationMessageHandler>());
    }

    // The option is only meaningful if it reaches the store the graph resolves.
    [Fact]
    public async Task TheRefreshStorageChoiceReachesTheTokenStore()
    {
        await using var provider = Build(o => o.RefreshStorage = RefreshTokenStorage.InMemoryOnly);

        Assert.Equal(RefreshTokenStorage.InMemoryOnly, provider.GetRequiredService<TokenStore>().RefreshMode);
    }

    // Refresh happens on this client. Attaching the authorization handler to it
    // would make obtaining a token require already having one.
    [Fact]
    public async Task TheTokenExchangeClientCarriesNoAuthorizationHandler()
    {
        await using var provider = Build();

        var client = provider.GetRequiredService<HttpClient>();

        Assert.Null(client.DefaultRequestHeaders.Authorization);
        Assert.Contains("application/json", client.DefaultRequestHeaders.Accept.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AddsTheAuthorizationCoreServices()
    {
        await using var provider = Build();

        Assert.NotNull(provider.GetService<IAuthorizationPolicyProvider>());
    }

    [Fact]
    public async Task AddVaultAuthorization_AttachesTheHandlerToANamedClient()
    {
        var services = NewServices();
        services.AddVaultAuth(Configure);
        services.AddHttpClient("VaultAPI", c => c.BaseAddress = new Uri("https://api.example.com"))
                .AddVaultAuthorization();
        await using var provider = services.BuildServiceProvider();

        // Resolving the named client builds the whole handler chain; a missing
        // registration surfaces here rather than on the first request.
        var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("VaultAPI");

        Assert.Equal(new Uri("https://api.example.com"), client.BaseAddress);
    }

    // VaultAuthService is IAsyncDisposable and not IDisposable, so the container
    // holding it must be torn down with DisposeAsync. A synchronous Dispose
    // throws rather than leaking, which is the safe direction, but it means an
    // application that disposes its provider synchronously fails at shutdown
    // rather than at startup. Pinned here so the shape of the contract is stated
    // somewhere rather than discovered.
    [Fact]
    public async Task TheContainerMustBeDisposedAsynchronously()
    {
        var provider = Build();

        // The container only has something to dispose once the singleton has
        // actually been resolved.
        _ = provider.GetRequiredService<VaultAuthService>();

        Assert.Throws<InvalidOperationException>(provider.Dispose);

        await provider.DisposeAsync();
    }

    private static ServiceProvider Build(Action<VaultBlazorOptions>? extra = null)
    {
        var services = NewServices();
        services.AddVaultAuth(o =>
        {
            Configure(o);
            extra?.Invoke(o);
        });
        return services.BuildServiceProvider();
    }

    private static ServiceCollection NewServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IJSRuntime>(new FakeJsRuntime());
        services.AddSingleton<NavigationManager>(new RecordingNavigationManager());
        return services;
    }

    private static void Configure(VaultBlazorOptions o)
    {
        o.Authority = "https://vault.example.com";
        o.ClientId = "blazor-app";
        o.RedirectUri = "https://app.example.com/auth/callback";
    }
}
