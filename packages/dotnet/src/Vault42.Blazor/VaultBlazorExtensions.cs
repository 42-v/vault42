using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using Vault42.Blazor.Internal;

namespace Vault42.Blazor;

/// <summary>
/// Extension methods for registering Vault Blazor authentication services.
/// </summary>
public static class VaultBlazorExtensions
{
    /// <summary>
    /// Add Vault authentication to a Blazor WASM application.
    /// Registers VaultAuthService, AuthenticationStateProvider, and the authorization message handler.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddVaultAuth(options =>
    /// {
    ///     options.Authority = "https://vault.example.com";
    ///     options.ClientId = "my-blazor-app";
    ///     options.RedirectUri = "https://myapp.com/auth/callback";
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddVaultAuth(
        this IServiceCollection services,
        Action<VaultBlazorOptions> configure)
    {
        var options = new VaultBlazorOptions();
        configure(options);

        if (string.IsNullOrEmpty(options.Authority))
            throw new ArgumentException("Authority is required", nameof(configure));
        if (string.IsNullOrEmpty(options.ClientId))
            throw new ArgumentException("ClientId is required", nameof(configure));
        if (string.IsNullOrEmpty(options.RedirectUri))
            throw new ArgumentException("RedirectUri is required", nameof(configure));

        services.AddSingleton(options);

        // Internal token store. Refresh-token backend is selected by
        // VaultBlazorOptions.RefreshStorage (default: HttpOnlyCookieOnly).
        services.AddSingleton<TokenStore>(sp =>
            new TokenStore(
                sp.GetRequiredService<IJSRuntime>(),
                sp.GetRequiredService<VaultBlazorOptions>().RefreshStorage));

        // Authentication state provider
        services.AddSingleton<VaultAuthenticationStateProvider>(sp =>
            new VaultAuthenticationStateProvider(sp.GetRequiredService<TokenStore>()));
        services.AddSingleton<AuthenticationStateProvider>(sp =>
            sp.GetRequiredService<VaultAuthenticationStateProvider>());

        // HttpClient for token exchange (no auth handler — would be circular)
        services.AddSingleton(sp =>
        {
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
            return httpClient;
        });

        // Auth service
        services.AddSingleton<VaultAuthService>(sp =>
            new VaultAuthService(
                sp.GetRequiredService<VaultBlazorOptions>(),
                sp.GetService<HttpClient>() ?? new HttpClient(),
                sp.GetRequiredService<NavigationManager>(),
                sp.GetRequiredService<TokenStore>(),
                sp.GetRequiredService<VaultAuthenticationStateProvider>()));

        // Authorization message handler for user-registered HttpClients
        services.AddTransient<VaultAuthorizationMessageHandler>(sp =>
            new VaultAuthorizationMessageHandler(sp.GetRequiredService<VaultAuthService>()));

        services.AddAuthorizationCore();

        return services;
    }

    /// <summary>
    /// Configure a named HttpClient to use Vault authentication.
    /// Attaches the Bearer token to all outgoing requests.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddHttpClient("VaultAPI", client =>
    /// {
    ///     client.BaseAddress = new Uri("https://vault.example.com");
    /// }).AddVaultAuthorization();
    /// </code>
    /// </example>
    public static IHttpClientBuilder AddVaultAuthorization(this IHttpClientBuilder builder)
    {
        return builder.AddHttpMessageHandler<VaultAuthorizationMessageHandler>();
    }
}
