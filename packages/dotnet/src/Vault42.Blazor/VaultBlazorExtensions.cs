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
    /// <param name="services">The service collection to register on.</param>
    /// <param name="configure">
    /// Configures the options. Invoked once, immediately; the resulting instance is registered as a
    /// singleton, so later mutation of it changes the live configuration.
    /// </param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <exception cref="ArgumentException">
    /// <c>Authority</c>, <c>ClientId</c> or <c>RedirectUri</c> is empty.
    /// </exception>
    /// <remarks>
    /// Registers an unauthenticated <see cref="HttpClient"/> for the token exchange itself.
    /// Attaching the authorization handler to that client would make refresh depend on a valid
    /// token, which is circular. Use <see cref="AddVaultAuthorization"/> on your own named clients
    /// instead.
    /// </remarks>
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
    /// <param name="builder">The named-client builder to attach the handler to.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <remarks>
    /// The token is attached to every request the client makes, so scope the client to the Vault
    /// origin. Pointing it at a third-party host would send the bearer there too. Requires
    /// <see cref="AddVaultAuth"/> to have registered the handler.
    /// </remarks>
    public static IHttpClientBuilder AddVaultAuthorization(this IHttpClientBuilder builder)
    {
        return builder.AddHttpMessageHandler<VaultAuthorizationMessageHandler>();
    }
}
