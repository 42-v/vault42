using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Vault42.AspNetCore;

/// <summary>
/// Extension methods for registering Vault authentication.
/// </summary>
public static class VaultAuthenticationExtensions
{
    /// <summary>
    /// Add Vault JWT authentication to the authentication builder.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddAuthentication(VaultDefaults.AuthenticationScheme)
    ///     .AddVault(options => {
    ///         options.Authority = "https://vault.example.com";
    ///     });
    /// </code>
    /// </example>
    public static AuthenticationBuilder AddVault(
        this AuthenticationBuilder builder,
        Action<VaultAuthenticationOptions> configure)
    {
        return builder.AddVault(VaultDefaults.AuthenticationScheme, configure);
    }

    /// <summary>
    /// Add Vault JWT authentication with a custom scheme name.
    /// </summary>
    public static AuthenticationBuilder AddVault(
        this AuthenticationBuilder builder,
        string scheme,
        Action<VaultAuthenticationOptions> configure)
    {
        var options = new VaultAuthenticationOptions();
        configure(options);

        if (string.IsNullOrEmpty(options.Authority))
            throw new ArgumentException("VaultAuthenticationOptions.Authority is required.", nameof(configure));

        if (options.RequireHttpsMetadata
            && !options.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "VaultAuthenticationOptions.Authority must be HTTPS. " +
                "Set RequireHttpsMetadata = false to allow HTTP (development only — JWKS over HTTP is trivially MITM-able).",
                nameof(configure));
        }

        builder.Services.AddHttpClient(VaultDefaults.HttpClientName, client =>
        {
            client.BaseAddress = new Uri(options.Authority.TrimEnd('/'));
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = options.JwksHttpTimeout;
        });

        builder.Services.AddSingleton(sp =>
        {
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            var httpClient = factory.CreateClient(VaultDefaults.HttpClientName);
            return new VaultJwksManager(httpClient, options);
        });

        builder.AddScheme<VaultAuthenticationOptions, VaultAuthenticationHandler>(
            scheme, VaultDefaults.DisplayName, configure);

        return builder;
    }

    /// <summary>
    /// Initialize the Vault JWKS manager. Call in the application startup pipeline.
    /// This fetches the initial key set from The Vault and starts background refresh.
    /// </summary>
    public static async Task UseVaultAuthenticationAsync(this IServiceProvider services, CancellationToken ct = default)
    {
        var jwks = services.GetRequiredService<VaultJwksManager>();
        await jwks.InitializeAsync(ct);
    }
}
