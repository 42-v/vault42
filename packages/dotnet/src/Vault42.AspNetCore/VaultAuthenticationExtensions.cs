using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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
    /// <param name="builder">The authentication builder to register the scheme on.</param>
    /// <param name="configure">
    /// Configures the options. Invoked immediately to validate <c>Authority</c>, and again by the
    /// options system when the scheme is resolved, so it must be free of side effects.
    /// </param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentException">
    /// <see cref="VaultAuthenticationOptions.Authority"/> is empty, or it is not HTTPS while
    /// <see cref="VaultAuthenticationOptions.RequireHttpsMetadata"/> is set.
    /// </exception>
    public static AuthenticationBuilder AddVault(
        this AuthenticationBuilder builder,
        Action<VaultAuthenticationOptions> configure)
    {
        return builder.AddVault(VaultDefaults.AuthenticationScheme, configure);
    }

    /// <summary>
    /// Add Vault JWT authentication with a custom scheme name.
    /// </summary>
    /// <param name="builder">The authentication builder to register the scheme on.</param>
    /// <param name="scheme">
    /// Scheme name to register under. Use this overload only when the default
    /// <see cref="VaultDefaults.AuthenticationScheme"/> collides with another scheme.
    /// </param>
    /// <param name="configure">
    /// Configures the options. Invoked immediately to validate <c>Authority</c>, and again by the
    /// options system when the scheme is resolved, so it must be free of side effects.
    /// </param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentException">
    /// <see cref="VaultAuthenticationOptions.Authority"/> is empty, or it is not HTTPS while
    /// <see cref="VaultAuthenticationOptions.RequireHttpsMetadata"/> is set. JWKS fetched over
    /// plain HTTP is trivially substituted in transit, which is why the HTTPS check is on by
    /// default and opting out is a development-only measure.
    /// </exception>
    /// <remarks>
    /// Registering the scheme does not fetch any key. Call
    /// <see cref="UseVaultAuthenticationAsync"/> during startup, or the first request finds an
    /// empty key cache.
    /// </remarks>
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
            return new VaultJwksManager(
                httpClient,
                options,
                sp.GetService<ILogger<VaultJwksManager>>());
        });

        builder.AddScheme<VaultAuthenticationOptions, VaultAuthenticationHandler>(
            scheme, VaultDefaults.DisplayName, configure);

        return builder;
    }

    /// <summary>
    /// Initialize the Vault JWKS manager. Call in the application startup pipeline.
    /// This fetches the initial key set from The Vault and starts background refresh.
    /// </summary>
    /// <param name="services">The built service provider, typically <c>app.Services</c>.</param>
    /// <param name="ct">Cancels the initial JWKS fetch.</param>
    /// <returns>A task that completes once the first fetch has settled and background refresh is armed.</returns>
    /// <exception cref="InvalidOperationException">
    /// <c>AddVault</c> was never called, so no <see cref="VaultJwksManager"/> is registered.
    /// </exception>
    /// <exception cref="HttpRequestException">The Vault server was unreachable or answered a non-success status.</exception>
    /// <remarks>
    /// Await this before the host starts serving. Skipping it leaves the key cache empty and every
    /// token is rejected as "Unknown signing key" until the first background refresh lands.
    /// </remarks>
    public static async Task UseVaultAuthenticationAsync(this IServiceProvider services, CancellationToken ct = default)
    {
        var jwks = services.GetRequiredService<VaultJwksManager>();
        await jwks.InitializeAsync(ct);
    }
}
