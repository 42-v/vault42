using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests.Hardening;

/// <summary>
/// CS-4 regression tests: every Vault-issued access token carries
/// token_type=Bearer, so a validly signed JWT without the claim must be
/// rejected the same as a 2FA challenge token, while token_type=Bearer
/// authenticates. Runs the real handler against a stubbed JWKS endpoint.
/// </summary>
public class TokenTypeClaimTests
{
    private const string Kid = "cs4-test-kid";
    private const string Authority = "https://vault.example.test";

    [Fact]
    public async Task Authenticate_SignedTokenWithoutTokenTypeClaim_Fails()
    {
        using var rsa = RSA.Create(2048);

        var result = await RunHandlerAsync(rsa, SignToken(rsa, includeTokenType: false));

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid token type", result.Failure?.Message);
    }

    [Fact]
    public async Task Authenticate_SignedTokenWithBearerTokenType_Succeeds()
    {
        using var rsa = RSA.Create(2048);

        var result = await RunHandlerAsync(rsa, SignToken(rsa, includeTokenType: true));

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Ticket);
    }

    private static string SignToken(RSA rsa, bool includeTokenType)
    {
        var claims = new List<Claim> { new ("sub", "user-1") };
        if (includeTokenType)
            claims.Add(new (VaultClaimTypes.TokenType, "Bearer"));

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = Authority,
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(rsa) { KeyId = Kid },
                SecurityAlgorithms.RsaSha256),
        };

        return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
    }

    private static string JwksJson(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var n = Base64UrlEncoder.Encode(p.Modulus);
        var e = Base64UrlEncoder.Encode(p.Exponent);
        return $"{{\"keys\":[{{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"{Kid}\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
    }

    private static async Task<AuthenticateResult> RunHandlerAsync(RSA rsa, string token)
    {
        var options = new VaultAuthenticationOptions { Authority = Authority };
        using var httpClient = new HttpClient(new StaticJwksHandler(JwksJson(rsa)));
        using var jwks = new VaultJwksManager(httpClient, options);
        await jwks.InitializeAsync();

        var handler = new VaultAuthenticationHandler(
            new StaticOptionsMonitor(options),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            jwks);

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer " + token;

        var scheme = new AuthenticationScheme(
            VaultDefaults.AuthenticationScheme,
            VaultDefaults.AuthenticationScheme,
            typeof(VaultAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        return await handler.AuthenticateAsync();
    }

    private sealed class StaticJwksHandler : HttpMessageHandler
    {
        private readonly string _json;

        public StaticJwksHandler(string json) => _json = json;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_json, Encoding.UTF8, "application/json"),
            });
    }

    private sealed class StaticOptionsMonitor : IOptionsMonitor<VaultAuthenticationOptions>
    {
        public StaticOptionsMonitor(VaultAuthenticationOptions value) => CurrentValue = value;

        public VaultAuthenticationOptions CurrentValue { get; }

        public VaultAuthenticationOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<VaultAuthenticationOptions, string?> listener) => null;
    }
}
