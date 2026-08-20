using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Vault42.AspNetCore;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// A signing key and a token factory, so the handler tests can mint exactly the
/// token the case needs -- wrong issuer, wrong algorithm, a jku header, a
/// missing token_type -- rather than approximating one.
/// </summary>
internal sealed class TestSigner : IDisposable
{
    internal TestSigner(string kid = "kid-1", int keySizeBits = 2048)
    {
        Rsa = RSA.Create(keySizeBits);
        Kid = kid;
        Key = new RsaSecurityKey(Rsa) { KeyId = kid };
    }

    internal RSA Rsa { get; }

    internal string Kid { get; }

    internal RsaSecurityKey Key { get; }

    internal const string Issuer = "https://vault.example.com";

    /// <summary>Serialises the public half as a JWKS document the manager can fetch.</summary>
    internal string JwksJson(string? use = "sig", string? alg = "RS256", string? kid = null)
    {
        var p = Rsa.ExportParameters(false);
        var fields = new List<string>
        {
            "\"kty\":\"RSA\"",
            $"\"kid\":\"{kid ?? Kid}\"",
            $"\"n\":\"{Base64Url(p.Modulus!)}\"",
            $"\"e\":\"{Base64Url(p.Exponent!)}\"",
        };
        if (use is not null) fields.Add($"\"use\":\"{use}\"");
        if (alg is not null) fields.Add($"\"alg\":\"{alg}\"");
        return "{\"keys\":[{" + string.Join(",", fields) + "}]}";
    }

    internal string Token(
        string issuer = Issuer,
        string audience = Issuer,
        string tokenType = "Bearer",
        string? kid = null,
        TimeSpan? lifetime = null,
        IEnumerable<Claim>? extraClaims = null,
        string algorithm = SecurityAlgorithms.RsaSha256)
    {
        var claims = new List<Claim>
        {
            new ("sub", "user-1"),
            new ("jti", "0e2c8a1a-0000-4000-8000-000000000001"),
        };
        if (tokenType.Length > 0)
            claims.Add(new Claim(VaultClaimTypes.TokenType, tokenType));
        if (extraClaims is not null)
            claims.AddRange(extraClaims);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(15)),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(Rsa) { KeyId = kid ?? Kid }, algorithm),
        };
        var handler = new JwtSecurityTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    /// <summary>
    /// Mints a token with an extra header field, signed over that header.
    /// </summary>
    /// <remarks>
    /// SecurityTokenDescriptor.AdditionalHeaderClaims is honoured by
    /// JsonWebTokenHandler and ignored by JwtSecurityTokenHandler, so asking the latter for a
    /// token with a jku header silently produces one without it -- and a test written that way
    /// passes whether or not the handler rejects the header. Assembling and signing the three
    /// segments by hand is the only way to produce the token an attacker would actually send.
    /// </remarks>
    internal string TokenWithHeader(string headerName, string headerValue)
    {
        var payload = new JwtSecurityTokenHandler().ReadJwtToken(Token()).EncodedPayload;
        var header = Base64Url(System.Text.Encoding.UTF8.GetBytes(
            $"{{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"{Kid}\",\"{headerName}\":\"{headerValue}\"}}"));

        var signingInput = System.Text.Encoding.ASCII.GetBytes($"{header}.{payload}");
        var signature = Rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{header}.{payload}.{Base64Url(signature)}";
    }

    /// <summary>Mints a token whose header names no kid.</summary>
    internal string TokenWithoutKid()
    {
        var payload = new JwtSecurityTokenHandler().ReadJwtToken(Token()).EncodedPayload;
        var header = Base64Url(System.Text.Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"));
        var signature = Rsa.SignData(
            System.Text.Encoding.ASCII.GetBytes($"{header}.{payload}"),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return $"{header}.{payload}.{Base64Url(signature)}";
    }

    public void Dispose() => Rsa.Dispose();

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>
/// Serves a queue of canned responses and records what was asked for, so a test
/// can assert that a rate-limited refresh did not reach the network at all.
/// </summary>
internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<Func<HttpResponseMessage>> _responses = new ();

    internal int Calls { get; private set; }

    internal StubHttpMessageHandler Enqueue(HttpStatusCode status, string body = "", long? contentLength = null)
    {
        _responses.Enqueue(() =>
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
            };
            if (contentLength is not null)
                response.Content.Headers.ContentLength = contentLength;
            return response;
        });
        return this;
    }

    /// <summary>
    /// Queues a body served without a Content-Length, the way a chunked response
    /// arrives.
    /// </summary>
    /// <remarks>
    /// The manager has two size defences and the Content-Length one shadows the other: a body
    /// that declares its length is refused before it is read, so the LimitedReadStream cut-off
    /// mid-parse is only reachable through a response that declares nothing.
    /// </remarks>
    internal StubHttpMessageHandler EnqueueChunked(string body)
    {
        // StreamContent reads Length off a seekable stream and sets Content-Length
        // from it, which would send this straight back down the branch it is meant
        // to bypass. A forward-only stream leaves the length undeclared.
        _responses.Enqueue(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new ForwardOnlyStream(System.Text.Encoding.UTF8.GetBytes(body))),
        });
        return this;
    }

    /// <summary>Queues a body whose read blocks until <paramref name="gate"/> completes.</summary>
    internal StubHttpMessageHandler EnqueueGated(string body, Task gate)
    {
        _responses.Enqueue(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new GatedStream(System.Text.Encoding.UTF8.GetBytes(body), gate)),
        });
        return this;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls++;
        if (_responses.Count == 0)
            throw new InvalidOperationException($"unexpected request: {request.RequestUri}");
        return Task.FromResult(_responses.Dequeue()());
    }

    private sealed class ForwardOnlyStream : MemoryStream
    {
        internal ForwardOnlyStream(byte[] buffer)
            : base(buffer)
        {
        }

        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();
    }

    private sealed class GatedStream : MemoryStream
    {
        private readonly Task _gate;
        private bool _waited;

        internal GatedStream(byte[] buffer, Task gate)
            : base(buffer) => _gate = gate;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_waited)
            {
                _waited = true;
                await _gate;
            }

            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
}

/// <summary>
/// Drives VaultAuthenticationHandler without a web host. The middleware
/// constructs the handler and calls InitializeAsync itself in a real
/// application; doing the same here reaches HandleAuthenticateAsync and
/// HandleChallengeAsync through their public entry points rather than through
/// reflection, so a change to how they are wired shows up as a failure.
/// </summary>
internal static class HandlerHarness
{
    internal static async Task<(AuthenticateResult Result, HttpContext Context)> AuthenticateAsync(
        VaultAuthenticationOptions options,
        VaultJwksManager jwks,
        Action<HttpContext> configureRequest)
    {
        var (handler, context) = await BuildAsync(options, jwks, configureRequest);
        return (await handler.AuthenticateAsync(), context);
    }

    internal static async Task<HttpContext> ChallengeAsync(
        VaultAuthenticationOptions options,
        VaultJwksManager jwks,
        Action<HttpContext> configureRequest)
    {
        var (handler, context) = await BuildAsync(options, jwks, configureRequest);
        await handler.ChallengeAsync(null);
        return context;
    }

    private static async Task<(VaultAuthenticationHandler Handler, HttpContext Context)> BuildAsync(
        VaultAuthenticationOptions options,
        VaultJwksManager jwks,
        Action<HttpContext> configureRequest)
    {
        var handler = new VaultAuthenticationHandler(
            new StaticOptionsMonitor(options),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            jwks);

        var context = new DefaultHttpContext();
        configureRequest(context);

        var scheme = new AuthenticationScheme(
            VaultDefaults.AuthenticationScheme,
            VaultDefaults.DisplayName,
            typeof(VaultAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);
        return (handler, context);
    }

    private sealed class StaticOptionsMonitor : IOptionsMonitor<VaultAuthenticationOptions>
    {
        private readonly VaultAuthenticationOptions _options;

        internal StaticOptionsMonitor(VaultAuthenticationOptions options) => _options = options;

        public VaultAuthenticationOptions CurrentValue => _options;

        public VaultAuthenticationOptions Get(string? name) => _options;

        public IDisposable? OnChange(Action<VaultAuthenticationOptions, string?> listener) => null;
    }
}
