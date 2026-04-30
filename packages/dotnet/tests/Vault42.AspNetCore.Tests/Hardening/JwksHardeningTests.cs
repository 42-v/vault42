using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests.Hardening;

/// <summary>
/// JWKS hardening tests (CS-5 use=sig, CS-6 min modulus, CS-7 size bound).
/// Drives <see cref="VaultJwksManager"/> against a fake HTTP server.
/// </summary>
public class JwksHardeningTests
{
    private const string FakeAuthority = "https://vault.test";

    // CS-5: a JWK with use=enc must NOT be added to the signing-key cache.
    [Fact]
    public async Task Refresh_RejectsUseEnc()
    {
        var jwks = MakeJwks(new[]
        {
            (kid: "enc-key", use: "enc", alg: "RS256", modBytes: 256),
            (kid: "sig-key", use: "sig", alg: "RS256", modBytes: 256),
        });

        var mgr = MakeManager(jwks);
        await mgr.InitializeAsync();

        Assert.Null(await mgr.ResolveKeyAsync("enc-key"));
        Assert.NotNull(await mgr.ResolveKeyAsync("sig-key"));
    }

    // CS-6: keys with modulus < 2048 bits (256 bytes) must NOT be added.
    [Fact]
    public async Task Refresh_RejectsUndersizedModulus()
    {
        var jwks = MakeJwks(new[]
        {
            (kid: "weak-1024", use: "sig", alg: "RS256", modBytes: 128), // 1024-bit
            (kid: "ok-2048",  use: "sig", alg: "RS256", modBytes: 256), // 2048-bit
        });

        var mgr = MakeManager(jwks);
        await mgr.InitializeAsync();

        Assert.Null(await mgr.ResolveKeyAsync("weak-1024"));
        Assert.NotNull(await mgr.ResolveKeyAsync("ok-2048"));
    }

    // CS-5 additional: JWK declaring alg != RS256 is rejected (defence-in-depth
    // even though RS256 is enforced again at validation time).
    [Fact]
    public async Task Refresh_RejectsNonRs256Alg()
    {
        var jwks = MakeJwks(new[]
        {
            (kid: "es-key", use: "sig", alg: "ES256", modBytes: 256),
        });

        var mgr = MakeManager(jwks);
        await mgr.InitializeAsync();

        Assert.Null(await mgr.ResolveKeyAsync("es-key"));
    }

    // CS-7: an oversized JWKS body must NOT exhaust memory; refresh quietly drops.
    [Fact]
    public async Task Refresh_BoundedBodySize()
    {
        // Build an extremely large JWKS (>1 MiB default) by inflating the JWK list.
        var entries = new List<(string kid, string use, string alg, int modBytes)>();
        for (int i = 0; i < 5000; i++)
            entries.Add(($"k-{i}", "sig", "RS256", 256));
        var oversized = MakeJwks(entries.ToArray());

        Assert.True(Encoding.UTF8.GetByteCount(oversized) > 1_000_000);

        // 1 MiB bound — should refuse.
        var mgr = MakeManager(oversized, maxBytes: 1L * 1024 * 1024);
        await mgr.InitializeAsync();

        // None of the keys should have been ingested.
        Assert.Empty(mgr.CachedKeyIds);
    }

    // -- helpers --
    private static VaultJwksManager MakeManager(string jwksJson, long? maxBytes = null)
    {
        var http = new HttpClient(new StubHandler(jwksJson))
        {
            BaseAddress = new Uri(FakeAuthority)
        };
        var opts = new VaultAuthenticationOptions
        {
            Authority = FakeAuthority,
            JwksRefreshInterval = TimeSpan.FromMinutes(60),
            MaxJwksBytes = maxBytes ?? 1L * 1024 * 1024,
        };
        return new VaultJwksManager(http, opts);
    }

    private static string MakeJwks((string kid, string use, string alg, int modBytes)[] entries)
    {
        var keys = entries.Select(e => new
        {
            kty = "RSA",
            use = e.use,
            alg = e.alg,
            kid = e.kid,
            n = Base64UrlEncode(new byte[e.modBytes]),
            e = Base64UrlEncode(new byte[] { 1, 0, 1 }),
        }).ToArray();

        return JsonSerializer.Serialize(new { keys });
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        // Fill the modulus with non-zero bytes so RsaSecurityKey doesn't reject.
        for (int i = 0; i < bytes.Length; i++)
            if (bytes[i] == 0) bytes[i] = (byte)(0x80 | (i & 0x7F));
        return Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly string _body;

        internal StubHandler(string body)
        {
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(resp);
        }
    }
}
