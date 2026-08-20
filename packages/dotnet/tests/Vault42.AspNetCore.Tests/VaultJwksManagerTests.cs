using System.Net;
using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// The JWKS manager decides which keys this application will verify tokens
/// under, so every filter in its parser is a security control: CS-5 (only
/// use=sig), CS-6 (no modulus under 2048 bits), RS256 only, RSA only. The
/// hardening suite asserted those rules against a hand-built key set; these
/// drive them through the fetch, which is also the only way to reach the size
/// bound, the stale-key eviction and the rate limit on forced refresh.
/// </summary>
public class VaultJwksManagerTests
{
    [Fact]
    public async Task Initialize_CachesTheKeysTheDocumentDeclares()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Equal(new[] { "kid-1" }, manager.CachedKeyIds);
        Assert.NotNull(await manager.ResolveKeyAsync("kid-1"));
    }

    // A JWKS fetch that fails at startup has to be fatal rather than silently
    // leaving an empty cache: an empty cache rejects every token, and the reason
    // an operator sees would be "Unknown signing key" on every request.
    [Fact]
    public async Task Initialize_PropagatesANonSuccessStatus()
    {
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.InternalServerError);
        using var manager = Manager(http);

        await Assert.ThrowsAsync<HttpRequestException>(() => manager.InitializeAsync());
    }

    // A malformed body is not: the periodic refresh will retry, and taking the
    // process down for one bad response would turn a transient issuer bug into an
    // outage.
    [Fact]
    public async Task Initialize_SurvivesAMalformedDocumentWithAnEmptyCache()
    {
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, "{\"keys\":null}");
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    // CS-5. A key published for encryption is not a key this application will
    // verify a signature under.
    [Fact]
    public async Task KeysDeclaredForEncryption_AreRefused()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson(use: "enc"));
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    // A legacy JWKS omits `use` entirely, and that stays acceptable: the check is
    // "not declared for something else", not "declared for signing".
    [Fact]
    public async Task KeysWithNoUseDeclaration_AreAccepted()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson(use: null));
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Equal(new[] { "kid-1" }, manager.CachedKeyIds);
    }

    [Fact]
    public async Task KeysDeclaringAnAlgorithmOtherThanRs256_AreRefused()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson(alg: "PS256"));
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    // CS-6. A 1024-bit modulus is forgeable with resources that exist, so the
    // issuer offering one is refused rather than trusted.
    [Fact]
    public async Task KeysBelow2048Bits_AreRefused()
    {
        using var weak = new TestSigner(keySizeBits: 1024);
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, weak.JwksJson());
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    [Fact]
    public async Task NonRsaKeys_AreSkipped()
    {
        const string ecOnly = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"ec-1\",\"use\":\"sig\",\"crv\":\"P-256\"}]}";
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, ecOnly);
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    [Fact]
    public async Task KeysWithoutAKid_AreSkipped()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson(kid: string.Empty));
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    // A retired key must stop verifying tokens once the issuer stops publishing
    // it, or revocation by rotation does not work.
    [Fact]
    public async Task ARefreshEvictsKeysTheDocumentNoLongerPublishes()
    {
        using var first = new TestSigner("kid-old");
        using var second = new TestSigner("kid-new");
        var http = new StubHttpMessageHandler()
            .Enqueue(HttpStatusCode.OK, first.JwksJson())
            .Enqueue(HttpStatusCode.OK, second.JwksJson());
        using var manager = Manager(http, o => o.MinimumJwksRefreshInterval = TimeSpan.Zero);

        await manager.InitializeAsync();
        Assert.Equal(new[] { "kid-old" }, manager.CachedKeyIds);

        // The unknown kid drives the second fetch.
        Assert.NotNull(await manager.ResolveKeyAsync("kid-new"));
        Assert.Equal(new[] { "kid-new" }, manager.CachedKeyIds);
    }

    // An advertised Content-Length over the cap is refused before the body is
    // read at all, so the cheap case never allocates.
    [Fact]
    public async Task AnOversizedContentLength_IsRefusedWithoutCachingAnything()
    {
        using var signer = new TestSigner();
        var body = signer.JwksJson();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, body, contentLength: 10_000_000);
        using var manager = Manager(http, o => o.MaxJwksBytes = 1024);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    // And a body that lies about its length, or does not declare one, is cut off
    // by LimitedReadStream mid-parse. The InvalidDataException is swallowed and
    // the cache left untouched, because a truncated key set is worse than none.
    [Fact]
    public async Task ABodyOverTheCap_IsAbandonedRatherThanPartiallyParsed()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
        using var manager = Manager(http, o => o.MaxJwksBytes = 16);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    // A response with no declared length reaches LimitedReadStream, which is the
    // defence that actually bounds an endless body. The InvalidDataException is
    // swallowed and the cache left untouched, because a truncated key set is
    // worse than none.
    [Fact]
    public async Task AnUndeclaredOversizedBody_IsCutOffMidParse()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().EnqueueChunked(signer.JwksJson());
        using var manager = Manager(http, o => o.MaxJwksBytes = 16);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    // Two refreshes racing must not both fetch: the second returns immediately
    // rather than queueing behind the first, so a burst of unknown kids costs one
    // request and not one each.
    [Fact]
    public async Task ARefreshRacingAnotherReturnsWithoutFetching()
    {
        using var signer = new TestSigner();
        var gate = new TaskCompletionSource();
        var http = new StubHttpMessageHandler().EnqueueGated(signer.JwksJson(), gate.Task);
        using var manager = Manager(http, o => o.MinimumJwksRefreshInterval = TimeSpan.Zero);

        var first = manager.InitializeAsync();

        // The first fetch is parked inside the response body, holding the lock.
        var second = manager.ResolveKeyAsync("kid-unknown");
        Assert.Null(await second);
        Assert.Equal(1, http.Calls);

        gate.SetResult();
        await first;
        Assert.Equal(new[] { "kid-1" }, manager.CachedKeyIds);
    }

    [Fact]
    public async Task ResolveKey_WithRefreshOnUnknownKidDisabled_MakesNoRequest()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
        using var manager = Manager(http, o => o.RefreshOnUnknownKid = false);
        await manager.InitializeAsync();

        Assert.Null(await manager.ResolveKeyAsync("kid-unknown"));
        Assert.Equal(1, http.Calls);
    }

    // The rate limit is what stops a flood of forged kids turning this
    // application into a request amplifier against the Vault. Within the window
    // the miss is answered from nothing at all.
    [Fact]
    public async Task ResolveKey_WithinTheRateLimitWindow_MakesNoRequest()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
        using var manager = Manager(http, o => o.MinimumJwksRefreshInterval = TimeSpan.FromMinutes(30));
        await manager.InitializeAsync();

        Assert.Null(await manager.ResolveKeyAsync("kid-unknown"));
        Assert.Null(await manager.ResolveKeyAsync("kid-unknown"));
        Assert.Equal(1, http.Calls);
    }

    [Fact]
    public async Task Dispose_IsIdempotent()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
        var manager = Manager(http);
        await manager.InitializeAsync();

        manager.Dispose();
        manager.Dispose();
    }

    private static VaultJwksManager Manager(
        StubHttpMessageHandler http,
        Action<VaultAuthenticationOptions>? configure = null)
    {
        var options = new VaultAuthenticationOptions { Authority = TestSigner.Issuer };
        configure?.Invoke(options);
        return new VaultJwksManager(new HttpClient(http), options);
    }
}
