using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
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

    // This was Initialize_SurvivesAMalformedDocumentWithAnEmptyCache, and it fed
    // {"keys":null}: well-formed JSON that deserialises to a null list and
    // returns quietly. So it exercised the quiet path while claiming the
    // malformed one, and the malformed one -- which throws straight out of
    // InitializeAsync, contradicting the XML doc that said it does not -- was
    // never executed. Both are asserted now, separately.
    [Fact]
    public async Task Initialize_WithAKeysMemberOfNull_CachesNothingAndDoesNotThrow()
    {
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, "{\"keys\":null}");
        using var manager = Manager(http);

        await manager.InitializeAsync();

        Assert.Empty(manager.CachedKeyIds);
    }

    // An unparseable body is fatal at startup for the same reason a 5xx is: the
    // process would come up answering 401 to every caller, and an operator finds
    // that out faster from a failed start than from traffic.
    [Fact]
    public async Task Initialize_PropagatesAnUnparseableBody()
    {
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, "{\"keys\": [");
        using var manager = Manager(http);

        await Assert.ThrowsAsync<JsonException>(() => manager.InitializeAsync());
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

        // Wait for the request to be dispatched rather than assuming it has
        // been. RefreshInternalAsync takes the lock before it calls GetAsync, so
        // a dispatched request means the lock is held -- without this the second
        // caller can win the lock, fetch first, and the stub answers a request
        // it has no canned response for.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (http.Calls == 0)
        {
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException("the first fetch never reached the transport");
            await Task.Delay(10);
        }

        // The first fetch is now parked inside the response body, holding the lock.
        Assert.Null(await manager.ResolveKeyAsync("kid-unknown"));
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

    // The test above only ever measured the limiter after a refresh that
    // succeeded, which is the one case where it already worked: the timestamp was
    // the last statement of the try, so success set it and every early return and
    // every throw skipped it. While refreshes were failing the window never
    // opened and each unknown kid bought its own outbound fetch -- the amplifier
    // the limiter exists to prevent, disarmed exactly when the Vault is already
    // in trouble.
    //
    // One failed fetch, then five misses. The stub was given one response and
    // throws on any request past it, so before the fix this fails on the second
    // request rather than on the count.
    [Fact]
    public async Task ResolveKey_AfterAFailedRefresh_IsStillRateLimited()
    {
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.InternalServerError);
        using var manager = Manager(http, o => o.MinimumJwksRefreshInterval = TimeSpan.FromMinutes(30));

        await Assert.ThrowsAsync<HttpRequestException>(() => manager.InitializeAsync());

        for (var i = 0; i < 5; i++)
            Assert.Null(await manager.ResolveKeyAsync("kid-unknown"));

        Assert.Equal(1, http.Calls);
    }

    // Every way the fetch can fail has to come back as "no key", because the
    // caller is the authentication handler and it turns null into a 401. Letting
    // any of these out made a token naming an unknown kid a 500 whenever the
    // Vault was unreachable, so an unauthenticated caller could drive this
    // application's error rate by sending garbage kids.
    [Theory]
    [InlineData("status")]
    [InlineData("unparseable")]
    [InlineData("bad-base64")]
    [InlineData("timeout")]
    public async Task ResolveKey_WhenTheForcedRefreshFails_AnswersNoKeyRatherThanThrowing(string failure)
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
        switch (failure)
        {
            case "status":
                http.Enqueue(HttpStatusCode.BadGateway);
                break;
            case "unparseable":
                http.Enqueue(HttpStatusCode.OK, "{\"keys\": [");
                break;
            case "bad-base64":
                // A JWK whose modulus is not base64url. Convert.FromBase64String
                // throws FormatException from inside the parse loop.
                http.Enqueue(HttpStatusCode.OK, "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"kid-2\",\"use\":\"sig\",\"n\":\"!!!!\",\"e\":\"AQAB\"}]}");
                break;
            default:
                // What HttpClient.Timeout raises: a cancellation nobody asked for.
                http.EnqueueThrow(new TaskCanceledException("timeout", new TimeoutException()));
                break;
        }

        using var manager = Manager(http, o => o.MinimumJwksRefreshInterval = TimeSpan.Zero);
        await manager.InitializeAsync();

        Assert.Null(await manager.ResolveKeyAsync("kid-unknown"));

        // The already-cached key is still there: a failed refresh is not a reason
        // to stop verifying tokens that were verifying a moment ago.
        Assert.NotNull(await manager.ResolveKeyAsync("kid-1"));
    }

    // A failure that leaves the key set stale is invisible from the outside --
    // every request just starts answering 401 -- so it has to be findable in the
    // log.
    [Fact]
    public async Task ResolveKey_LogsAFailedForcedRefresh()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler()
            .Enqueue(HttpStatusCode.OK, signer.JwksJson())
            .Enqueue(HttpStatusCode.BadGateway);
        var logger = new RecordingLogger<VaultJwksManager>();
        using var manager = Manager(http, o => o.MinimumJwksRefreshInterval = TimeSpan.Zero, logger);
        await manager.InitializeAsync();

        Assert.Null(await manager.ResolveKeyAsync("kid-unknown"));

        var record = Assert.Single(logger.Records);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Contains("JWKS refresh", record.Message, StringComparison.Ordinal);
    }

    // A caller that really did cancel -- an aborted request -- is not a JWKS
    // problem, and swallowing it would report "unknown signing key" for a
    // response nobody is waiting for any more. The exception filter that lets a
    // timeout through has to keep this one out.
    [Fact]
    public async Task ResolveKey_WithACancelledToken_DoesNotSwallowTheCancellation()
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
        using var manager = Manager(http, o => o.MinimumJwksRefreshInterval = TimeSpan.Zero);
        await manager.InitializeAsync();

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => manager.ResolveKeyAsync("kid-unknown", cts.Token));
    }

    // A JWKS that parses but publishes nothing usable -- an empty array, or a set
    // whose every member the use/alg/modulus rules refuse -- used to fall through
    // to the eviction loop and empty the cache, so one bad publish rejected every
    // token in flight and stayed broken until the issuer published again. Keep
    // what is cached and say so loudly instead.
    [Theory]
    [InlineData("{\"keys\":[]}")]
    [InlineData("{\"keys\":[{\"kty\":\"EC\",\"kid\":\"ec-1\",\"use\":\"sig\",\"crv\":\"P-256\"}]}")]
    public async Task ARefreshPublishingNoUsableKey_KeepsThePreviousSetAndLogs(string emptyDocument)
    {
        using var signer = new TestSigner();
        var http = new StubHttpMessageHandler()
            .Enqueue(HttpStatusCode.OK, signer.JwksJson())
            .Enqueue(HttpStatusCode.OK, emptyDocument);
        var logger = new RecordingLogger<VaultJwksManager>();
        using var manager = Manager(http, o => o.MinimumJwksRefreshInterval = TimeSpan.Zero, logger);
        await manager.InitializeAsync();

        Assert.Null(await manager.ResolveKeyAsync("kid-unknown"));

        Assert.Equal(new[] { "kid-1" }, manager.CachedKeyIds);
        Assert.NotNull(await manager.ResolveKeyAsync("kid-1"));

        var record = Assert.Single(logger.Records);
        Assert.Equal(LogLevel.Error, record.Level);
        Assert.Contains("no usable signing key", record.Message, StringComparison.Ordinal);
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
        Action<VaultAuthenticationOptions>? configure = null,
        ILogger<VaultJwksManager>? logger = null)
    {
        var options = new VaultAuthenticationOptions { Authority = TestSigner.Issuer };
        configure?.Invoke(options);
        return new VaultJwksManager(new HttpClient(http), options, logger);
    }
}
