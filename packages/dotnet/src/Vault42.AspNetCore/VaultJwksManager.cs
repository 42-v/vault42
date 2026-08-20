using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Vault42.AspNetCore.Internal;

namespace Vault42.AspNetCore;

/// <summary>
/// Fetches, caches, and auto-refreshes JWKS keys from The Vault.
/// Thread-safe. Supports forced refresh on unknown kid (rate-limited).
/// </summary>
public sealed class VaultJwksManager : IDisposable
{
    // Minimum RSA modulus length in bytes (2048 bits = 256 bytes).
    // Reject any JWKS-supplied key smaller than this.
    private const int MinModulusBytes = 256;

    private readonly HttpClient _httpClient;
    private readonly ILogger<VaultJwksManager>? _logger;
    private readonly string _jwksUri;
    private readonly TimeSpan _refreshInterval;
    private readonly TimeSpan _minRefreshInterval;
    private readonly bool _refreshOnUnknownKid;
    private readonly long _maxJwksBytes;
    private readonly SemaphoreSlim _refreshLock = new (1, 1);
    private readonly ConcurrentDictionary<string, SecurityKey> _keys = new ();

    // The Vault server emits JWKS with lowercase property names (kty/kid/n/e),
    // and System.Text.Json defaults to case-sensitive matching.
    private static readonly JsonSerializerOptions JwksJsonOptions = new ()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly Timer _timer;
    private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="VaultJwksManager"/> class.
    /// </summary>
    /// <param name="httpClient">
    /// Client used for every JWKS fetch. Its <see cref="HttpClient.Timeout"/> bounds the fetch;
    /// <c>AddVault</c> configures one from <see cref="VaultAuthenticationOptions.JwksHttpTimeout"/>.
    /// </param>
    /// <param name="options">
    /// Source of the JWKS URI (<see cref="VaultAuthenticationOptions.Authority"/> plus
    /// <c>/.well-known/jwks.json</c>) and of the refresh and size limits. The values are copied
    /// here, so later mutation of <paramref name="options"/> has no effect.
    /// </param>
    /// <param name="logger">
    /// Receives the two conditions that leave the cache serving stale or no keys while every
    /// request still looks ordinary: a forced refresh that failed, and a refresh that parsed but
    /// yielded no usable key. Optional, but without it both are silent and the only symptom is
    /// "Unknown signing key" on tokens that should validate.
    /// </param>
    /// <remarks>
    /// The constructor performs no I/O and leaves the key cache empty; the background refresh
    /// timer stays disarmed until <see cref="InitializeAsync"/> runs. Resolving a kid before then
    /// fails.
    /// </remarks>
    public VaultJwksManager(
        HttpClient httpClient,
        VaultAuthenticationOptions options,
        ILogger<VaultJwksManager>? logger = null)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jwksUri = options.Authority.TrimEnd('/') + "/.well-known/jwks.json";
        _refreshInterval = options.JwksRefreshInterval;
        _minRefreshInterval = options.MinimumJwksRefreshInterval;
        _refreshOnUnknownKid = options.RefreshOnUnknownKid;
        _maxJwksBytes = options.MaxJwksBytes;
#pragma warning disable S1854 // discard '_ =' is the documented fire-and-forget pattern for Timer callbacks
        _timer = new Timer(_ => _ = RefreshInternalAsync(), null, Timeout.Infinite, Timeout.Infinite);
#pragma warning restore S1854
    }

    /// <summary>
    /// Initialize by fetching JWKS. Call once at startup.
    /// </summary>
    /// <param name="ct">Cancels the initial fetch.</param>
    /// <returns>A task that completes once the first fetch has settled and the refresh timer is armed.</returns>
    /// <exception cref="HttpRequestException">
    /// The initial fetch failed at the transport layer or the server answered a non-success status.
    /// Startup should treat this as fatal: with no keys cached, every token is rejected as
    /// "Unknown signing key".
    /// </exception>
    /// <exception cref="JsonException">
    /// The body was not parseable JSON. Fatal for the same reason as a non-success status, and
    /// stated here because it was previously documented as not throwing: the one test covering it
    /// fed <c>{"keys":null}</c>, which is well-formed and returns quietly, so the throw was never
    /// exercised.
    /// </exception>
    /// <remarks>
    /// An oversized body is not an exception, and neither is a well-formed document with no usable
    /// key. Both return having changed nothing, and the periodic refresh retries on the next tick,
    /// so this method can complete successfully with an empty key set. Unlike a forced refresh from
    /// <see cref="ResolveKeyAsync"/>, failures here are not caught: an application that starts with
    /// no keys serves 401s to every caller, and finding that out at startup beats finding it out in
    /// production traffic.
    /// </remarks>
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await RefreshInternalAsync(ct);
        _timer.Change(_refreshInterval, _refreshInterval);
    }

    /// <summary>
    /// Resolve a security key by kid. Returns null if not found
    /// (after attempting a forced refresh if enabled).
    /// </summary>
    /// <param name="kid">The <c>kid</c> header value of the token being validated.</param>
    /// <param name="ct">Cancels a forced refresh triggered by an unknown kid.</param>
    /// <returns>
    /// The cached <see cref="SecurityKey"/> for <paramref name="kid"/>, or <see langword="null"/>
    /// when the key is unknown. Callers must fail authentication on null rather than fall back to
    /// any other key.
    /// </returns>
    /// <remarks>
    /// <para>A cache miss triggers one immediate refetch only when
    /// <see cref="VaultAuthenticationOptions.RefreshOnUnknownKid"/> is enabled and at least
    /// <see cref="VaultAuthenticationOptions.MinimumJwksRefreshInterval"/> has passed since the
    /// last refresh attempt. That rate limit makes an unknown kid a bounded cost, so a flood of
    /// forged kids cannot turn token validation into a request amplifier against the Vault server.
    /// Within the window the miss returns null without any network call, which means a genuinely
    /// new signing key can be rejected for up to that interval after rotation.</para>
    /// <para>A forced refresh that fails is answered null, not rethrown. The caller is the
    /// authentication handler, which turns null into a 401; letting the fetch failure out instead
    /// made an unknown kid arriving while the Vault was down a 500, so a caller could take the
    /// resource server's error rate up by presenting garbage kids. The failure is logged rather
    /// than swallowed silently.</para>
    /// </remarks>
    public async Task<SecurityKey?> ResolveKeyAsync(string kid, CancellationToken ct = default)
    {
        if (_keys.TryGetValue(kid, out var key))
            return key;

        if (!_refreshOnUnknownKid)
            return null;

        // Rate-limited forced refresh
        if (DateTimeOffset.UtcNow - _lastRefresh < _minRefreshInterval)
            return null;

        try
        {
            await RefreshInternalAsync(ct);
        }
        catch (HttpRequestException ex)
        {
            _logger?.LogWarning(ex, "Vault42: forced JWKS refresh for an unknown kid failed; the key set is unchanged");
            return null;
        }
        catch (JsonException ex)
        {
            _logger?.LogWarning(ex, "Vault42: forced JWKS refresh returned a body that is not a JWKS document; the key set is unchanged");
            return null;
        }
        catch (FormatException ex)
        {
            // Base64UrlDecode of a JWK's n or e. A JWKS with one malformed member is not a
            // reason to fail the request with a 500.
            _logger?.LogWarning(ex, "Vault42: forced JWKS refresh returned a key whose base64url did not decode; the key set is unchanged");
            return null;
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            // HttpClient.Timeout. The filter keeps a genuine caller cancellation -- an aborted
            // request -- propagating, because that is not a JWKS problem and the response is
            // already gone.
            _logger?.LogWarning(ex, "Vault42: forced JWKS refresh timed out; the key set is unchanged");
            return null;
        }

        _keys.TryGetValue(kid, out key);
        return key;
    }

    /// <summary>
    /// Gets a snapshot of all cached key IDs (for diagnostics).
    /// </summary>
#pragma warning disable S2365 // diagnostics-only API; callers consume immediately, no caching concerns
    public IReadOnlyCollection<string> CachedKeyIds => _keys.Keys.ToArray();
#pragma warning restore S2365

    private async Task RefreshInternalAsync(CancellationToken ct = default)
    {
        if (!await _refreshLock.WaitAsync(0, ct))
            return; // another refresh in progress

        try
        {
            var response = await _httpClient.GetAsync(_jwksUri, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();

            // Reject upfront if Content-Length advertises an oversized body.
            if (response.Content.Headers.ContentLength is long cl && cl > _maxJwksBytes)
                return;

            await using var rawStream = await response.Content.ReadAsStreamAsync(ct);
            await using var bounded = new LimitedReadStream(rawStream, _maxJwksBytes);
            JwksResponse? jwks;
            try
            {
                jwks = await JsonSerializer.DeserializeAsync<JwksResponse>(bounded, JwksJsonOptions, ct);
            }
            catch (InvalidDataException)
            {
                // Body exceeded MaxJwksBytes
                return;
            }

            if (jwks?.Keys is null)
                return;

            var newKeys = new HashSet<string>();
            foreach (var jwk in jwks.Keys)
            {
                if (jwk.Kty != "RSA" || string.IsNullOrEmpty(jwk.Kid))
                    continue;

                // CS-5: only accept JWKs with `use=sig` (or no `use` at all, for legacy JWKS).
                if (!string.IsNullOrEmpty(jwk.Use) && jwk.Use != "sig")
                    continue;

                // Cross-check declared alg if present — must be RS256.
                if (!string.IsNullOrEmpty(jwk.Alg) && jwk.Alg != "RS256")
                    continue;

                var modulus = Base64UrlDecode(jwk.N);

                // CS-6: reject keys shorter than 2048 bits.
                if (modulus.Length < MinModulusBytes)
                    continue;

                var rsaParams = new RSAParameters
                {
                    Modulus = modulus,
                    Exponent = Base64UrlDecode(jwk.E),
                };

                var rsaKey = new RsaSecurityKey(rsaParams) { KeyId = jwk.Kid };
                _keys[jwk.Kid] = rsaKey;
                newKeys.Add(jwk.Kid);
            }

            // A document that parsed but yielded nothing usable -- {"keys":[]}, or a set whose
            // every member was filtered out by the use/alg/modulus rules -- is treated as a
            // fetch that told us nothing, not as "the issuer has retired every key". Falling
            // through to the eviction loop emptied the cache and rejected every token in flight
            // with "Unknown signing key", turning one bad publish into a total outage that
            // recovers only when the issuer publishes again.
            if (newKeys.Count == 0)
            {
                _logger?.LogError(
                    "Vault42: JWKS at {JwksUri} published no usable signing key; keeping the {CachedCount} already cached",
                    _jwksUri,
                    _keys.Count);
                return;
            }

            // Remove stale keys no longer in JWKS
            foreach (var oldKid in _keys.Keys)
            {
                if (!newKeys.Contains(oldKid))
                    _keys.TryRemove(oldKid, out _);
            }
        }
        finally
        {
            // Stamped on every terminating path, not only the successful one. As the last
            // statement of the try it was skipped by every early return and every throw, which
            // left _lastRefresh at its initial value and made the MinimumJwksRefreshInterval
            // check in ResolveKeyAsync unreachable: while the Vault was unreachable, each
            // unknown-kid request produced its own outbound fetch. The limiter has to hold
            // precisely when refreshes are failing, because that is when the retries pile up.
            _lastRefresh = DateTimeOffset.UtcNow;
            _refreshLock.Release();
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        // base64url -> base64: replace chars and add padding
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }

        return Convert.FromBase64String(s);
    }

    /// <summary>
    /// Stops the background refresh timer and releases the refresh lock.
    /// </summary>
    /// <remarks>
    /// Idempotent. Cached keys are left in place and a refresh already in flight is not awaited,
    /// so <see cref="ResolveKeyAsync"/> must not be called after disposal. The manager is
    /// registered as a singleton by <c>AddVault</c>, so in a normal host the container owns this
    /// call at shutdown.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _timer.Dispose();
        _refreshLock.Dispose();
    }

    // JSON deserialization targets — analyzers can't see the System.Text.Json
    // reflection path, so they flag setters as "unassigned" and suggest
    // converting to records. Suppress those rules; setters ARE required.
#pragma warning disable S3459, CA1812, S1144, CA1852
    private sealed class JwksResponse
    {
        public List<JwkEntry>? Keys { get; set; }
    }

    private sealed class JwkEntry
    {
        public string Kty { get; set; } = string.Empty;

        public string Use { get; set; } = string.Empty;

        public string Kid { get; set; } = string.Empty;

        public string Alg { get; set; } = string.Empty;

        public string N { get; set; } = string.Empty;

        public string E { get; set; } = string.Empty;
    }
#pragma warning restore S3459, CA1812, S1144, CA1852
}
