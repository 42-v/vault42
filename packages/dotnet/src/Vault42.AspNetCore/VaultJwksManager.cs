using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
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

    public VaultJwksManager(HttpClient httpClient, VaultAuthenticationOptions options)
    {
        _httpClient = httpClient;
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
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await RefreshInternalAsync(ct);
        _timer.Change(_refreshInterval, _refreshInterval);
    }

    /// <summary>
    /// Resolve a security key by kid. Returns null if not found
    /// (after attempting a forced refresh if enabled).
    /// </summary>
    public async Task<SecurityKey?> ResolveKeyAsync(string kid, CancellationToken ct = default)
    {
        if (_keys.TryGetValue(kid, out var key))
            return key;

        if (!_refreshOnUnknownKid)
            return null;

        // Rate-limited forced refresh
        if (DateTimeOffset.UtcNow - _lastRefresh < _minRefreshInterval)
            return null;

        await RefreshInternalAsync(ct);
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

            // Remove stale keys no longer in JWKS
            foreach (var oldKid in _keys.Keys)
            {
                if (!newKeys.Contains(oldKid))
                    _keys.TryRemove(oldKid, out _);
            }

            _lastRefresh = DateTimeOffset.UtcNow;
        }
        finally
        {
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
