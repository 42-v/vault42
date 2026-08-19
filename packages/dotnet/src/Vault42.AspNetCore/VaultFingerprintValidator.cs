using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Vault42.AspNetCore;

/// <summary>
/// Computes and validates Vault device fingerprints.
/// Matches the Go implementation in internal/crypto/fingerprint.go exactly:
/// SHA256 over 4-byte big-endian length-prefixed UTF-8 fields.
/// </summary>
public static class VaultFingerprintValidator
{
    /// <summary>
    /// Compute a fingerprint from the given components.
    /// </summary>
    /// <param name="ip">The client IP as the server sees it.</param>
    /// <param name="userAgent">The <c>User-Agent</c> header value, or the empty string when absent.</param>
    /// <param name="acceptLanguage">The <c>Accept-Language</c> header value, or the empty string when absent.</param>
    /// <param name="tlsFingerprint">
    /// The TLS fingerprint forwarded by the terminating proxy, or the empty string when no such
    /// header is configured.
    /// </param>
    /// <returns>The lowercase hex SHA-256 digest of the four length-prefixed fields.</returns>
    /// <remarks>
    /// Each field is written as a 4-byte big-endian length followed by its UTF-8 bytes. The length
    /// prefixes are what make the digest unambiguous: without them two different field splits could
    /// hash identically and one client could impersonate another's fingerprint. Field order is part
    /// of the contract and must match <c>internal/crypto/fingerprint.go</c> on the server, or every
    /// comparison fails.
    /// </remarks>
    public static string ComputeFingerprint(string ip, string userAgent, string acceptLanguage, string tlsFingerprint)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        WriteLengthPrefixed(sha, ip);
        WriteLengthPrefixed(sha, userAgent);
        WriteLengthPrefixed(sha, acceptLanguage);
        WriteLengthPrefixed(sha, tlsFingerprint);
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>
    /// Validate the fingerprint claim against the current HTTP request.
    /// </summary>
    /// <param name="context">The request whose IP and headers are re-hashed.</param>
    /// <param name="expectedFingerprint">The <c>fingerprint</c> claim value carried by the token.</param>
    /// <param name="tlsFingerprintHeader">
    /// Name of the header carrying the proxy's TLS fingerprint, or <see langword="null"/> to hash
    /// an empty TLS field. This must match the server's configuration; a mismatch makes every
    /// comparison fail rather than fail open.
    /// </param>
    /// <returns><see langword="true"/> when the recomputed fingerprint equals the claim.</returns>
    /// <remarks>
    /// The comparison is constant-time, so a caller cannot recover the expected value by timing
    /// repeated attempts. The client IP is read from <see cref="Microsoft.AspNetCore.Http.ConnectionInfo.RemoteIpAddress"/>,
    /// which behind a reverse proxy is the proxy's address unless forwarded-headers processing is
    /// configured first; without that, every token issued through the proxy fails this check.
    /// </remarks>
    public static bool Validate(HttpContext context, string expectedFingerprint, string? tlsFingerprintHeader)
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        var ua = context.Request.Headers.UserAgent.ToString();
        var lang = context.Request.Headers.AcceptLanguage.ToString();
        var tls = string.IsNullOrEmpty(tlsFingerprintHeader)
            ? string.Empty
            : context.Request.Headers[tlsFingerprintHeader].ToString();

        var computed = ComputeFingerprint(ip, ua, lang, tls);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computed),
            Encoding.UTF8.GetBytes(expectedFingerprint));
    }

    private static void WriteLengthPrefixed(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> lenBuf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)bytes.Length);
        hash.AppendData(lenBuf);
        hash.AppendData(bytes);
    }
}
