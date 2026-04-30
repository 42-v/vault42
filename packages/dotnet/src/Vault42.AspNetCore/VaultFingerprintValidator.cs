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
