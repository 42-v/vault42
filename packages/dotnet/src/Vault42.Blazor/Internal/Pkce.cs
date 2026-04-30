using System.Security.Cryptography;
using System.Text;

namespace Vault42.Blazor.Internal;

/// <summary>
/// PKCE (RFC 7636) helper — generates code verifier and S256 challenge.
/// </summary>
internal static class Pkce
{
    /// <summary>
    /// Generate a cryptographically random code verifier (43-128 unreserved characters).
    /// </summary>
    internal static string GenerateVerifier()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Base64UrlEncode(bytes);
    }

    /// <summary>
    /// Compute the S256 code challenge from a verifier.
    /// challenge = BASE64URL(SHA256(ASCII(verifier))).
    /// </summary>
    internal static string ComputeChallenge(string verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
