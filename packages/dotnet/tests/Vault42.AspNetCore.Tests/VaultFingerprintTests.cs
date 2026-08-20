using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// A fingerprint computed here has to equal the one the Vault computed when it
/// issued the token, or the claim rejects the request. That makes this a
/// cross-implementation contract, and the only test that can check a contract
/// between two implementations is one holding a value the other one produced.
///
/// The test that used to make this claim, ComputeFingerprint_MatchesGoImplementation,
/// asserted a 64-character lower-hex regex and that two calls to the same function
/// agree. Both hold for any SHA-256 of anything in any field order, so it would
/// have passed with the fields swapped, the length prefix dropped, or a different
/// hash entirely. The digests below were produced by running
/// internal/crypto/fingerprint.go under Go 1.26.
/// </summary>
public class VaultFingerprintTests
{
    /// <summary>
    /// Known-answer vectors, in order: four empty fields, which is sixteen zero bytes and pins
    /// the length prefix itself; a browser behind no TLS-fingerprinting proxy; the same browser
    /// with VAULT_TLS_FINGERPRINT_HEADER configured, since the fourth field is the one an
    /// implementation is most likely to drop because it is empty everywhere else; a native IPv6
    /// client in the compressed lowercase form both net.IP.String and IPAddress.ToString produce;
    /// and the separator-collision pair, each with the digest Go gives it. Asserting only that
    /// the last two differ from each other, which is what this file used to do, cannot tell a
    /// correct length prefix from a different wrong one.
    /// </summary>
    [Theory]
    [InlineData("", "", "", "", "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb")]
    [InlineData(
        "203.0.113.7", "Mozilla/5.0", "en-GB,en;q=0.9", "",
        "537c0d1a678f75404f506e0d09e2c83289f0c55f2a4c3dcbc727d905523c0661")]
    [InlineData(
        "203.0.113.7", "Mozilla/5.0", "en-GB,en;q=0.9", "t13d1516h2_8daaf6152771_b0da82dd1658",
        "f59ac93406eb191ae156dd2d439bcf776ca53c46aa6de65a9857dc6a52a045ab")]
    [InlineData(
        "2001:db8::1", "curl/8.5.0", "", "",
        "038a4a0fbbc881b34dfc6f87ea08ea542dec83aec0a0a00ae9fe4854c21301e2")]
    [InlineData("ab", "cd", "", "", "b624a80bcb7759ba730d10d02a63a40e206c120cfa566efb224cc9aa0afab6d8")]
    [InlineData("a", "bcd", "", "", "132b367d01205d90b26ec03dca3144bbff365e29c5e24c22d29369780272473f")]
    public void ComputeFingerprint_MatchesTheDigestTheGoImplementationProduces(
        string ip, string userAgent, string acceptLanguage, string tlsFingerprint, string expected)
    {
        Assert.Equal(expected, VaultFingerprintValidator.ComputeFingerprint(ip, userAgent, acceptLanguage, tlsFingerprint));
    }

    // Field order is half the contract and the known-answer vectors above only
    // pin it indirectly. Two fields swapped between positions must not produce
    // the same digest.
    [Fact]
    public void ComputeFingerprint_IsSensitiveToFieldOrder()
    {
        var forward = VaultFingerprintValidator.ComputeFingerprint("alpha", "bravo", "charlie", "delta");
        var swapped = VaultFingerprintValidator.ComputeFingerprint("bravo", "alpha", "delta", "charlie");

        Assert.NotEqual(forward, swapped);
    }

    [Fact]
    public void ComputeFingerprint_DifferentInputs_ProduceDifferentHashes()
    {
        var a = VaultFingerprintValidator.ComputeFingerprint("192.168.1.1", "Mozilla/5.0", "en-US", string.Empty);
        var b = VaultFingerprintValidator.ComputeFingerprint("192.168.1.2", "Mozilla/5.0", "en-US", string.Empty);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeFingerprint_LowercaseHex()
    {
        var fp = VaultFingerprintValidator.ComputeFingerprint("127.0.0.1", "test-agent", "en", "ja4_abc");
        Assert.Matches("^[0-9a-f]{64}$", fp);
    }
}
