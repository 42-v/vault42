using System.Net;
using Microsoft.AspNetCore.Http;
using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// ComputeFingerprint was covered; Validate, the half that reads the live
/// request, was not. It is the function that decides whether a stolen token
/// replayed from somewhere else is refused, and three of its details are easy to
/// get wrong in a way no compiler catches: which header supplies each field, what
/// a request with no remote address hashes as, and whether the TLS field is
/// included when no header is configured.
/// </summary>
public class VaultFingerprintValidateTests
{
    [Fact]
    public void AMatchingRequest_Validates()
    {
        var context = Request("203.0.113.7", "probe-agent", "en-GB");
        var expected = VaultFingerprintValidator.ComputeFingerprint(
            "203.0.113.7", "probe-agent", "en-GB", string.Empty);

        Assert.True(VaultFingerprintValidator.Validate(context, expected, null));
    }

    // One field at a time, because a validator that hashed only the address would
    // pass the first of these and fail nothing else.
    [Theory]
    [InlineData("198.51.100.9", "probe-agent", "en-GB")]
    [InlineData("203.0.113.7", "other-agent", "en-GB")]
    [InlineData("203.0.113.7", "probe-agent", "fr-FR")]
    public void AnyChangedField_Invalidates(string ip, string agent, string language)
    {
        var expected = VaultFingerprintValidator.ComputeFingerprint(
            "203.0.113.7", "probe-agent", "en-GB", string.Empty);

        Assert.False(VaultFingerprintValidator.Validate(Request(ip, agent, language), expected, null));
    }

    // The TLS field is only read when a header name is configured, and the header
    // is ignored entirely when it is not. Reading it unconditionally would make
    // every token fail the moment a proxy started sending one.
    [Fact]
    public void TheTlsFieldIsReadOnlyWhenAHeaderIsConfigured()
    {
        var context = Request("203.0.113.7", "probe-agent", "en-GB");
        context.Request.Headers["X-JA4"] = "ja4-value";

        var withTls = VaultFingerprintValidator.ComputeFingerprint(
            "203.0.113.7", "probe-agent", "en-GB", "ja4-value");
        var withoutTls = VaultFingerprintValidator.ComputeFingerprint(
            "203.0.113.7", "probe-agent", "en-GB", string.Empty);

        Assert.True(VaultFingerprintValidator.Validate(context, withTls, "X-JA4"));
        Assert.False(VaultFingerprintValidator.Validate(context, withoutTls, "X-JA4"));

        Assert.True(VaultFingerprintValidator.Validate(context, withoutTls, null));
        Assert.True(VaultFingerprintValidator.Validate(context, withoutTls, string.Empty));
    }

    // A configured header the proxy did not send hashes as empty rather than
    // throwing, so a misconfiguration degrades to "no TLS component" instead of a
    // 500 on every request.
    [Fact]
    public void AConfiguredHeaderThatIsAbsent_HashesAsEmpty()
    {
        var context = Request("203.0.113.7", "probe-agent", "en-GB");
        var expected = VaultFingerprintValidator.ComputeFingerprint(
            "203.0.113.7", "probe-agent", "en-GB", string.Empty);

        Assert.True(VaultFingerprintValidator.Validate(context, expected, "X-JA4"));
    }

    // Kestrel on IPv6Any -- the default for any container image, and what
    // ASPNETCORE_URLS=http://+:8080 produces -- reports an IPv4 client as
    // ::ffff:203.0.113.7, and IPAddress.ToString keeps it in that form. Go prints
    // the same address as its dotted quad, so the Vault hashed "203.0.113.7"
    // while this hashed "::ffff:203.0.113.7": two digests for one client, and a
    // 401 on every request from every IPv4 user of every container deployment.
    [Fact]
    public void AnIPv4ClientOnADualStackListener_HashesAsItsDottedQuad()
    {
        var context = Request("::ffff:203.0.113.7", "probe-agent", "en-GB");
        var asTheVaultHashedIt = VaultFingerprintValidator.ComputeFingerprint(
            "203.0.113.7", "probe-agent", "en-GB", string.Empty);

        Assert.True(VaultFingerprintValidator.Validate(context, asTheVaultHashedIt, null));
    }

    // The digest the unfixed validator produced. It has to be refused, because no
    // Vault has ever issued a token carrying it.
    [Fact]
    public void TheMappedSpellingIsNotAcceptedAsAFingerprint()
    {
        var context = Request("::ffff:203.0.113.7", "probe-agent", "en-GB");
        var mappedSpelling = VaultFingerprintValidator.ComputeFingerprint(
            "::ffff:203.0.113.7", "probe-agent", "en-GB", string.Empty);

        Assert.False(VaultFingerprintValidator.Validate(context, mappedSpelling, null));
    }

    // Unmapping must not touch a native IPv6 client. Go and .NET already agree on
    // the compressed lowercase form there, and rewriting it would break the case
    // the fix was not about.
    [Fact]
    public void ANativeIPv6Client_IsHashedUnchanged()
    {
        var context = Request("2001:db8::1", "probe-agent", "en-GB");
        var expected = VaultFingerprintValidator.ComputeFingerprint(
            "2001:db8::1", "probe-agent", "en-GB", string.Empty);

        Assert.True(VaultFingerprintValidator.Validate(context, expected, null));
    }

    // Kestrel leaves RemoteIpAddress null for a Unix-socket connection, and the
    // in-process test host leaves it null too. Empty rather than an exception.
    [Fact]
    public void ARequestWithNoRemoteAddress_HashesTheAddressAsEmpty()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.UserAgent = "probe-agent";
        context.Request.Headers.AcceptLanguage = "en-GB";
        var expected = VaultFingerprintValidator.ComputeFingerprint(
            string.Empty, "probe-agent", "en-GB", string.Empty);

        Assert.True(VaultFingerprintValidator.Validate(context, expected, null));
    }

    // The comparison is constant-time, so it cannot short-circuit on the first
    // differing byte. A digest of a different length is not equal either.
    [Theory]
    [InlineData("")]
    [InlineData("short")]
    public void AnExpectedValueOfTheWrongLength_IsNotEqual(string expected)
    {
        var context = Request("203.0.113.7", "probe-agent", "en-GB");

        Assert.False(VaultFingerprintValidator.Validate(context, expected, null));
    }

    private static DefaultHttpContext Request(string ip, string userAgent, string acceptLanguage)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        context.Request.Headers.UserAgent = userAgent;
        context.Request.Headers.AcceptLanguage = acceptLanguage;
        return context;
    }
}
