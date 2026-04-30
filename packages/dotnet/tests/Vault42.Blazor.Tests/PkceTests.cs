using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Vault42.Blazor.Tests;

public class PkceTests
{
    [Fact]
    public void GenerateVerifier_Returns43CharBase64Url()
    {
        var verifier = Internal.Pkce.GenerateVerifier();
        Assert.InRange(verifier.Length, 43, 128);

        // Must be base64url safe characters only
        Assert.Matches("^[A-Za-z0-9_-]+$", verifier);
    }

    [Fact]
    public void GenerateVerifier_ProducesUniqueValues()
    {
        var a = Internal.Pkce.GenerateVerifier();
        var b = Internal.Pkce.GenerateVerifier();
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeChallenge_S256_MatchesRFC7636()
    {
        // RFC 7636 Appendix B test vector
        // verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // expected challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = Internal.Pkce.ComputeChallenge(verifier);
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
    }

    [Fact]
    public void ComputeChallenge_DifferentVerifiers_ProduceDifferentChallenges()
    {
        var a = Internal.Pkce.ComputeChallenge("verifier-alpha");
        var b = Internal.Pkce.ComputeChallenge("verifier-bravo");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeChallenge_SameVerifier_ProducesSameChallenge()
    {
        var verifier = Internal.Pkce.GenerateVerifier();
        var a = Internal.Pkce.ComputeChallenge(verifier);
        var b = Internal.Pkce.ComputeChallenge(verifier);
        Assert.Equal(a, b);
    }
}
