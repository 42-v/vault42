using System.Security.Claims;
using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// The claims helpers are what consuming applications write their authorization
/// checks against, so their edge behaviour is part of the published contract:
/// what an unauthenticated principal returns, whether a scope check is exact,
/// and which claim name wins when a token supplies both spellings of the
/// subject. None of that was covered.
///
/// The documented promise is that these never throw. A helper that threw on an
/// anonymous principal would turn an ordinary unauthenticated request into a 500
/// in every application that called it outside an [Authorize] endpoint.
/// </summary>
public class VaultClaimsPrincipalExtensionsTests
{
    [Fact]
    public void AnonymousPrincipal_ReturnsEmptyRatherThanThrowing()
    {
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Null(anonymous.GetUserId());
        Assert.Null(anonymous.GetClientId());
        Assert.Null(anonymous.GetFingerprint());
        Assert.Null(anonymous.GetTokenId());
        Assert.Empty(anonymous.GetRoles());
        Assert.Empty(anonymous.GetScopes());
        Assert.False(anonymous.HasScope("read"));
        Assert.False(anonymous.HasVaultRole("admin"));
    }

    [Fact]
    public void GetUserId_PrefersTheNameIdentifierUri()
    {
        var principal = Principal(
            new Claim(ClaimTypes.NameIdentifier, "mapped-subject"),
            new Claim("sub", "raw-subject"));

        Assert.Equal("mapped-subject", principal.GetUserId());
    }

    // A token whose subject was never mapped still has to resolve, otherwise a
    // principal built by anything other than VaultAuthenticationHandler reports
    // no user at all.
    [Fact]
    public void GetUserId_FallsBackToTheRawSubClaim()
    {
        var principal = Principal(new Claim("sub", "raw-subject"));

        Assert.Equal("raw-subject", principal.GetUserId());
    }

    [Fact]
    public void GetRolesAndScopes_ReturnEveryValue()
    {
        var principal = Principal(
            new Claim(ClaimTypes.Role, "user"),
            new Claim(ClaimTypes.Role, "admin"),
            new Claim("scope", "read"),
            new Claim("scope", "write"));

        Assert.Equal(new[] { "user", "admin" }, principal.GetRoles());
        Assert.Equal(new[] { "read", "write" }, principal.GetScopes());
    }

    // The XML documentation states this explicitly: the comparison is ordinal and
    // exact, with no prefix or hierarchy rules. A scope check that treated
    // "blobs" as covering "blobs:read" would silently widen every grant the Vault
    // issues.
    [Theory]
    [InlineData("blobs:read", true)]
    [InlineData("blobs", false)]
    [InlineData("blobs:read:extra", false)]
    [InlineData("BLOBS:READ", false)]
    public void HasScope_IsExactAndCaseSensitive(string probe, bool expected)
    {
        var principal = Principal(new Claim("scope", "blobs:read"));

        Assert.Equal(expected, principal.HasScope(probe));
    }

    [Fact]
    public void HasVaultRole_ReadsTheMappedRoleClaim()
    {
        var principal = Principal(new Claim(ClaimTypes.Role, "admin"));

        Assert.True(principal.HasVaultRole("admin"));
        Assert.False(principal.HasVaultRole("owner"));
    }

    [Fact]
    public void ClientIdFingerprintAndTokenId_ComeFromTheirOwnClaims()
    {
        var principal = Principal(
            new Claim(VaultClaimTypes.ClientId, "blazor-app"),
            new Claim(VaultClaimTypes.Fingerprint, new string('a', 64)),
            new Claim("jti", "0e2c8a1a-0000-4000-8000-000000000001"));

        Assert.Equal("blazor-app", principal.GetClientId());
        Assert.Equal(new string('a', 64), principal.GetFingerprint());
        Assert.Equal("0e2c8a1a-0000-4000-8000-000000000001", principal.GetTokenId());
    }

    // The scope claims the helpers read are the mapped ones. A token carrying a
    // raw "scopes" array with mapping disabled reports no scopes, which is the
    // documented behaviour and the reason the option exists.
    [Fact]
    public void UnmappedArrayClaims_AreNotReadAsScopesOrRoles()
    {
        var principal = Principal(
            new Claim("scopes", "[\"read\",\"write\"]"),
            new Claim("roles", "[\"admin\"]"));

        Assert.Empty(principal.GetScopes());
        Assert.Empty(principal.GetRoles());
        Assert.False(principal.HasScope("read"));
    }

    private static ClaimsPrincipal Principal(params Claim[] claims) =>
        new (new ClaimsIdentity(claims, "Vault", "sub", ClaimTypes.Role));
}
