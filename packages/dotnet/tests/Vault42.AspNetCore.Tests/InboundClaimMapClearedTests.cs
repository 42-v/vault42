using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// JwtSecurityTokenHandler.DefaultInboundClaimTypeMap is static, mutable, and
/// widely cleared: an application that wants its claims to keep the names the
/// issuer gave them writes
/// <c>JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear()</c> at startup.
/// With the map in place a "roles" claim is renamed to ClaimTypes.Role before
/// this handler sees it, which is why role mapping appeared to work while the
/// handler's own mapping code was inert. With the map cleared, the handler's
/// code is the only thing left, so this is where MapRolesToClaims is actually
/// load-bearing.
///
/// The map is process-global, so these tests share a collection with the rest of
/// the handler suite to keep them off the same thread, and restore it afterwards.
/// </summary>
[Collection(ClaimMapSerializer.Name)]
public sealed class InboundClaimMapClearedTests : IDisposable
{
    private readonly IDictionary<string, string> _saved;

    public InboundClaimMapClearedTests()
    {
        _saved = new Dictionary<string, string>(JwtSecurityTokenHandler.DefaultInboundClaimTypeMap);
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
    }

    public void Dispose()
    {
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        foreach (var pair in _saved)
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Add(pair.Key, pair.Value);
    }

    [Fact]
    public async Task RolesAreStillMappedWhenNothingElseMapsThem()
    {
        using var signer = new TestSigner();
        var options = Options();
        using var jwks = await JwksAsync(signer, options);
        var token = signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Roles, "[\"user\",\"admin\"]", System.IdentityModel.Tokens.Jwt.JsonClaimValueTypes.JsonArray),
        });

        var (result, _) = await HandlerHarness.AuthenticateAsync(options, jwks, ctx =>
            ctx.Request.Headers.Authorization = $"Bearer {token}");

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.NotNull(result.Principal);
        Assert.Equal(new[] { "user", "admin" }, result.Principal.GetRoles());
        Assert.True(result.Principal.HasVaultRole("admin"));
    }

    // And with mapping turned off, nothing puts them back.
    [Fact]
    public async Task WithRoleMappingOffNoRolesReachThePrincipal()
    {
        using var signer = new TestSigner();
        var options = Options(o => o.MapRolesToClaims = false);
        using var jwks = await JwksAsync(signer, options);
        var token = signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Roles, "[\"admin\"]", System.IdentityModel.Tokens.Jwt.JsonClaimValueTypes.JsonArray),
        });

        var (result, _) = await HandlerHarness.AuthenticateAsync(options, jwks, ctx =>
            ctx.Request.Headers.Authorization = $"Bearer {token}");

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.NotNull(result.Principal);
        Assert.Empty(result.Principal.GetRoles());
    }

    private static VaultAuthenticationOptions Options(Action<VaultAuthenticationOptions>? configure = null)
    {
        var options = new VaultAuthenticationOptions
        {
            Authority = TestSigner.Issuer,
            RefreshOnUnknownKid = false,
        };
        configure?.Invoke(options);
        return options;
    }

    private static async Task<VaultJwksManager> JwksAsync(TestSigner signer, VaultAuthenticationOptions options)
    {
        var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
        var jwks = new VaultJwksManager(new HttpClient(http), options);
        await jwks.InitializeAsync();
        return jwks;
    }
}

/// <summary>
/// Serialises every test that reads or writes the static inbound claim map.
/// Named without a "Collection" suffix because CA1711 reserves it for collection types.
/// </summary>
[CollectionDefinition(Name)]
public static class ClaimMapSerializer
{
    internal const string Name = "inbound-claim-map";
}
