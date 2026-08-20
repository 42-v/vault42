using System.Security.Claims;
using System.Text.Json;
using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// The state provider decodes the JWT payload in the browser without verifying
/// it, so what it does with a payload it cannot make sense of is the whole
/// question. Every branch answers the same way: anonymous, never a partially
/// populated identity. The existing suite covered the happy path and the
/// no-token path; these cover the rest of the payload shapes a real token
/// carries and the three ways parsing gives up.
/// </summary>
public class VaultAuthenticationStateProviderPayloadTests
{
    [Fact]
    public async Task NumericBooleanAndObjectClaims_AreCarriedAsTheirRawJson()
    {
        var state = await StateFor(new
        {
            sub = "user-1",
            iat = 1_700_000_000,
            email_verified = true,
            mfa = false,
            profile = new { locale = "en" },
        });

        var user = state.User;
        Assert.Equal("1700000000", user.FindFirst("iat")?.Value);
        Assert.Equal("true", user.FindFirst("email_verified")?.Value);
        Assert.Equal("false", user.FindFirst("mfa")?.Value);
        Assert.Equal("{\"locale\":\"en\"}", user.FindFirst("profile")?.Value);
    }

    // roles and scopes are expanded; any other array keeps its JSON text, because
    // the SDK has no idea what an unknown array means and inventing one claim per
    // element would be a guess.
    [Fact]
    public async Task UnknownArrayClaims_KeepTheirJsonText()
    {
        var state = await StateFor(new
        {
            sub = "user-1",
            roles = new[] { "admin" },
            scopes = new[] { "read" },
            amr = new[] { "pwd", "otp" },
        });

        var user = state.User;
        Assert.Equal(new[] { "admin" }, Roles(user));
        Assert.Equal(new[] { "read" }, Scopes(user));
        Assert.Equal("[\"pwd\",\"otp\"]", user.FindFirst("amr")?.Value);
    }

    // Non-string members of roles and scopes are skipped rather than coerced.
    [Fact]
    public async Task NonStringMembersOfRolesAndScopes_AreSkipped()
    {
        var state = await StateFor(new
        {
            sub = "user-1",
            roles = new object[] { "admin", 42 },
            scopes = new object?[] { "read", null },
        });

        Assert.Equal(new[] { "admin" }, Roles(state.User));
        Assert.Equal(new[] { "read" }, Scopes(state.User));
    }

    // A null claim is neither a string nor a number nor an array, so it lands in
    // the default arm and is carried as "null" rather than dropped.
    [Fact]
    public async Task NullClaims_AreCarriedAsTheirRawJson()
    {
        var state = await StateFor(new { sub = "user-1", middle_name = (string?)null });

        Assert.Equal("null", state.User.FindFirst("middle_name")?.Value);
    }

    [Theory]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("a.b.c.d")]
    public async Task ATokenThatIsNotThreeSegments_IsAnonymous(string token)
    {
        var store = new TokenStore(new FakeJsRuntime());
        store.SetAccessToken(token, 900);

        var state = await new VaultAuthenticationStateProvider(store).GetAuthenticationStateAsync();

        Assert.False(state.User.Identity?.IsAuthenticated);
    }

    // Base64 that decodes to something other than JSON, and base64 that does not
    // decode at all, both land in the catch and both must be anonymous rather
    // than an identity built from whatever survived.
    [Theory]
    [InlineData("aGVhZGVy.bm90LWpzb24.c2ln")]
    [InlineData("aGVhZGVy.!!!not-base64!!!.c2ln")]
    public async Task ATokenWhosePayloadWillNotParse_IsAnonymous(string token)
    {
        var store = new TokenStore(new FakeJsRuntime());
        store.SetAccessToken(token, 900);

        var state = await new VaultAuthenticationStateProvider(store).GetAuthenticationStateAsync();

        Assert.False(state.User.Identity?.IsAuthenticated);
    }

    // base64url drops the padding, so a payload whose length is 2 or 3 short of a
    // multiple of four has to have it put back before decoding. Getting this
    // wrong makes roughly half of all real tokens unparseable.
    [Theory]
    [InlineData("a")]
    [InlineData("ab")]
    [InlineData("abc")]
    [InlineData("abcd")]
    public async Task PayloadsOfEveryPaddingLength_Decode(string filler)
    {
        var state = await StateFor(new { sub = "user-1", pad = filler });

        Assert.True(state.User.Identity?.IsAuthenticated);
        Assert.Equal(filler, state.User.FindFirst("pad")?.Value);
    }

    private static string[] Roles(ClaimsPrincipal user) =>
        user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();

    private static string[] Scopes(ClaimsPrincipal user) =>
        user.FindAll("scope").Select(c => c.Value).ToArray();

    private static Task<Microsoft.AspNetCore.Components.Authorization.AuthenticationState> StateFor(object payload)
    {
        var store = new TokenStore(new FakeJsRuntime());
        store.SetAccessToken(Jwt(payload), 900);
        return new VaultAuthenticationStateProvider(store).GetAuthenticationStateAsync();
    }

    private static string Jwt(object payload)
    {
        static string Segment(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var options = new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };
        return string.Join(
            '.',
            Segment(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "JWT" })),
            Segment(JsonSerializer.SerializeToUtf8Bytes(payload, options)),
            Segment(new byte[32]));
    }
}
