using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Vault42.AspNetCore;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// The handler is the package: every request an application authenticates goes
/// through HandleAuthenticateAsync, and the note left in the hardening suite
/// said the functional path was covered by integration tests and asserted the
/// source-level invariants instead. There are no integration tests for this
/// package, so the eight refusal branches -- oversized, unreadable, jku/x5u/
/// x5c/jwk, missing kid, unknown kid, wrong issuer, wrong audience, expired,
/// wrong algorithm, wrong token_type, fingerprint mismatch -- were asserted by
/// nothing at all.
///
/// These drive the real handler through AuthenticateAsync and ChallengeAsync.
/// </summary>
[Collection(ClaimMapCollection.Name)]
public class VaultAuthenticationHandlerTests
{
    // ---- no token ----
    // NoResult, not Fail: an unauthenticated request must leave other schemes a
    // turn rather than terminating the chain.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Bearer ")]
    [InlineData("Bearer    ")]
    public async Task RequestsWithoutABearerToken_ProduceNoResult(string? authorization)
    {
        var h = await Fixture.CreateAsync();

        var (result, _) = await h.AuthenticateAsync(authorization);

        Assert.False(result.Succeeded);
        Assert.False(result.Failure is not null, "an absent token is not a failure");
        Assert.True(result.None);
    }

    [Fact]
    public async Task AValidToken_AuthenticatesAndCarriesItsClaims()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Roles, "[\"user\",\"admin\"]", JsonClaimValueTypes.JsonArray),
            new Claim(VaultClaimTypes.Scopes, "[\"read\",\"write\"]", JsonClaimValueTypes.JsonArray),
            new Claim(VaultClaimTypes.ClientId, "blazor-app"),
        });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.True(result.Succeeded, result.Failure?.Message);
        var user = result.Principal;
        Assert.Equal("user-1", user.GetUserId());
        Assert.Equal(new[] { "user", "admin" }, user.GetRoles());
        Assert.Equal(new[] { "read", "write" }, user.GetScopes());
        Assert.Equal("blazor-app", user.GetClientId());
        Assert.True(user.HasScope("read"));
        Assert.True(user.HasVaultRole("admin"));
    }

    // ---- rejection paths ----
    [Fact]
    public async Task ATokenOverTheSizeLimit_IsRefusedBeforeItIsParsed()
    {
        var h = await Fixture.CreateAsync(o => o.MaxTokenSize = 64);

        var (result, _) = await h.AuthenticateAsync($"Bearer {h.Signer.Token()}");

        Assert.Equal("Token exceeds maximum size", result.Failure?.Message);
    }

    [Theory]
    [InlineData("not-a-jwt")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    public async Task AMalformedToken_IsRefusedAsAFormatError(string token)
    {
        var h = await Fixture.CreateAsync();

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.Equal("Invalid token format", result.Failure?.Message);
    }

    // The whole class of key-injection attacks. Each of these headers nominates a
    // key or a key location, and honouring any of them lets the caller choose
    // what verifies their own token.
    [Theory]
    [InlineData("jku")]
    [InlineData("x5u")]
    [InlineData("x5c")]
    [InlineData("jwk")]
    public async Task TokensNominatingTheirOwnKey_AreRefused(string header)
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.TokenWithHeader(header, "https://attacker.example.com/keys.json");

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.Equal($"Rejected header: {header}", result.Failure?.Message);
    }

    // CanReadToken accepts three dot-separated segments whose header decodes as
    // JSON; ReadJwtToken then parses the payload and throws on one that does not.
    // Both are "invalid token format" to the caller.
    [Fact]
    public async Task ATokenWhoseHeaderReadsButWhosePayloadDoesNot_IsRefusedAsAFormatError()
    {
        var h = await Fixture.CreateAsync();
        const string headerOnly = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";

        var (result, _) = await h.AuthenticateAsync($"Bearer {headerOnly}.bm90LWpzb24.c2ln");

        Assert.Equal("Invalid token format", result.Failure?.Message);
    }

    // A token with no kid names no key. Falling back to "the only key we have"
    // would make key rotation unverifiable, so it is refused outright.
    [Fact]
    public async Task ATokenWithNoKidHeader_IsRefused()
    {
        var h = await Fixture.CreateAsync();

        var (result, _) = await h.AuthenticateAsync($"Bearer {h.Signer.TokenWithoutKid()}");

        Assert.Equal("Missing kid header", result.Failure?.Message);
    }

    [Fact]
    public async Task ATokenSignedByAnUnknownKey_IsRefused()
    {
        var h = await Fixture.CreateAsync();
        using var stranger = new TestSigner("kid-stranger");

        var (result, _) = await h.AuthenticateAsync($"Bearer {stranger.Token(kid: "kid-stranger")}");

        Assert.Equal("Unknown signing key", result.Failure?.Message);
    }

    // CS-3: the reason never reaches the caller. Expiry, a bad signature and the
    // wrong issuer are indistinguishable from outside, so the response cannot be
    // used to probe why a token was refused.
    [Fact]
    public async Task AnExpiredToken_IsRefusedWithTheGenericReason()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(lifetime: TimeSpan.FromMinutes(-10));

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.Equal("invalid_token", result.Failure?.Message);
    }

    [Fact]
    public async Task AWrongIssuerToken_IsRefusedWithTheSameGenericReason()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(issuer: "https://other-issuer.example.com");

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.Equal("invalid_token", result.Failure?.Message);
    }

    [Fact]
    public async Task AWrongAudienceToken_IsRefusedWithTheSameGenericReason()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(audience: "api://someone-else");

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.Equal("invalid_token", result.Failure?.Message);
    }

    // 30 seconds of skew is allowed on purpose, so a clock a few seconds behind
    // does not reject every token.
    [Fact]
    public async Task ATokenJustInsideTheClockSkew_IsAccepted()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(lifetime: TimeSpan.FromSeconds(-5));

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.True(result.Succeeded, result.Failure?.Message);
    }

    // CS-4. The 2fa_challenge token issued between the password step and the
    // second factor is a real, correctly signed, unexpired Vault token. Only
    // token_type separates it from an access token, so a missing claim is
    // refused the same as a wrong one.
    [Theory]
    [InlineData("")]
    [InlineData("2fa_challenge")]
    [InlineData("bearer")]
    public async Task TokensThatAreNotBearerAccessTokens_AreRefused(string tokenType)
    {
        var h = await Fixture.CreateAsync();

        var (result, _) = await h.AuthenticateAsync($"Bearer {h.Signer.Token(tokenType: tokenType)}");

        Assert.Equal("Invalid token type", result.Failure?.Message);
    }

    // ---- claim mapping ----
    [Fact]
    public async Task MappingCanBeTurnedOffIndependentlyForRolesAndScopes()
    {
        var h = await Fixture.CreateAsync(o =>
        {
            o.MapRolesToClaims = false;
            o.MapScopesToClaims = true;
        });
        var token = h.Signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Roles, "[\"admin\"]", JsonClaimValueTypes.JsonArray),
            new Claim(VaultClaimTypes.Scopes, "[\"read\"]", JsonClaimValueTypes.JsonArray),
        });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.Empty(result.Principal.GetRoles());
        Assert.Equal(new[] { "read" }, result.Principal.GetScopes());
    }

    // A scalar where an array belongs is a malformed token, not a reason to
    // refuse a signature that verified. It maps to nothing, which fails closed.
    //
    // Roles are the exception and not by this handler's choice:
    // JwtSecurityTokenHandler's default inbound map rewrites any "roles" claim to
    // ClaimTypes.Role during validation, scalar included, and the mapped claim is
    // already on the principal before MapClaims runs.
    [Fact]
    public async Task ScalarsWhereAnArrayBelongs_MapToNothing()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Scopes, "read"),
        });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.Empty(result.Principal.GetScopes());
    }

    // The regression that motivated reading the payload instead of the flattened
    // claim collection. A single-element array is one Claim whose value is the
    // element, indistinguishable from a scalar unless the array is read where it
    // is still an array.
    [Fact]
    public async Task ASingleElementScopesArray_StillMaps()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Scopes, "[\"read\"]", JsonClaimValueTypes.JsonArray),
        });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.Equal(new[] { "read" }, result.Principal.GetScopes());
        Assert.True(result.Principal.HasScope("read"));
    }

    // Non-string members are skipped rather than coerced, so a token mixing types
    // grants only the scopes it actually names.
    [Fact]
    public async Task NonStringArrayMembers_AreSkipped()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Scopes, "[\"read\",42,null]", JsonClaimValueTypes.JsonArray),
        });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.Equal(new[] { "read" }, result.Principal.GetScopes());
    }

    // Roles arrive twice: once through the inbound claim map as ClaimTypes.Role,
    // once through MapClaims reading the payload. The identity must not end up
    // holding each role twice.
    //
    // The reverse case -- an application that clears
    // JwtSecurityTokenHandler.DefaultInboundClaimTypeMap, which is a common way
    // to stop the library renaming claims -- is covered by
    // InboundClaimMapClearedTests, where MapClaims is the only thing left
    // mapping them.
    [Fact]
    public async Task RolesAreNotDuplicatedByTheTwoMappingRoutes()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Roles, "[\"admin\"]", JsonClaimValueTypes.JsonArray),
        });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.Equal(new[] { "admin" }, result.Principal.GetRoles());
    }

    [Fact]
    public async Task ATokenWithNoRolesOrScopes_StillAuthenticates()
    {
        var h = await Fixture.CreateAsync();

        var (result, _) = await h.AuthenticateAsync($"Bearer {h.Signer.Token()}");

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.Empty(result.Principal.GetRoles());
    }

    // ---- fingerprint ----
    [Fact]
    public async Task FingerprintValidation_AcceptsAMatchingRequest()
    {
        var h = await Fixture.CreateAsync(o => o.ValidateFingerprint = true);
        var expected = VaultFingerprintValidator.ComputeFingerprint(
            "203.0.113.7", "probe-agent", "en-GB", string.Empty);
        var token = h.Signer.Token(extraClaims: new[] { new Claim(VaultClaimTypes.Fingerprint, expected) });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}", ctx =>
        {
            ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");
            ctx.Request.Headers.UserAgent = "probe-agent";
            ctx.Request.Headers.AcceptLanguage = "en-GB";
        });

        Assert.True(result.Succeeded, result.Failure?.Message);
    }

    [Fact]
    public async Task FingerprintValidation_RefusesAStolenTokenReplayedElsewhere()
    {
        var h = await Fixture.CreateAsync(o => o.ValidateFingerprint = true);
        var boundElsewhere = VaultFingerprintValidator.ComputeFingerprint(
            "198.51.100.9", "probe-agent", "en-GB", string.Empty);
        var token = h.Signer.Token(extraClaims: new[] { new Claim(VaultClaimTypes.Fingerprint, boundElsewhere) });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}", ctx =>
        {
            ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");
            ctx.Request.Headers.UserAgent = "probe-agent";
            ctx.Request.Headers.AcceptLanguage = "en-GB";
        });

        Assert.Equal("Fingerprint mismatch", result.Failure?.Message);
    }

    // The claim is optional. A token issued before fingerprinting was enabled
    // carries none, and the documented behaviour is to skip the check rather than
    // reject the token.
    [Fact]
    public async Task FingerprintValidation_SkipsATokenThatCarriesNoClaim()
    {
        var h = await Fixture.CreateAsync(o => o.ValidateFingerprint = true);

        var (result, _) = await h.AuthenticateAsync($"Bearer {h.Signer.Token()}");

        Assert.True(result.Succeeded, result.Failure?.Message);
    }

    // Off by default, so a mismatched claim is not consulted at all.
    [Fact]
    public async Task FingerprintValidation_IsNotAppliedWhenDisabled()
    {
        var h = await Fixture.CreateAsync();
        var token = h.Signer.Token(extraClaims: new[]
        {
            new Claim(VaultClaimTypes.Fingerprint, new string('0', 64)),
        });

        var (result, _) = await h.AuthenticateAsync($"Bearer {token}");

        Assert.True(result.Succeeded, result.Failure?.Message);
    }

    // ---- challenge ----
    [Fact]
    public async Task ChallengingAnApiClient_Produces401WithAWwwAuthenticateHeader()
    {
        var h = await Fixture.CreateAsync();

        var context = await h.ChallengeAsync(accept: "application/json", path: "/orders");

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(
            $"Bearer realm=\"{TestSigner.Issuer}\"",
            context.Response.Headers.WWWAuthenticate.ToString());
        Assert.False(context.Response.Headers.ContainsKey("Location"));
    }

    [Fact]
    public async Task ChallengingABrowser_RedirectsToLoginWithTheReturnUrl()
    {
        var h = await Fixture.CreateAsync();

        var context = await h.ChallengeAsync(accept: "text/html", path: "/orders", query: "?page=2");

        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        Assert.Equal(
            "/login?returnUrl=%2Forders%3Fpage%3D2",
            context.Response.Headers.Location.ToString());
    }

    // CS-2: the exemption is boundary-aware, so /login does not exempt
    // /login-other-route. Redirecting the login page to itself is a loop; not
    // redirecting a route that merely starts with the same letters is the bug the
    // boundary check exists for.
    [Theory]
    [InlineData("/login", false)]
    [InlineData("/login/reset", false)]
    [InlineData("/_blazor/negotiate", false)]
    [InlineData("/_framework/blazor.boot.json", false)]
    [InlineData("/_content/pkg/style.css", false)]
    [InlineData("/healthz", false)]
    [InlineData("/login-other-route", true)]
    [InlineData("/healthz-internal", true)]
    [InlineData("/orders", true)]
    public async Task BrowserChallenges_RedirectOnlyOutsideTheExemptPrefixes(string path, bool expectRedirect)
    {
        var h = await Fixture.CreateAsync();

        var context = await h.ChallengeAsync(accept: "text/html", path: path);

        Assert.Equal(
            expectRedirect ? StatusCodes.Status302Found : StatusCodes.Status401Unauthorized,
            context.Response.StatusCode);
    }

    [Fact]
    public async Task TheLoginPathIsConfigurable()
    {
        var h = await Fixture.CreateAsync(o => o.LoginPath = "/account/sign-in");

        var redirected = await h.ChallengeAsync(accept: "text/html", path: "/orders");
        var exempt = await h.ChallengeAsync(accept: "text/html", path: "/account/sign-in");

        Assert.StartsWith("/account/sign-in?returnUrl=", redirected.Response.Headers.Location.ToString(), StringComparison.Ordinal);
        Assert.Equal(StatusCodes.Status401Unauthorized, exempt.Response.StatusCode);
    }

    private sealed class Fixture : IDisposable
    {
        private Fixture(TestSigner signer, VaultAuthenticationOptions options, VaultJwksManager jwks)
        {
            Signer = signer;
            _options = options;
            _jwks = jwks;
        }

        private readonly VaultAuthenticationOptions _options;
        private readonly VaultJwksManager _jwks;

        internal TestSigner Signer { get; }

        internal static async Task<Fixture> CreateAsync(Action<VaultAuthenticationOptions>? configure = null)
        {
            var signer = new TestSigner();
            var options = new VaultAuthenticationOptions
            {
                Authority = TestSigner.Issuer,

                // The forced refresh on an unknown kid would otherwise reach for
                // a second canned response the stub does not hold.
                RefreshOnUnknownKid = false,
            };
            configure?.Invoke(options);

            var http = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, signer.JwksJson());
            var jwks = new VaultJwksManager(new HttpClient(http), options);
            await jwks.InitializeAsync();

            return new Fixture(signer, options, jwks);
        }

        internal Task<(Microsoft.AspNetCore.Authentication.AuthenticateResult Result, HttpContext Context)> AuthenticateAsync(
            string? authorization,
            Action<HttpContext>? configureRequest = null) =>
            HandlerHarness.AuthenticateAsync(_options, _jwks, ctx =>
            {
                if (authorization is not null)
                    ctx.Request.Headers.Authorization = authorization;
                configureRequest?.Invoke(ctx);
            });

        internal Task<HttpContext> ChallengeAsync(string accept, string path, string query = "") =>
            HandlerHarness.ChallengeAsync(_options, _jwks, ctx =>
            {
                ctx.Request.Headers.Accept = accept;
                ctx.Request.Path = path;
                ctx.Request.QueryString = new QueryString(query);
            });

        public void Dispose()
        {
            _jwks.Dispose();
            Signer.Dispose();
        }
    }
}
