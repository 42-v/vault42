using System.Net;
using System.Text.Json;
using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// VaultAuthService is the whole OAuth2 client: it builds the authorize
/// redirect, validates the callback, exchanges the code, refreshes, and logs
/// out. It shipped in 1.0.0 with no test touching it, which left the four
/// fail-closed branches in HandleCallbackAsync -- provider error, missing code,
/// state mismatch, missing verifier -- resting on inspection alone.
///
/// Every one of those returns false rather than throwing, and the state
/// comparison is constant-time and one-shot. A regression that made any of them
/// return true would accept a callback the app did not initiate, which is the
/// exact attack PKCE and the state nonce exist to stop.
/// </summary>
public class VaultAuthServiceTests
{
    private const string Authority = "https://vault.example.com";
    private const string RedirectUri = "https://app.example.com/auth/callback";

    // ---- login ----
    [Fact]
    public async Task LoginAsync_PersistsTheHandshakeAndLeavesTheApp()
    {
        var h = new Harness();

        await h.Service.LoginAsync();

        // Both survive the full page load only because they went to sessionStorage.
        Assert.True(h.Js.Session.ContainsKey("vault_pkce_verifier"));
        Assert.True(h.Js.Session.ContainsKey("vault_state"));

        var (uri, forceLoad) = Assert.Single(h.Navigation.Navigations);
        Assert.True(forceLoad, "the authorize redirect must leave the SPA, not route inside it");
        Assert.StartsWith(Authority + "/auth/authorize?", uri, StringComparison.Ordinal);

        var query = System.Web.HttpUtility.ParseQueryString(new Uri(uri).Query);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal("blazor-app", query["client_id"]);
        Assert.Equal(RedirectUri, query["redirect_uri"]);
        Assert.Equal("read write", query["scope"]);
        Assert.Equal(h.Js.Session["vault_state"], query["state"]);
        Assert.Equal(Pkce.ComputeChallenge(h.Js.Session["vault_pkce_verifier"]), query["code_challenge"]);
    }

    // The nonce is what binds a callback to the login that started it, so two
    // logins must not be able to reuse one.
    [Fact]
    public async Task LoginAsync_MintsAFreshStateEachTime()
    {
        var h = new Harness();

        await h.Service.LoginAsync();
        var first = h.Js.Session["vault_state"];
        await h.Service.LoginAsync();

        Assert.NotEqual(first, h.Js.Session["vault_state"]);
        Assert.Equal(64, first.Length);
    }

    // ---- callback ----
    [Fact]
    public async Task HandleCallback_ExchangesTheCodeAndEstablishesTheSession()
    {
        var h = new Harness();
        await h.Service.LoginAsync();
        var state = h.Js.Session["vault_state"];
        var verifier = h.Js.Session["vault_pkce_verifier"];
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-1", "refresh-1", 900));

        var ok = await h.Service.HandleCallbackAsync($"{RedirectUri}?code=auth-code&state={state}");

        Assert.True(ok);
        Assert.Equal("access-1", h.Service.AccessToken);
        Assert.True(h.Service.IsAuthenticated);

        var request = Assert.Single(h.Http.Requests);
        Assert.Equal(new Uri(Authority + "/auth/token"), request.Uri);
        using var body = JsonDocument.Parse(request.Body);
        Assert.Equal("authorization_code", body.RootElement.GetProperty("grant_type").GetString());
        Assert.Equal("auth-code", body.RootElement.GetProperty("code").GetString());
        Assert.Equal(verifier, body.RootElement.GetProperty("code_verifier").GetString());
        Assert.Equal(RedirectUri, body.RootElement.GetProperty("redirect_uri").GetString());

        // One-time use: neither slot survives a completed exchange.
        Assert.DoesNotContain("vault_pkce_verifier", h.Js.Session.Keys);
        Assert.DoesNotContain("vault_state", h.Js.Session.Keys);
    }

    [Fact]
    public async Task HandleCallback_ProviderReportedError_IsRefusedWithoutAnExchange()
    {
        var h = new Harness();
        await h.Service.LoginAsync();

        var ok = await h.Service.HandleCallbackAsync($"{RedirectUri}?error=access_denied");

        Assert.False(ok);
        Assert.Empty(h.Http.Requests);
    }

    [Theory]
    [InlineData("")]
    [InlineData("?state=only")]
    [InlineData("?code=only")]
    public async Task HandleCallback_WithoutBothCodeAndState_IsRefused(string query)
    {
        var h = new Harness();
        await h.Service.LoginAsync();

        Assert.False(await h.Service.HandleCallbackAsync(RedirectUri + query));
        Assert.Empty(h.Http.Requests);
    }

    // The nonce mismatch is the injected-callback case. Refusing is half of it.
    // Clearing the stored nonce is the other half, or the attacker simply retries
    // against the same value until they guess it.
    [Fact]
    public async Task HandleCallback_StateMismatch_IsRefusedAndBurnsTheNonce()
    {
        var h = new Harness();
        await h.Service.LoginAsync();

        var ok = await h.Service.HandleCallbackAsync($"{RedirectUri}?code=auth-code&state=not-the-stored-one");

        Assert.False(ok);
        Assert.DoesNotContain("vault_state", h.Js.Session.Keys);
        Assert.Empty(h.Http.Requests);
    }

    // No login was ever started, so there is nothing to compare against. This has
    // to fail closed rather than treating "nothing stored" as "anything matches".
    [Fact]
    public async Task HandleCallback_WithNoStoredState_IsRefused()
    {
        var h = new Harness();

        Assert.False(await h.Service.HandleCallbackAsync($"{RedirectUri}?code=auth-code&state=anything"));
        Assert.Empty(h.Http.Requests);
    }

    // State matched but the verifier is gone: without it the exchange cannot
    // prove possession, so it is not attempted.
    [Fact]
    public async Task HandleCallback_WithoutThePkceVerifier_IsRefused()
    {
        var h = new Harness();
        await h.Service.LoginAsync();
        var state = h.Js.Session["vault_state"];
        h.Js.Session.Remove("vault_pkce_verifier");

        Assert.False(await h.Service.HandleCallbackAsync($"{RedirectUri}?code=auth-code&state={state}"));
        Assert.Empty(h.Http.Requests);
    }

    [Fact]
    public async Task HandleCallback_TokenEndpointRejects_IsRefused()
    {
        var h = new Harness();
        await h.Service.LoginAsync();
        var state = h.Js.Session["vault_state"];
        h.Http.Enqueue(HttpStatusCode.BadRequest, "{\"error\":\"invalid_grant\"}");

        Assert.False(await h.Service.HandleCallbackAsync($"{RedirectUri}?code=auth-code&state={state}"));
        Assert.Null(h.Service.AccessToken);
    }

    // A 200 with no access_token is a broken issuer, not a session.
    [Fact]
    public async Task HandleCallback_TokenEndpointAnswersWithoutAnAccessToken_IsRefused()
    {
        var h = new Harness();
        await h.Service.LoginAsync();
        var state = h.Js.Session["vault_state"];
        h.Http.Enqueue(HttpStatusCode.OK, "{\"token_type\":\"Bearer\",\"expires_in\":900}");

        Assert.False(await h.Service.HandleCallbackAsync($"{RedirectUri}?code=auth-code&state={state}"));
        Assert.False(h.Service.IsAuthenticated);
    }

    // ---- refresh ----
    // The point of the cookie default: the SDK holds no refresh token at all, so
    // it must still issue the request and let the browser attach the cookie. A
    // "no token, no request" shortcut would break the most secure mode and only
    // that one.
    [Fact]
    public async Task Refresh_UnderCookieMode_PostsWithNoRefreshTokenInTheBody()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-2", null, 900));

        Assert.True(await h.Service.RefreshAsync());

        var request = Assert.Single(h.Http.Requests);
        Assert.DoesNotContain("\"refresh_token\":", request.Body, StringComparison.Ordinal);
        Assert.Contains("\"grant_type\":\"refresh_token\"", request.Body, StringComparison.Ordinal);
        Assert.Equal("access-2", h.Service.AccessToken);
    }

    [Fact]
    public async Task Refresh_UnderInMemoryMode_SendsTheHeldToken()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-2", "refresh-next", 900));

        Assert.True(await h.Service.RefreshAsync());

        var request = Assert.Single(h.Http.Requests);
        Assert.Contains("\"refresh_token\":\"refresh-held\"", request.Body, StringComparison.Ordinal);
        Assert.Equal("refresh-next", await h.Store.GetRefreshTokenAsync());
    }

    [Fact]
    public async Task Refresh_UnderInMemoryModeWithNothingHeld_IsANoOp()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);

        Assert.False(await h.Service.RefreshAsync());
        Assert.Empty(h.Http.Requests);
    }

    // A refused refresh means the family is gone server-side. Keeping the stale
    // access token would leave the app rendering as signed in until it expired.
    [Fact]
    public async Task Refresh_Refused_ClearsTheSession()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Store.SetAccessToken("stale", 900);
        h.Http.Enqueue(HttpStatusCode.Unauthorized, "{\"error\":\"invalid_grant\"}");

        Assert.False(await h.Service.RefreshAsync());

        Assert.Null(h.Service.AccessToken);
        Assert.Null(await h.Store.GetRefreshTokenAsync());
    }

    [Fact]
    public async Task Refresh_AnsweredWithoutAnAccessToken_ClearsTheSession()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Store.SetAccessToken("stale", 900);
        h.Http.Enqueue(HttpStatusCode.OK, "{\"expires_in\":900}");

        Assert.False(await h.Service.RefreshAsync());
        Assert.Null(h.Service.AccessToken);
    }

    // The network being down is not a logout: the token in hand is still valid
    // until it expires, so a transport failure returns false without clearing.
    [Fact]
    public async Task Refresh_TransportFailure_ReturnsFalseWithoutClearing()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Store.SetAccessToken("still-valid", 900);
        h.Http.EnqueueThrow(new HttpRequestException("connection refused"));

        Assert.False(await h.Service.RefreshAsync());
        Assert.Equal("still-valid", h.Service.AccessToken);
    }

    // ---- session restore ----
    [Fact]
    public async Task TryRestoreSession_UnderCookieMode_AlwaysAsksTheServer()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-restored", null, 900));

        Assert.True(await h.Service.TryRestoreSessionAsync());
        Assert.Single(h.Http.Requests);
    }

    // Under the other modes the SDK can see there is nothing to restore, so it
    // skips the round trip rather than provoking a 401 on every cold start.
    [Fact]
    public async Task TryRestoreSession_WithNothingHeld_SkipsTheRoundTrip()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);

        Assert.False(await h.Service.TryRestoreSessionAsync());
        Assert.Empty(h.Http.Requests);
    }

    [Fact]
    public async Task TryRestoreSession_WithAHeldToken_Refreshes()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-restored", "refresh-next", 900));

        Assert.True(await h.Service.TryRestoreSessionAsync());
        Assert.Equal("access-restored", h.Service.AccessToken);
    }

    // ---- logout ----
    [Fact]
    public async Task Logout_ClearsLocallyFirstAndTellsTheServerAfterwards()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Store.SetAccessToken("access-1", 900);
        h.Http.Enqueue(HttpStatusCode.NoContent);

        await h.Service.LogoutAsync();

        Assert.Null(h.Service.AccessToken);
        Assert.Null(await h.Store.GetRefreshTokenAsync());

        var request = Assert.Single(h.Http.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(new Uri(Authority + "/auth/logout"), request.Uri);
        Assert.Equal("Bearer access-1", request.Authorization);

        var (uri, forceLoad) = Assert.Single(h.Navigation.Navigations);
        Assert.Equal("/", uri);
        Assert.True(forceLoad);
    }

    // An unreachable server must not leave the app signed in. Local state is
    // already gone by the time the call is attempted, and the failure is
    // swallowed on purpose.
    [Fact]
    public async Task Logout_SurvivesAnUnreachableServer()
    {
        var h = new Harness();
        h.Store.SetAccessToken("access-1", 900);
        h.Http.EnqueueThrow(new HttpRequestException("connection refused"));

        await h.Service.LogoutAsync();

        Assert.Null(h.Service.AccessToken);
        Assert.Single(h.Navigation.Navigations);
    }

    [Fact]
    public async Task Logout_WithNoSession_SkipsTheServerCall()
    {
        var h = new Harness();

        await h.Service.LogoutAsync();

        Assert.Empty(h.Http.Requests);
        Assert.Single(h.Navigation.Navigations);
    }

    [Fact]
    public async Task Logout_HonoursThePostLogoutRedirectUri()
    {
        var h = new Harness(configure: o => o.PostLogoutRedirectUri = "/signed-out");

        await h.Service.LogoutAsync();

        Assert.Equal("/signed-out", h.Navigation.LastUri);
    }

    // ---- disposal ----
    // Disposing is not signing out. The refresh timer stops and the handshake
    // slots are dropped, but a session the app can still restore is left alone.
    [Fact]
    public async Task DisposeAsync_StopsTheTimerWithoutEndingTheSession()
    {
        var h = new Harness(RefreshTokenStorage.SessionStorage);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        await h.Store.SetPkceVerifierAsync("verifier");

        await h.Service.DisposeAsync();

        Assert.Equal("refresh-held", h.Js.Session["vault_rt"]);
        Assert.DoesNotContain("vault_pkce_verifier", h.Js.Session.Keys);
    }

    // AutoRefresh off means no timer is armed at all, which is the difference
    // between an app that refreshes in the background and one that refreshes on
    // demand. Both are supported; silently arming the timer either way would make
    // the option a no-op.
    [Fact]
    public async Task ApplyingATokenResponse_WithAutoRefreshOff_ArmsNoTimer()
    {
        var h = new Harness(configure: o => o.AutoRefresh = false);
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-1", null, 900));

        Assert.True(await h.Service.RefreshAsync());

        var timer = typeof(VaultAuthService)
            .GetField("_refreshTimer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(h.Service);
        Assert.Null(timer);
    }

    [Fact]
    public async Task ApplyingATokenResponse_WithAutoRefreshOn_ArmsTheTimer()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-1", null, 900));

        Assert.True(await h.Service.RefreshAsync());

        var timer = typeof(VaultAuthService)
            .GetField("_refreshTimer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(h.Service);
        Assert.NotNull(timer);

        await h.Service.DisposeAsync();
    }

    // The armed timer has to actually fire a refresh, not merely exist. The
    // schedule floors at one second, so this is the shortest honest wait: the
    // alternative is asserting that a Timer object is non-null, which is what the
    // test above already does and is not the same claim.
    [Fact]
    public async Task TheArmedTimerRefreshesWithoutBeingAsked()
    {
        var h = new Harness(configure: o => o.RefreshBeforeExpirySecs = 3600);
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-1", null, 900));
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-2", null, 900));

        Assert.True(await h.Service.RefreshAsync());
        Assert.Equal("access-1", h.Service.AccessToken);

        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (h.Service.AccessToken == "access-1" && DateTime.UtcNow < deadline)
            await Task.Delay(100);

        Assert.Equal("access-2", h.Service.AccessToken);
        await h.Service.DisposeAsync();
    }

    private static string TokenJson(string access, string? refresh, int expiresIn)
    {
        var refreshField = refresh is null ? string.Empty : $"\"refresh_token\":\"{refresh}\",";
        return $"{{\"access_token\":\"{access}\",{refreshField}\"token_type\":\"Bearer\",\"expires_in\":{expiresIn}}}";
    }

    private sealed class Harness
    {
        internal Harness(
            RefreshTokenStorage mode = RefreshTokenStorage.HttpOnlyCookieOnly,
            Action<VaultBlazorOptions>? configure = null)
        {
            Options = new VaultBlazorOptions
            {
                Authority = Authority,
                ClientId = "blazor-app",
                RedirectUri = RedirectUri,
                RefreshStorage = mode,
            };
            configure?.Invoke(Options);

            Js = new FakeJsRuntime();
            Store = new TokenStore(Js, mode);
            Navigation = new RecordingNavigationManager();
            Http = new StubHttpMessageHandler();
            AuthState = new VaultAuthenticationStateProvider(Store);
            Service = new VaultAuthService(Options, new HttpClient(Http), Navigation, Store, AuthState);
        }

        internal VaultBlazorOptions Options { get; }

        internal FakeJsRuntime Js { get; }

        internal TokenStore Store { get; }

        internal RecordingNavigationManager Navigation { get; }

        internal StubHttpMessageHandler Http { get; }

        internal VaultAuthenticationStateProvider AuthState { get; }

        internal VaultAuthService Service { get; }
    }
}
