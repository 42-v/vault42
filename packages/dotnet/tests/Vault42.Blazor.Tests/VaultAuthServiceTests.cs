using System.Net;
using System.Text.Json;
using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// VaultAuthService is the whole login client: it builds the authorize redirect,
/// reads the callback, exchanges the one-time code, refreshes, and logs out.
///
/// Until 1.0.3 every one of these tests passed against a service that could not
/// have signed anybody in. The suite stubbed the transport and asserted the
/// SDK's own idea of the protocol back to itself: it checked that a PKCE
/// challenge was in the authorize URL, that a state nonce round-tripped, and
/// that an authorization_code grant was POSTed to /auth/token -- none of which
/// the Vault server has ever read or served. What is asserted here now is the
/// shape the server actually accepts, and VaultBlazorOptionsTests pins the paths
/// against the route table itself.
/// </summary>
public class VaultAuthServiceTests
{
    private const string Authority = "https://vault.example.com";

    // Where the Vault's callback puts the browser: its own origin, its own path,
    // and the code in the fragment rather than the query.
    private const string CallbackPage = "https://vault.example.com/oauth/callback";

    // ---- login ----
    [Fact]
    public async Task LoginAsync_SendsTheBrowserToTheProvidersAuthorizeRoute()
    {
        var h = new Harness();

        await h.Service.LoginAsync();

        var (uri, forceLoad) = Assert.Single(h.Navigation.Navigations);
        Assert.True(forceLoad, "the authorize redirect must leave the SPA, not route inside it");
        Assert.Equal(Authority + "/auth/oauth2/authorize?provider=github", uri);
    }

    // provider is the only parameter GET /auth/oauth2/authorize reads, and it is
    // answered 400 unknown_provider without one. Sending the OAuth2 parameters
    // the SDK used to send -- response_type, client_id, redirect_uri,
    // code_challenge, state, scope -- reached exactly that 400, because none of
    // them is the one the server wants.
    [Fact]
    public async Task LoginAsync_SendsNothingTheServerDoesNotRead()
    {
        var h = new Harness();

        await h.Service.LoginAsync();

        var query = System.Web.HttpUtility.ParseQueryString(new Uri(h.Navigation.LastUri!).Query);
        Assert.Equal(new[] { "provider" }, query.AllKeys);
    }

    [Fact]
    public async Task LoginAsync_EscapesTheProviderName()
    {
        var h = new Harness(configure: o => o.Provider = "a b&c");

        await h.Service.LoginAsync();

        Assert.Equal(Authority + "/auth/oauth2/authorize?provider=a%20b%26c", h.Navigation.LastUri);
    }

    // ---- callback ----
    [Fact]
    public async Task HandleCallback_ExchangesTheCodeAndEstablishesTheSession()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-1", null, 900));

        var ok = await h.Service.HandleCallbackAsync($"{CallbackPage}#code=one-time-code");

        Assert.True(ok);
        Assert.Equal("access-1", h.Service.AccessToken);
        Assert.True(h.Service.IsAuthenticated);

        var request = Assert.Single(h.Http.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(new Uri(Authority + "/auth/oauth2/exchange"), request.Uri);
    }

    // POST /auth/oauth2/exchange decodes with DisallowUnknownFields, so anything
    // beside "code" is a 400 invalid_request. This is the assertion that stops a
    // future change from reintroducing the OAuth2-shaped body.
    [Fact]
    public async Task HandleCallback_SendsTheCodeAndNothingElse()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-1", null, 900));

        await h.Service.HandleCallbackAsync($"{CallbackPage}#code=one-time-code");

        using var body = JsonDocument.Parse(Assert.Single(h.Http.Requests).Body);
        Assert.Equal(new[] { "code" }, body.RootElement.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal("one-time-code", body.RootElement.GetProperty("code").GetString());
    }

    // The code is in the fragment on purpose: a fragment never leaves the
    // browser, so it stays out of the server's access log and out of Referer.
    // Reading the query instead finds nothing, which is what a callback landing
    // on a query-reading SDK looks like -- a silent refusal on a valid login.
    [Fact]
    public async Task HandleCallback_DoesNotReadTheCodeFromTheQueryString()
    {
        var h = new Harness();

        Assert.False(await h.Service.HandleCallbackAsync($"{CallbackPage}?code=one-time-code"));
        Assert.Empty(h.Http.Requests);
    }

    // The one error the callback redirect can carry: a first-time sign-in from a
    // provider that publishes no proof the caller owns the address.
    [Fact]
    public async Task HandleCallback_ProviderReportedError_IsRefusedWithoutAnExchange()
    {
        var h = new Harness();

        Assert.False(await h.Service.HandleCallbackAsync($"{CallbackPage}#error=verification_required"));
        Assert.Empty(h.Http.Requests);
    }

    [Theory]
    [InlineData("")]
    [InlineData("#")]
    [InlineData("#code=")]
    [InlineData("#state=only")]
    public async Task HandleCallback_WithoutACode_IsRefused(string fragment)
    {
        var h = new Harness();

        Assert.False(await h.Service.HandleCallbackAsync(CallbackPage + fragment));
        Assert.Empty(h.Http.Requests);
    }

    // A wrong-fingerprint or expired code is a 400, and the SDK cannot tell those
    // apart from a forged one -- by design, the server answers both identically.
    [Fact]
    public async Task HandleCallback_ExchangeRejects_IsRefused()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.BadRequest, "{\"error\":\"invalid_or_expired_code\"}");

        Assert.False(await h.Service.HandleCallbackAsync($"{CallbackPage}#code=one-time-code"));
        Assert.Null(h.Service.AccessToken);
    }

    // A 200 with no access_token is a broken issuer, not a session.
    [Fact]
    public async Task HandleCallback_ExchangeAnswersWithoutAnAccessToken_IsRefused()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, "{\"token_type\":\"Bearer\",\"expires_in\":900}");

        Assert.False(await h.Service.HandleCallbackAsync($"{CallbackPage}#code=one-time-code"));
        Assert.False(h.Service.IsAuthenticated);
    }

    // A Vault started with VAULT_SERVE_FRONTEND answers an unrouted POST with 200
    // and index.html, so IsSuccessStatusCode is true and the JSON reader is what
    // fails. It used to fail by throwing straight out of HandleCallbackAsync,
    // past the component that called it. It has to read as a refusal.
    /// <summary>
    /// The first two are the catch-all page, whose body fails to parse whichever media type it
    /// is labelled with. The third fails earlier and differently: a charset no encoding is
    /// registered for makes ReadFromJsonAsync throw before the parser sees a byte, which is why
    /// that needs its own arm to read as a refusal rather than as an exception thrown past the
    /// component that called this.
    /// </summary>
    [Theory]
    [InlineData("text/html", "<!doctype html><html><body>vault42</body></html>")]
    [InlineData("application/json", "<!doctype html><html><body>vault42</body></html>")]
    [InlineData("application/json; charset=utf-42", "{\"access_token\":\"access-1\",\"expires_in\":900}")]
    public async Task HandleCallback_AnUnreadableResponse_IsRefusedRatherThanThrown(
        string contentType, string body)
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, body, contentType);

        Assert.False(await h.Service.HandleCallbackAsync($"{CallbackPage}#code=one-time-code"));
        Assert.Null(h.Service.AccessToken);
    }

    // ---- refresh ----
    // POST /auth/refresh reads the refresh token only from the
    // __Host-refresh_token cookie and decodes no body at all, so the SDK holds
    // nothing and must still issue the request for the browser to attach the
    // cookie.
    [Fact]
    public async Task Refresh_UnderCookieMode_PostsToTheRefreshRouteWithNoBody()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-2", null, 900));

        Assert.True(await h.Service.RefreshAsync());

        var request = Assert.Single(h.Http.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(new Uri(Authority + "/auth/refresh"), request.Uri);
        Assert.Equal(string.Empty, request.Body);
        Assert.Equal("access-2", h.Service.AccessToken);
    }

    // The non-cookie modes only ever hold a token if something put one there.
    // A Vault never does -- its refresh token is cookie-only -- but the SDK still
    // stores a body-borne one, which is what those modes are for.
    [Fact]
    public async Task Refresh_UnderInMemoryMode_StoresARotatedTokenFromTheBody()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-2", "refresh-next", 900));

        Assert.True(await h.Service.RefreshAsync());

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
        h.Http.Enqueue(HttpStatusCode.Unauthorized, "{\"error\":\"invalid_token\"}");

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

    // The same catch-all page, on the path that used to hide it completely: the
    // JsonException went into RefreshAsync's catch and came out as an ordinary
    // "refresh failed", so a wholly misrouted SDK looked like an expired session.
    [Fact]
    public async Task Refresh_AnHtmlPageFromTheSpaCatchAll_ClearsTheSessionRatherThanThrowing()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Store.SetAccessToken("stale", 900);
        h.Http.Enqueue(HttpStatusCode.OK, "<!doctype html><html></html>", "text/html");

        Assert.False(await h.Service.RefreshAsync());
        Assert.Null(h.Service.AccessToken);
    }

    // RefreshAsync is called from two places that do not know about each other:
    // the timer ScheduleRefresh arms, and the retry path of any request that
    // gets a 401. Both firing at once sent the same refresh cookie twice, and
    // the server reads that as replay -- correctly, per RFC 9700 4.14 and with
    // no grace window here -- so it revokes the whole family and the operator's
    // token-theft alarm fires on a legitimate user.
    //
    // One request must leave the client, and both callers must get its answer.
    [Fact]
    public async Task Refresh_ConcurrentCallers_SendOneRequestAndShareItsAnswer()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        var gate = new TaskCompletionSource();
        h.Http.EnqueueGated(HttpStatusCode.OK, TokenJson("access-1", null, 900), gate.Task);

        // A second response is queued so that a client which wrongly sends two
        // requests succeeds twice rather than failing on an empty queue -- the
        // assertion has to be about the count, not about an exhausted stub.
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-2", null, 900));

        var first = h.Service.RefreshAsync();
        var second = h.Service.RefreshAsync();
        gate.SetResult();
        var results = await Task.WhenAll(first, second);

        Assert.True(results[0]);
        Assert.True(results[1]);
        Assert.Single(h.Http.Requests);
        Assert.Equal("access-1", h.Service.AccessToken);
    }

    // A refresh that follows a completed one is a new refresh, not a joined
    // one: the in-flight task is cleared when it settles, or the second call
    // would hand back a stale answer forever.
    [Fact]
    public async Task Refresh_SequentialCallers_EachSendTheirOwnRequest()
    {
        var h = new Harness(RefreshTokenStorage.InMemoryOnly);
        await h.Store.SetRefreshTokenAsync("refresh-held");
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-1", null, 900));
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-2", null, 900));

        Assert.True(await h.Service.RefreshAsync());
        Assert.True(await h.Service.RefreshAsync());

        Assert.Equal(2, h.Http.Requests.Count);
        Assert.Equal("access-2", h.Service.AccessToken);
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
    // Disposing is not signing out. The refresh timer stops and a session the app
    // can still restore is left alone.
    [Fact]
    public async Task DisposeAsync_StopsTheTimerWithoutEndingTheSession()
    {
        var h = new Harness(RefreshTokenStorage.SessionStorage);
        await h.Store.SetRefreshTokenAsync("refresh-held");

        await h.Service.DisposeAsync();

        Assert.Equal("refresh-held", h.Js.Session["vault_rt"]);
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

        Assert.Null(RefreshTimer(h.Service));
    }

    // The FAILURE path has to respect AutoRefresh too, and it did not.
    //
    // The success path has always been gated on the option; the re-arm added to
    // the catch was not. So an app that had switched automatic refresh off
    // stayed off only until the first refresh threw, after which every failed
    // retry re-entered the same catch and re-armed the timer. Measured against
    // the unfixed build: three requests to /auth/refresh in seventy seconds,
    // from an app that opted out.
    //
    // Deleting the re-arm entirely also leaves the suite green, so this asserts
    // both directions rather than only the one that was broken.
    [Fact]
    public async Task AFailedRefresh_WithAutoRefreshOff_ArmsNoTimer()
    {
        var h = new Harness(configure: o => o.AutoRefresh = false);
        await h.Store.SetRefreshTokenAsync("refresh-1");
        h.Http.EnqueueThrow(new HttpRequestException("network down"));

        Assert.False(await h.Service.RefreshAsync());
        Assert.Null(RefreshTimer(h.Service));

        await h.Service.DisposeAsync();
    }

    // And with the option on, a failure must still re-arm: that is the defect
    // the re-arm was added for -- one thrown refresh used to leave a one-shot
    // timer that never fired again, silently, while the UI still showed a
    // session.
    [Fact]
    public async Task AFailedRefresh_WithAutoRefreshOn_ReArmsTheTimer()
    {
        var h = new Harness();
        await h.Store.SetRefreshTokenAsync("refresh-1");
        h.Http.EnqueueThrow(new HttpRequestException("network down"));

        Assert.False(await h.Service.RefreshAsync());
        Assert.NotNull(RefreshTimer(h.Service));

        await h.Service.DisposeAsync();
    }

    [Fact]
    public async Task ApplyingATokenResponse_WithAutoRefreshOn_ArmsTheTimer()
    {
        var h = new Harness();
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson("access-1", null, 900));

        Assert.True(await h.Service.RefreshAsync());
        Assert.NotNull(RefreshTimer(h.Service));

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

    private static object? RefreshTimer(VaultAuthService service) =>
        typeof(VaultAuthService)
            .GetField("_refreshTimer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(service);

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
                RedirectUri = CallbackPage,
                Provider = "github",
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
