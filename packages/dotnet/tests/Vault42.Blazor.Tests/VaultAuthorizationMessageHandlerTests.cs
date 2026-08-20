using System.Net;
using System.Text;
using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// CS-13 was asserted by calling the private IsSafeForAutoRetry predicate
/// through reflection. That proves the predicate classifies methods correctly
/// and nothing about whether SendAsync consults it: unwiring the call would
/// leave that test green and start replaying POSTs on 401. These drive the
/// handler itself.
///
/// The replay is the whole risk. An unsafe request may already have taken effect
/// server-side before the 401 was written, so retrying it can duplicate a state
/// change the caller believes happened once.
/// </summary>
public class VaultAuthorizationMessageHandlerTests
{
    [Fact]
    public async Task AttachesTheBearerTokenToOutgoingRequests()
    {
        var h = new Harness(accessToken: "access-1");
        h.Inner.Enqueue(HttpStatusCode.OK);

        await h.Invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things"), default);

        Assert.Equal("Bearer access-1", Assert.Single(h.Inner.Requests).Authorization);
    }

    // An anonymous client is a supported case: no token means no header, not an
    // empty or literal "Bearer " one.
    [Fact]
    public async Task WithoutAToken_SendsNoAuthorizationHeader()
    {
        var h = new Harness(accessToken: null);
        h.Inner.Enqueue(HttpStatusCode.OK);

        await h.Invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things"), default);

        Assert.Null(Assert.Single(h.Inner.Requests).Authorization);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public async Task SafeMethods_AreRetriedOnceAfterASuccessfulRefresh(string method)
    {
        var h = new Harness(accessToken: "access-1");
        h.Inner.Enqueue(HttpStatusCode.Unauthorized);            // the original request
        h.Refresh.Enqueue(HttpStatusCode.OK, TokenJson("access-2"));  // the refresh
        h.Inner.Enqueue(HttpStatusCode.OK);                      // the retry

        var response = await h.Invoker.SendAsync(
            new HttpRequestMessage(new HttpMethod(method), "https://api.example.com/things"), default);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, h.Inner.Requests.Count);
        Assert.Equal("Bearer access-1", h.Inner.Requests[0].Authorization);
        Assert.Equal("Bearer access-2", h.Inner.Requests[1].Authorization);
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public async Task UnsafeMethods_SurfaceThe401WithoutRetrying(string method)
    {
        var h = new Harness(accessToken: "access-1");
        h.Inner.Enqueue(HttpStatusCode.Unauthorized);

        var response = await h.Invoker.SendAsync(
            new HttpRequestMessage(new HttpMethod(method), "https://api.example.com/things")
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            },
            default);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(h.Inner.Requests);
        Assert.Empty(h.Refresh.Requests);
    }

    // Nothing was authenticated, so a 401 is the answer rather than a stale
    // token. Refreshing here would turn every anonymous 401 into a refresh
    // attempt.
    [Fact]
    public async Task A401OnAnAnonymousRequest_IsNotRetried()
    {
        var h = new Harness(accessToken: null);
        h.Inner.Enqueue(HttpStatusCode.Unauthorized);

        var response = await h.Invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things"), default);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(h.Inner.Requests);
        Assert.Empty(h.Refresh.Requests);
    }

    // One retry, not a loop. A refresh that fails leaves the caller with the
    // original 401.
    [Fact]
    public async Task WhenTheRefreshFails_TheOriginal401IsReturned()
    {
        var h = new Harness(accessToken: "access-1");
        h.Inner.Enqueue(HttpStatusCode.Unauthorized);
        h.Refresh.Enqueue(HttpStatusCode.Unauthorized, "{\"error\":\"invalid_grant\"}");

        var response = await h.Invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things"), default);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(h.Inner.Requests);
    }

    [Fact]
    public async Task NonUnauthorizedResponses_PassStraightThrough()
    {
        var h = new Harness(accessToken: "access-1");
        h.Inner.Enqueue(HttpStatusCode.Forbidden);

        var response = await h.Invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things"), default);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Single(h.Inner.Requests);
    }

    // The retry is a clone, not the original message: HttpRequestMessage cannot
    // be sent twice. A clone that dropped the headers or the body would turn a
    // retried conditional GET into an unconditional one.
    [Fact]
    public async Task TheRetryCarriesTheOriginalHeadersAndBody()
    {
        var h = new Harness(accessToken: "access-1");
        h.Inner.Enqueue(HttpStatusCode.Unauthorized);
        h.Refresh.Enqueue(HttpStatusCode.OK, TokenJson("access-2"));
        h.Inner.Enqueue(HttpStatusCode.OK);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things")
        {
            Content = new StringContent("{\"probe\":true}", Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Correlation-Id", "corr-1");

        await h.Invoker.SendAsync(request, default);

        Assert.Equal(2, h.Inner.Requests.Count);
        Assert.Equal("{\"probe\":true}", h.Inner.Requests[1].Body);
        Assert.Equal(new Uri("https://api.example.com/things"), h.Inner.Requests[1].Uri);
    }

    private static string TokenJson(string access) =>
        $"{{\"access_token\":\"{access}\",\"token_type\":\"Bearer\",\"expires_in\":900}}";

    private sealed class Harness
    {
        internal Harness(string? accessToken)
        {
            var options = new VaultBlazorOptions
            {
                Authority = "https://vault.example.com",
                ClientId = "blazor-app",
                RedirectUri = "https://app.example.com/auth/callback",
                AutoRefresh = false,
            };
            var js = new FakeJsRuntime();
            var store = new TokenStore(js);
            if (accessToken is not null)
                store.SetAccessToken(accessToken, 900);

            Refresh = new StubHttpMessageHandler();
            var authState = new VaultAuthenticationStateProvider(store);
            var service = new VaultAuthService(
                options, new HttpClient(Refresh), new RecordingNavigationManager(), store, authState);

            Inner = new StubHttpMessageHandler();
            var handler = new VaultAuthorizationMessageHandler(service) { InnerHandler = Inner };
            Invoker = new HttpMessageInvoker(handler);
        }

        internal StubHttpMessageHandler Inner { get; }

        internal StubHttpMessageHandler Refresh { get; }

        internal HttpMessageInvoker Invoker { get; }
    }
}
