using System.Net;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace Vault42.Blazor.Tests;

/// <summary>
/// An IJSRuntime that implements sessionStorage for real rather than returning
/// default for every call. RecordingJsRuntime in the hardening suite answers
/// every getItem with null, which is the right double for asserting that a call
/// was not made and the wrong one for anything that has to read back what it
/// wrote: under <see cref="RefreshTokenStorage.SessionStorage"/> the refresh
/// token round-trips through it, and a double that loses it makes a restore test
/// pass for the wrong reason.
/// </summary>
internal sealed class FakeJsRuntime : IJSRuntime
{
    internal Dictionary<string, string> Session { get; } = new (StringComparer.Ordinal);

    internal List<string> Calls { get; } = new ();

    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
    {
        Calls.Add(identifier);
        var a = args ?? Array.Empty<object?>();

        switch (identifier)
        {
            case "sessionStorage.setItem":
                Session[(string)a[0]!] = (string)a[1]!;
                break;
            case "sessionStorage.removeItem":
                Session.Remove((string)a[0]!);
                break;
            case "sessionStorage.getItem":
                if (Session.TryGetValue((string)a[0]!, out var stored) && stored is TValue typed)
                    return ValueTask.FromResult(typed);
                break;
        }

        return ValueTask.FromResult<TValue>(default!);
    }

    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args) =>
        InvokeAsync<TValue>(identifier, args);
}

/// <summary>
/// NavigationManager is abstract and its only observable effect in this SDK is
/// the URI it is asked to go to, so the double records that instead of
/// navigating. Both places the SDK navigates -- the authorize redirect and the
/// post-logout redirect -- pass forceLoad, which is recorded too: a login that
/// navigated without it would stay inside the SPA and never reach the Vault.
/// </summary>
internal sealed class RecordingNavigationManager : NavigationManager
{
    internal RecordingNavigationManager(string uri = "https://app.example.com/")
    {
        Initialize("https://app.example.com/", uri);
    }

    internal List<(string Uri, bool ForceLoad)> Navigations { get; } = new ();

    internal string? LastUri => Navigations.Count == 0 ? null : Navigations[^1].Uri;

    protected override void NavigateToCore(string uri, bool forceLoad)
    {
        Navigations.Add((uri, forceLoad));
    }
}

/// <summary>
/// Answers each request from a queue and keeps every request it was given,
/// including the body, so a test can assert what was actually sent rather than
/// only what came back. An empty queue is a failure and not a default response:
/// a test that expected one call and provoked two should say so.
/// </summary>
internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<Func<HttpRequestMessage, Task<HttpResponseMessage>>> _responses = new ();

    internal List<(HttpMethod Method, Uri? Uri, string Body, string? Authorization)> Requests { get; } = new ();

    /// <summary>
    /// Queues one canned response. <paramref name="contentType"/> exists because a Vault serving
    /// its own SPA answers an unrouted POST from the catch-all, with 200 and an HTML page: the
    /// media type is part of what the SDK has to survive, and a stub that labels everything
    /// application/json cannot reproduce it.
    /// </summary>
    internal StubHttpMessageHandler Enqueue(
        HttpStatusCode status, string body = "", string contentType = "application/json")
    {
        _responses.Enqueue(_ => Task.FromResult(Response(status, body, contentType)));
        return this;
    }

    /// <summary>
    /// Queues a response that does not arrive until <paramref name="gate"/> completes.
    /// </summary>
    /// <remarks>
    /// The wait is awaited rather than blocked on, because the component tests drive this from
    /// Blazor's render dispatcher and blocking that thread deadlocks the renderer against the
    /// test that is waiting for it to produce markup.
    /// </remarks>
    internal StubHttpMessageHandler EnqueueGated(HttpStatusCode status, string body, Task gate)
    {
        _responses.Enqueue(async _ =>
        {
            await gate;
            return Response(status, body, "application/json");
        });
        return this;
    }

    internal StubHttpMessageHandler EnqueueThrow(Exception ex)
    {
        _responses.Enqueue(_ => throw ex);
        return this;
    }

    private static HttpResponseMessage Response(HttpStatusCode status, string body, string contentType)
    {
        var content = new StringContent(body, System.Text.Encoding.UTF8);

        // Assigned rather than passed to the constructor, whose mediaType overload rejects a
        // value carrying parameters. A charset is one of the things the SDK has to survive
        // being handed, so the double has to be able to send one.
        content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType);
        return new HttpResponseMessage(status) { Content = content };
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);

        Requests.Add((request.Method, request.RequestUri, body, request.Headers.Authorization?.ToString()));

        if (_responses.Count == 0)
            throw new InvalidOperationException($"unexpected request: {request.Method} {request.RequestUri}");

        return await _responses.Dequeue()(request);
    }
}
