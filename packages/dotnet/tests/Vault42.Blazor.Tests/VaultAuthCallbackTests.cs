using System.Net;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.JSInterop;
using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// VaultAuthCallback is the component an application drops at its redirect URI,
/// so it is the only part of this SDK a consuming app does not write itself. It
/// had no test, and its failure path is the one that matters: a callback that
/// did not validate must not navigate anywhere, because navigating away from the
/// error state is indistinguishable from having signed in.
///
/// Rendered through a real Renderer rather than by calling OnInitializedAsync
/// with reflection, so the injected services, the lifecycle and the markup are
/// all exercised the way the framework exercises them.
/// </summary>
public class VaultAuthCallbackTests
{
    [Fact]
    public async Task ASuccessfulCallback_RaisesOnSuccessAndNavigatesToRedirectTo()
    {
        var h = new Harness();
        await h.StartLoginAsync();
        h.Navigation.Reset(h.CallbackUri(valid: true));
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson);
        var succeeded = false;

        await h.RenderAsync(new Dictionary<string, object?>
        {
            ["RedirectTo"] = "/dashboard",
            ["OnSuccess"] = EventCallback.Factory.Create(h, () => succeeded = true),
        });

        Assert.True(succeeded);
        Assert.Equal("/dashboard", h.Navigation.LastUri);
    }

    [Fact]
    public async Task AFailedCallback_RaisesOnErrorAndStaysPut()
    {
        var h = new Harness();
        await h.StartLoginAsync();
        h.Navigation.Reset(h.CallbackUri(valid: false));
        string? reported = null;

        await h.RenderAsync(new Dictionary<string, object?>
        {
            ["RedirectTo"] = "/dashboard",
            ["OnError"] = EventCallback.Factory.Create<string>(h, m => reported = m),
        });

        Assert.Equal("Authentication failed", reported);
        Assert.Null(h.Navigation.LastUri);
        Assert.Contains("Authentication failed.", await h.MarkupAsync(), StringComparison.Ordinal);
    }

    // The default is the application root, so an app that drops the component in
    // with no parameters still lands somewhere.
    [Fact]
    public async Task RedirectToDefaultsToTheApplicationRoot()
    {
        var h = new Harness();
        await h.StartLoginAsync();
        h.Navigation.Reset(h.CallbackUri(valid: true));
        h.Http.Enqueue(HttpStatusCode.OK, TokenJson);

        await h.RenderAsync(new Dictionary<string, object?>());

        Assert.Equal("/", h.Navigation.LastUri);
    }

    // Neither callback is required. A component rendered without them must still
    // complete the flow rather than throwing on an unset EventCallback.
    [Fact]
    public async Task TheCallbacksAreOptional()
    {
        var h = new Harness();
        await h.StartLoginAsync();
        h.Navigation.Reset(h.CallbackUri(valid: false));

        await h.RenderAsync(new Dictionary<string, object?>());

        Assert.Null(h.Navigation.LastUri);
    }

    [Fact]
    public async Task TheErrorStateCanBeReplacedByTheApplication()
    {
        var h = new Harness();
        await h.StartLoginAsync();
        h.Navigation.Reset(h.CallbackUri(valid: false));

        await h.RenderAsync(new Dictionary<string, object?>
        {
            ["Error"] = (RenderFragment)(builder => builder.AddContent(0, "custom failure copy")),
        });

        Assert.Contains("custom failure copy", await h.MarkupAsync(), StringComparison.Ordinal);
        Assert.DoesNotContain("Authentication failed.", await h.MarkupAsync(), StringComparison.Ordinal);
    }

    // While the exchange is in flight the component renders its processing state,
    // which is the only thing the user sees during the round trip. An app that
    // supplies its own Loading fragment gets that instead of the built-in copy.
    [Fact]
    public async Task TheProcessingStateRendersUntilTheExchangeSettles()
    {
        var h = new Harness();
        await h.StartLoginAsync();
        h.Navigation.Reset(h.CallbackUri(valid: true));
        var gate = new TaskCompletionSource();
        h.Http.EnqueueGated(HttpStatusCode.OK, TokenJson, gate.Task);

        var render = h.RenderAsync(new Dictionary<string, object?>());
        await h.WaitForMarkupAsync("Completing authentication...");

        gate.SetResult();
        await render;

        Assert.Equal("/", h.Navigation.LastUri);
    }

    [Fact]
    public async Task TheProcessingStateCanBeReplacedByTheApplication()
    {
        var h = new Harness();
        await h.StartLoginAsync();
        h.Navigation.Reset(h.CallbackUri(valid: true));
        var gate = new TaskCompletionSource();
        h.Http.EnqueueGated(HttpStatusCode.OK, TokenJson, gate.Task);

        var render = h.RenderAsync(new Dictionary<string, object?>
        {
            ["Loading"] = (RenderFragment)(builder => builder.AddContent(0, "custom loading copy")),
        });
        await h.WaitForMarkupAsync("custom loading copy");

        Assert.DoesNotContain("Completing authentication...", await h.MarkupAsync(), StringComparison.Ordinal);

        gate.SetResult();
        await render;
    }

    private const string TokenJson =
        "{\"access_token\":\"access-1\",\"token_type\":\"Bearer\",\"expires_in\":900}";

    private sealed class Harness
    {
        private readonly TestRenderer _renderer;

        internal Harness()
        {
            var options = new VaultBlazorOptions
            {
                Authority = "https://vault.example.com",
                ClientId = "blazor-app",
                RedirectUri = "https://app.example.com/auth/callback",
                AutoRefresh = false,
            };
            Js = new FakeJsRuntime();
            Http = new StubHttpMessageHandler();
            Navigation = new ResettableNavigationManager();
            var store = new TokenStore(Js, options.RefreshStorage);
            var authState = new VaultAuthenticationStateProvider(store);
            Service = new VaultAuthService(options, new HttpClient(Http), Navigation, store, authState);

            var services = new ServiceCollection();
            services.AddSingleton(Service);
            services.AddSingleton<NavigationManager>(Navigation);
            services.AddSingleton<IJSRuntime>(Js);
            _renderer = new TestRenderer(services.BuildServiceProvider());
        }

        internal FakeJsRuntime Js { get; }

        internal StubHttpMessageHandler Http { get; }

        internal ResettableNavigationManager Navigation { get; }

        internal VaultAuthService Service { get; }

        internal Task<string> MarkupAsync() => _renderer.MarkupAsync();

        /// <summary>Runs LoginAsync so the PKCE verifier and state nonce exist.</summary>
        internal async Task StartLoginAsync()
        {
            await Service.LoginAsync();
            Navigation.Reset("https://app.example.com/");
        }

        internal string CallbackUri(bool valid)
        {
            var state = valid ? Js.Session["vault_state"] : "not-the-stored-nonce";
            return $"https://app.example.com/auth/callback?code=auth-code&state={state}";
        }

        internal Task RenderAsync(Dictionary<string, object?> parameters) =>
            _renderer.RenderAsync<VaultAuthCallback>(parameters);

        /// <summary>Polls until the first render has produced the expected text.</summary>
        internal async Task WaitForMarkupAsync(string expected)
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            string markup;
            while (!(markup = await MarkupAsync()).Contains(expected, StringComparison.Ordinal))
            {
                if (DateTime.UtcNow > deadline)
                    throw new TimeoutException($"markup never contained \"{expected}\"; it was: {markup}");
                await Task.Delay(20);
            }
        }
    }

    /// <summary>
    /// The component reads NavigationManager.Uri to find the callback query, so
    /// the double has to be able to land on that URI before rendering and then
    /// record where the component navigates next.
    /// </summary>
    private sealed class ResettableNavigationManager : NavigationManager
    {
        internal ResettableNavigationManager() => Initialize("https://app.example.com/", "https://app.example.com/");

        internal string? LastUri { get; private set; }

        // NavigationManager.Initialize is one-shot, so the address the component
        // will read is set through the protected Uri setter the framework uses
        // when a real navigation lands.
        internal void Reset(string uri)
        {
            Uri = uri;
            LastUri = null;
        }

        protected override void NavigateToCore(string uri, bool forceLoad) => LastUri = uri;
    }

    /// <summary>
    /// The smallest Renderer that can host one component and read back what it
    /// produced. Blazor's own test infrastructure is not published, and a
    /// third-party component-test package would be a new dependency for one
    /// component, so the render tree is walked here instead.
    /// </summary>
    private sealed class TestRenderer : Renderer
    {
        private readonly List<Exception> _errors = new ();
        private int _rootId = -1;

        internal TestRenderer(IServiceProvider services)
            : base(services, NullLoggerFactory.Instance)
        {
        }

        public override Dispatcher Dispatcher { get; } = Dispatcher.CreateDefault();

        internal Task<string> MarkupAsync() =>
            Dispatcher.InvokeAsync(() => _rootId < 0 ? string.Empty : Render(_rootId));

        internal async Task RenderAsync<TComponent>(Dictionary<string, object?> parameters)
            where TComponent : IComponent
        {
            await Dispatcher.InvokeAsync(async () =>
            {
                var component = InstantiateComponent(typeof(TComponent));
                _rootId = AssignRootComponentId(component);
                await RenderRootComponentAsync(_rootId, ParameterView.FromDictionary(parameters));
            });

            if (_errors.Count > 0)
                throw _errors[0];
        }

        protected override void HandleException(Exception exception) => _errors.Add(exception);

        protected override Task UpdateDisplayAsync(in RenderBatch renderBatch) => Task.CompletedTask;

        private string Render(int componentId)
        {
            var sb = new System.Text.StringBuilder();
            Append(sb, componentId);
            return sb.ToString();
        }

        private void Append(System.Text.StringBuilder sb, int componentId)
        {
            var frames = GetCurrentRenderTreeFrames(componentId);
            for (var i = 0; i < frames.Count; i++)
            {
                ref var frame = ref frames.Array[i];
                switch (frame.FrameType)
                {
                    case RenderTreeFrameType.Text:
                    case RenderTreeFrameType.Markup:
                        sb.Append(frame.TextContent ?? frame.MarkupContent);
                        break;
                    case RenderTreeFrameType.Component:
                        Append(sb, frame.ComponentId);
                        break;
                }
            }
        }
    }
}
