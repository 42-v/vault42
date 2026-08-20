using System.Net.Http.Json;
using Microsoft.AspNetCore.Components;
using Vault42.Blazor.Internal;

namespace Vault42.Blazor;

/// <summary>
/// Core authentication service for Vault Blazor apps.
/// Drives the Vault server's social-login flow: redirect to the server's authorize route, then
/// exchange the one-time code it hands back for an access token.
/// </summary>
/// <remarks>
/// The Vault server runs the OAuth2 authorization-code + PKCE dance with the upstream identity
/// provider itself, under its own registration. The browser side of it has no client, no scope
/// negotiation and no code challenge: the app sends the user to
/// <see cref="VaultBlazorOptions.AuthorizePath"/> with a provider name, the server bounces through
/// the IdP, and the callback lands back on the app with a one-time code in the URI fragment. That
/// code is exchanged for an access token at <see cref="VaultBlazorOptions.ExchangePath"/>.
/// </remarks>
public sealed class VaultAuthService : IAsyncDisposable
{
    private readonly VaultBlazorOptions _options;
    private readonly HttpClient _httpClient;
    private readonly NavigationManager _navigation;
    private readonly TokenStore _store;
    private readonly VaultAuthenticationStateProvider _authState;
    private Timer? _refreshTimer;

    internal VaultAuthService(
        VaultBlazorOptions options,
        HttpClient httpClient,
        NavigationManager navigation,
        TokenStore store,
        VaultAuthenticationStateProvider authState)
    {
        _options = options;
        _httpClient = httpClient;
        _navigation = navigation;
        _store = store;
        _authState = authState;
    }

    /// <summary>
    /// Gets the current access token, or null if not authenticated.
    /// </summary>
    public string? AccessToken => _store.AccessToken;

    /// <summary>
    /// Gets a value indicating whether whether the user has a valid (non-expired) access token.
    /// </summary>
    public bool IsAuthenticated => _store.IsAccessTokenValid;

    /// <summary>
    /// Initiate login by redirecting to the Vault authorization endpoint for
    /// <see cref="VaultBlazorOptions.Provider"/>.
    /// </summary>
    /// <returns>
    /// A completed task. It does not represent a completed login: the browser leaves the app, and
    /// the flow resumes in <see cref="HandleCallbackAsync"/> on the redirect back.
    /// </returns>
    /// <remarks>
    /// <para>Nothing is persisted before navigating, because there is nothing on this side of the
    /// flow to carry across the page load. The CSRF binding is the server's: it mints an
    /// HMAC-signed state carrying the hash of a <c>__Host-oauth_state</c> cookie it sets on this
    /// redirect, and the callback refuses a state whose hash does not match the cookie the browser
    /// presents. A nonce minted here could not participate -- the callback redirect carries no
    /// state back to the app -- so generating one would be theatre.</para>
    /// <para>The same goes for PKCE. The server generates the verifier it sends to the IdP and
    /// keeps it server-side; a challenge computed in the browser has no counterparty.</para>
    /// </remarks>
    public Task LoginAsync()
    {
        var authorizeUrl = $"{_options.EffectiveAuthority}{_options.AuthorizePath}" +
            $"?provider={Uri.EscapeDataString(_options.Provider)}";

        _navigation.NavigateTo(authorizeUrl, forceLoad: true);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Handle the callback after Vault redirects back with a one-time exchange code.
    /// </summary>
    /// <param name="callbackUri">
    /// The full redirect URI the browser landed on, including its fragment. Pass
    /// <c>NavigationManager.Uri</c> unmodified.
    /// </param>
    /// <returns>True if authentication succeeded, false on error.</returns>
    /// <remarks>
    /// <para>The code arrives in the URI <em>fragment</em>, not the query string, because a
    /// fragment is never sent to a server: it stays out of access logs, out of the Referer header
    /// and out of any proxy in between. Reading the query instead would find nothing.</para>
    /// <para>Every failure path returns false rather than throwing, including a provider-reported
    /// error and a missing code. Callers must treat false as "not signed in" and must not infer a
    /// reason from it. A false here does not always mean the callback was hostile: the exchange
    /// code is stored under a key that includes the request fingerprint, so a client whose address,
    /// User-Agent or Accept-Language changed between the callback and the exchange is refused
    /// exactly like a forged code.</para>
    /// </remarks>
    public async Task<bool> HandleCallbackAsync(string callbackUri)
    {
        var uri = new Uri(callbackUri);
        var fragment = System.Web.HttpUtility.ParseQueryString(uri.Fragment.TrimStart('#'));

        if (!string.IsNullOrEmpty(fragment["error"]))
            return false;

        var code = fragment["code"];
        if (string.IsNullOrEmpty(code))
            return false;

        var exchangeUrl = $"{_options.EffectiveAuthority}{_options.ExchangePath}";
        var response = await _httpClient.PostAsJsonAsync(exchangeUrl, new ExchangeRequest { Code = code });
        if (!response.IsSuccessStatusCode)
            return false;

        var tokenResponse = await ReadTokenResponseAsync(response);
        if (tokenResponse is null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            return false;

        await ApplyTokenResponseAsync(tokenResponse);
        return true;
    }

    /// <summary>
    /// Refresh the access token.
    /// </summary>
    /// <returns>True if refresh succeeded.</returns>
    /// <remarks>
    /// The request carries no body. <c>POST /auth/refresh</c> reads the refresh token only from the
    /// <c>__Host-refresh_token</c> cookie the browser attaches, so under
    /// <see cref="RefreshTokenStorage.HttpOnlyCookieOnly"/> the SDK holds nothing and must still
    /// issue the request. Under the other two modes it can see it holds nothing and skips the round
    /// trip -- but note that against a Vault server those modes are never given a token to hold,
    /// because the refresh token is only ever a cookie.
    /// </remarks>
    public async Task<bool> RefreshAsync()
    {
        var refreshToken = await _store.GetRefreshTokenAsync();

        // CS-10/CS-11: under HttpOnlyCookieOnly, the SDK has no in-memory refresh
        // token (the server holds it in the cookie). Still issue the request -- the
        // browser will attach the cookie. For other modes, missing refresh = no-op.
        if (string.IsNullOrEmpty(refreshToken)
            && _store.RefreshMode != RefreshTokenStorage.HttpOnlyCookieOnly)
        {
            return false;
        }

        var refreshUrl = $"{_options.EffectiveAuthority}{_options.RefreshPath}";
        try
        {
            var response = await _httpClient.PostAsync(refreshUrl, content: null);
            if (!response.IsSuccessStatusCode)
            {
                await _store.ClearAllAsync();
                _authState.NotifyStateChanged();
                return false;
            }

            var tokenResponse = await ReadTokenResponseAsync(response);
            if (tokenResponse is null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                await _store.ClearAllAsync();
                _authState.NotifyStateChanged();
                return false;
            }

            await ApplyTokenResponseAsync(tokenResponse);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Try to restore a session from a stored refresh token (call on app startup).
    /// Under <see cref="RefreshTokenStorage.HttpOnlyCookieOnly"/>, this always
    /// attempts a refresh -- the SDK can't introspect the cookie, so we ask the
    /// server. Under other modes, we skip the round-trip when no token is held.
    /// </summary>
    /// <returns>True if a session was restored.</returns>
    public async Task<bool> TryRestoreSessionAsync()
    {
        if (_store.RefreshMode != RefreshTokenStorage.HttpOnlyCookieOnly)
        {
            var refreshToken = await _store.GetRefreshTokenAsync();
            if (string.IsNullOrEmpty(refreshToken))
                return false;
        }

        return await RefreshAsync();
    }

    /// <summary>
    /// Log out -- clears all tokens and optionally calls the Vault logout endpoint.
    /// </summary>
    /// <returns>A task that completes once local state is cleared and navigation away has been requested.</returns>
    /// <remarks>
    /// Local tokens are cleared and the refresh timer stopped before the server is told anything,
    /// so a server that is unreachable still leaves the app signed out. The server call is
    /// best-effort and its failure is swallowed, which means the session may survive server-side
    /// even though this returned successfully.
    /// </remarks>
    public async Task LogoutAsync()
    {
        var accessToken = _store.AccessToken;
        await _store.ClearAllAsync();
        _authState.NotifyStateChanged();
        StopRefreshTimer();

        // Best-effort server logout
        if (!string.IsNullOrEmpty(accessToken))
        {
            try
            {
                var logoutUrl = $"{_options.EffectiveAuthority}{_options.LogoutPath}";
                var request = new HttpRequestMessage(HttpMethod.Post, logoutUrl);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                await _httpClient.SendAsync(request);
            }
            catch
            { /* best-effort */
            }
        }

        _navigation.NavigateTo(_options.PostLogoutRedirectUri, forceLoad: true);
    }

    /// <summary>
    /// Reads the token payload, treating a body that is not the JSON object this SDK expects as a
    /// failed call rather than an exception.
    /// </summary>
    /// <remarks>
    /// A Vault server started with <c>VAULT_SERVE_FRONTEND</c> serves the SPA from a catch-all, so
    /// a POST to a path it does not route is answered 200 with <c>index.html</c>. The status check
    /// passes and the JSON reader throws, which is how the 1.0.2 endpoint defaults produced a login
    /// that failed with no diagnostic at all: the exception escaped the callback uncaught and was
    /// swallowed whole by the refresh path's catch. Returning null keeps a misrouted response on
    /// the same footing as a refusal.
    /// </remarks>
    private static async Task<TokenResponse?> ReadTokenResponseAsync(HttpResponseMessage response)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<TokenResponse>();
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            // What ReadFromJsonAsync raises, ahead of the parser and so not as a JsonException,
            // when Content-Type names a charset no encoding is registered for. Without this arm a
            // single mislabelled response is an exception thrown past the callback component
            // rather than a refused login.
            return null;
        }
    }

    private async Task ApplyTokenResponseAsync(TokenResponse response)
    {
        _store.SetAccessToken(response.AccessToken, response.ExpiresIn);

        if (!string.IsNullOrEmpty(response.RefreshToken))
            await _store.SetRefreshTokenAsync(response.RefreshToken);

        _authState.NotifyStateChanged();

        if (_options.AutoRefresh)
            ScheduleRefresh(response.ExpiresIn);
    }

    private void ScheduleRefresh(int expiresInSeconds)
    {
        StopRefreshTimer();
        var refreshInMs = Math.Max(1000, (expiresInSeconds - _options.RefreshBeforeExpirySecs) * 1000);
        _refreshTimer = new Timer(
            async _ =>
        {
            await RefreshAsync();
        }, null, refreshInMs, Timeout.Infinite);
    }

    private void StopRefreshTimer()
    {
        _refreshTimer?.Dispose();
        _refreshTimer = null;
    }

    /// <summary>
    /// Stops the background refresh timer.
    /// </summary>
    /// <returns>A completed task once the timer is stopped.</returns>
    /// <remarks>
    /// This does not sign the user out. Tokens persisted in browser storage survive disposal, so a
    /// later <see cref="TryRestoreSessionAsync"/> can pick the session back up. Call
    /// <see cref="LogoutAsync"/> when the intent is to end the session. The service is registered
    /// as a singleton by <c>AddVaultAuth</c>, so in a normal app the container owns this call.
    /// </remarks>
    public ValueTask DisposeAsync()
    {
        StopRefreshTimer();
        return ValueTask.CompletedTask;
    }
}
