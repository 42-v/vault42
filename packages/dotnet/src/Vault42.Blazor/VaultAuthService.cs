using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Components;
using Vault42.Blazor.Internal;

namespace Vault42.Blazor;

/// <summary>
/// Core authentication service for Vault Blazor apps.
/// Handles OAuth2 Authorization Code + PKCE flow with redirect to Vault's integrated frontend.
/// </summary>
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
    /// Initiate login by redirecting to the Vault authorization endpoint.
    /// Generates PKCE challenge and state, stores them in sessionStorage,
    /// then navigates the browser to Vault's login page.
    /// </summary>
    public async Task LoginAsync()
    {
        var verifier = Pkce.GenerateVerifier();
        var challenge = Pkce.ComputeChallenge(verifier);
        var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

        await _store.SetPkceVerifierAsync(verifier);
        await _store.SetStateAsync(state);

        var scope = string.Join(" ", _options.Scopes);
        var authorizeUrl = $"{_options.EffectiveAuthority}{_options.AuthorizePath}" +
            $"?response_type=code" +
            $"&client_id={Uri.EscapeDataString(_options.ClientId)}" +
            $"&redirect_uri={Uri.EscapeDataString(_options.RedirectUri)}" +
            $"&code_challenge={Uri.EscapeDataString(challenge)}" +
            $"&code_challenge_method=S256" +
            $"&state={Uri.EscapeDataString(state)}" +
            $"&scope={Uri.EscapeDataString(scope)}";

        _navigation.NavigateTo(authorizeUrl, forceLoad: true);
    }

    /// <summary>
    /// Handle the callback after Vault redirects back with an authorization code.
    /// Validates state, exchanges code for tokens via PKCE, and establishes the session.
    /// </summary>
    /// <returns>True if authentication succeeded, false on error.</returns>
    public async Task<bool> HandleCallbackAsync(string callbackUri)
    {
        var uri = new Uri(callbackUri);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);

        var code = query["code"];
        var returnedState = query["state"];
        var error = query["error"];

        if (!string.IsNullOrEmpty(error))
            return false;

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(returnedState))
            return false;

        // Validate state matches what we stored
        var savedState = await _store.GetStateAsync();
        if (savedState is null || !CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(savedState),
            System.Text.Encoding.UTF8.GetBytes(returnedState)))
        {
            await _store.ClearStateAsync();
            return false;
        }

        // Retrieve PKCE verifier
        var verifier = await _store.GetPkceVerifierAsync();
        if (string.IsNullOrEmpty(verifier))
            return false;

        // Clean up PKCE + state (one-time use)
        await _store.ClearPkceVerifierAsync();
        await _store.ClearStateAsync();

        // Exchange code for tokens
        var tokenRequest = new TokenRequest
        {
            GrantType = "authorization_code",
            Code = code,
            RedirectUri = _options.RedirectUri,
            ClientId = _options.ClientId,
            CodeVerifier = verifier,
        };

        var tokenUrl = $"{_options.EffectiveAuthority}{_options.TokenPath}";
        var response = await _httpClient.PostAsJsonAsync(tokenUrl, tokenRequest);
        if (!response.IsSuccessStatusCode)
            return false;

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (tokenResponse is null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            return false;

        await ApplyTokenResponseAsync(tokenResponse);
        return true;
    }

    /// <summary>
    /// Refresh the access token. Source of the refresh token depends on
    /// <see cref="VaultBlazorOptions.RefreshStorage"/>:
    /// <list type="bullet">
    /// <item>HttpOnlyCookieOnly: server-issued <c>HttpOnly + Secure + SameSite=Strict</c>
    /// cookie travels with the request automatically; no body field.</item>
    /// <item>InMemoryOnly / SessionStorage: refresh token attached to the request body.</item>
    /// </list>
    /// </summary>
    /// <returns>True if refresh succeeded.</returns>
    public async Task<bool> RefreshAsync()
    {
        var refreshToken = await _store.GetRefreshTokenAsync();

        // CS-10/CS-11: under HttpOnlyCookieOnly, the SDK has no in-memory refresh
        // token (the server holds it in the cookie). Still issue the request — the
        // browser will attach the cookie. For other modes, missing refresh = no-op.
        if (string.IsNullOrEmpty(refreshToken)
            && _store.RefreshMode != RefreshTokenStorage.HttpOnlyCookieOnly)
        {
            return false;
        }

        var tokenRequest = new TokenRequest
        {
            GrantType = "refresh_token",
            RefreshToken = _store.RefreshMode == RefreshTokenStorage.HttpOnlyCookieOnly
                ? null
                : refreshToken,
            ClientId = _options.ClientId,
        };

        var tokenUrl = $"{_options.EffectiveAuthority}{_options.TokenPath}";
        try
        {
            var response = await _httpClient.PostAsJsonAsync(tokenUrl, tokenRequest);
            if (!response.IsSuccessStatusCode)
            {
                await _store.ClearAllAsync();
                _authState.NotifyStateChanged();
                return false;
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
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
    /// attempts a refresh — the SDK can't introspect the cookie, so we ask the
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
    /// Log out — clears all tokens and optionally calls the Vault logout endpoint.
    /// </summary>
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

    public async ValueTask DisposeAsync()
    {
        StopRefreshTimer();
        await _store.DisposeAsync();
    }
}
