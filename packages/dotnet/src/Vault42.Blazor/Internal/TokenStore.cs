using Microsoft.JSInterop;

namespace Vault42.Blazor.Internal;

/// <summary>
/// Stores authentication state. Access token is always held in process memory only.
/// Refresh-token storage is governed by <see cref="VaultBlazorOptions.RefreshStorage"/>:
///
/// <list type="bullet">
/// <item><see cref="RefreshTokenStorage.HttpOnlyCookieOnly"/> (default): refresh token
/// is never read from or written to JS storage by this class — the Vault server
/// emits it as <c>HttpOnly + Secure + SameSite=Strict</c> and the browser
/// auto-attaches it on subsequent requests.</item>
/// <item><see cref="RefreshTokenStorage.InMemoryOnly"/>: refresh token kept in a
/// private field, lost on full reload.</item>
/// <item><see cref="RefreshTokenStorage.SessionStorage"/>: legacy mode —
/// <c>window.sessionStorage</c>, XSS-readable.</item>
/// </list>
///
/// PKCE verifier and OAuth state are short-lived and always go to sessionStorage
/// (cleared after callback consumption); they are not refresh tokens.
/// </summary>
internal class TokenStore : IAsyncDisposable
{
    private readonly IJSRuntime _js;
    private readonly RefreshTokenStorage _refreshMode;

    private string? _accessToken;
    private DateTimeOffset _accessTokenExpiry = DateTimeOffset.MinValue;
    private string? _refreshTokenInMemory;

    private const string KeyRefreshToken = "vault_rt";
    private const string KeyPkceVerifier = "vault_pkce_verifier";
    private const string KeyState = "vault_state";

    internal TokenStore(IJSRuntime js, RefreshTokenStorage refreshMode = RefreshTokenStorage.HttpOnlyCookieOnly)
    {
        _js = js;
        _refreshMode = refreshMode;
    }

    internal RefreshTokenStorage RefreshMode => _refreshMode;

    internal string? AccessToken => _accessToken;

    internal bool IsAccessTokenValid => _accessToken is not null && DateTimeOffset.UtcNow < _accessTokenExpiry;

    internal DateTimeOffset AccessTokenExpiry => _accessTokenExpiry;

    internal void SetAccessToken(string token, int expiresInSeconds)
    {
        _accessToken = token;
        _accessTokenExpiry = DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds);
    }

    internal void ClearAccessToken()
    {
        _accessToken = null;
        _accessTokenExpiry = DateTimeOffset.MinValue;
    }

    internal async Task SetRefreshTokenAsync(string token)
    {
        switch (_refreshMode)
        {
            case RefreshTokenStorage.HttpOnlyCookieOnly:
                // Cookie-bearing response from the server already sets the refresh
                // token; the SDK has no JS-side persistence to do.
                return;
            case RefreshTokenStorage.InMemoryOnly:
                _refreshTokenInMemory = token;
                return;
            case RefreshTokenStorage.SessionStorage:
                await SetSessionStorageAsync(KeyRefreshToken, token);
                return;
        }
    }

    internal async Task<string?> GetRefreshTokenAsync()
    {
        return _refreshMode switch
        {
            RefreshTokenStorage.HttpOnlyCookieOnly => null, // cookie path; can't read HttpOnly
            RefreshTokenStorage.InMemoryOnly => _refreshTokenInMemory,
            RefreshTokenStorage.SessionStorage => await GetSessionStorageAsync(KeyRefreshToken),
            _ => null,
        };
    }

    internal async Task ClearRefreshTokenAsync()
    {
        switch (_refreshMode)
        {
            case RefreshTokenStorage.HttpOnlyCookieOnly:
                // Server-side logout endpoint clears the cookie via Set-Cookie; nothing to do here.
                return;
            case RefreshTokenStorage.InMemoryOnly:
                _refreshTokenInMemory = null;
                return;
            case RefreshTokenStorage.SessionStorage:
                await RemoveSessionStorageAsync(KeyRefreshToken);
                return;
        }
    }

    internal async Task SetPkceVerifierAsync(string verifier)
    {
        await SetSessionStorageAsync(KeyPkceVerifier, verifier);
    }

    internal async Task<string?> GetPkceVerifierAsync()
    {
        return await GetSessionStorageAsync(KeyPkceVerifier);
    }

    internal async Task ClearPkceVerifierAsync()
    {
        await RemoveSessionStorageAsync(KeyPkceVerifier);
    }

    internal async Task SetStateAsync(string state)
    {
        await SetSessionStorageAsync(KeyState, state);
    }

    internal async Task<string?> GetStateAsync()
    {
        return await GetSessionStorageAsync(KeyState);
    }

    internal async Task ClearStateAsync()
    {
        await RemoveSessionStorageAsync(KeyState);
    }

    internal async Task ClearAllAsync()
    {
        ClearAccessToken();
        await ClearRefreshTokenAsync();
        await ClearPkceVerifierAsync();
        await ClearStateAsync();
    }

    private async Task SetSessionStorageAsync(string key, string value)
    {
        await _js.InvokeVoidAsync("sessionStorage.setItem", key, value);
    }

    private async Task<string?> GetSessionStorageAsync(string key)
    {
        return await _js.InvokeAsync<string?>("sessionStorage.getItem", key);
    }

    private async Task RemoveSessionStorageAsync(string key)
    {
        await _js.InvokeVoidAsync("sessionStorage.removeItem", key);
    }

    public async ValueTask DisposeAsync()
    {
        await ClearPkceVerifierAsync();
        await ClearStateAsync();
    }
}
