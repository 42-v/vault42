using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// The refresh-token half of TokenStore is covered by the CS-10/CS-11 hardening
/// suite. The rest was not: the access-token validity window, the PKCE and state
/// slots that survive the full page load a login redirect causes, and what
/// DisposeAsync is allowed to throw away.
///
/// The PKCE and state slots deliberately ignore RefreshStorage and always use
/// sessionStorage, because they have to outlive the navigation to the Vault and
/// nothing in memory does. That is a separate decision from where the refresh
/// token lives, and it is asserted separately.
/// </summary>
public class TokenStoreTests
{
    [Fact]
    public void AccessToken_IsValidUntilItsExpiryPasses()
    {
        var store = new TokenStore(new FakeJsRuntime());

        Assert.False(store.IsAccessTokenValid);

        store.SetAccessToken("header.body.sig", 300);

        Assert.True(store.IsAccessTokenValid);
        Assert.Equal("header.body.sig", store.AccessToken);
        Assert.True(store.AccessTokenExpiry > DateTimeOffset.UtcNow);
    }

    // expires_in of 0 is what a server sends for an already-dead token, and what
    // the SDK sets when it clears one. Either way it must not read as valid.
    [Fact]
    public void AccessToken_WithZeroLifetime_IsNotValid()
    {
        var store = new TokenStore(new FakeJsRuntime());

        store.SetAccessToken("header.body.sig", 0);

        Assert.False(store.IsAccessTokenValid);
        Assert.Equal("header.body.sig", store.AccessToken);
    }

    [Fact]
    public void ClearAccessToken_ResetsBothTheTokenAndItsExpiry()
    {
        var store = new TokenStore(new FakeJsRuntime());
        store.SetAccessToken("header.body.sig", 300);

        store.ClearAccessToken();

        Assert.Null(store.AccessToken);
        Assert.False(store.IsAccessTokenValid);
        Assert.Equal(DateTimeOffset.MinValue, store.AccessTokenExpiry);
    }

    // Both short-lived slots have to cross a full page load, so they go to
    // sessionStorage under every refresh mode, including the cookie-only default
    // that otherwise never touches JS storage at all.
    [Theory]
    [InlineData(RefreshTokenStorage.HttpOnlyCookieOnly)]
    [InlineData(RefreshTokenStorage.InMemoryOnly)]
    [InlineData(RefreshTokenStorage.SessionStorage)]
    public async Task PkceVerifierAndState_UseSessionStorageUnderEveryRefreshMode(RefreshTokenStorage mode)
    {
        var js = new FakeJsRuntime();
        var store = new TokenStore(js, mode);

        await store.SetPkceVerifierAsync("verifier-value");
        await store.SetStateAsync("state-value");

        Assert.Equal("verifier-value", js.Session["vault_pkce_verifier"]);
        Assert.Equal("state-value", js.Session["vault_state"]);
        Assert.Equal("verifier-value", await store.GetPkceVerifierAsync());
        Assert.Equal("state-value", await store.GetStateAsync());
    }

    // One-time use: the callback clears both before exchanging the code, so a
    // replayed callback finds nothing to validate against.
    [Fact]
    public async Task ClearingPkceAndState_RemovesThemFromStorage()
    {
        var js = new FakeJsRuntime();
        var store = new TokenStore(js);
        await store.SetPkceVerifierAsync("verifier-value");
        await store.SetStateAsync("state-value");

        await store.ClearPkceVerifierAsync();
        await store.ClearStateAsync();

        Assert.Null(await store.GetPkceVerifierAsync());
        Assert.Null(await store.GetStateAsync());
        Assert.DoesNotContain("vault_pkce_verifier", js.Session.Keys);
        Assert.DoesNotContain("vault_state", js.Session.Keys);
    }

    [Fact]
    public async Task ClearAll_ClearsTheAccessTokenAndEveryStoredSlot()
    {
        var js = new FakeJsRuntime();
        var store = new TokenStore(js, RefreshTokenStorage.SessionStorage);
        store.SetAccessToken("header.body.sig", 300);
        await store.SetRefreshTokenAsync("refresh-value");
        await store.SetPkceVerifierAsync("verifier-value");
        await store.SetStateAsync("state-value");

        await store.ClearAllAsync();

        Assert.Null(store.AccessToken);
        Assert.Null(await store.GetRefreshTokenAsync());
        Assert.Null(await store.GetPkceVerifierAsync());
        Assert.Null(await store.GetStateAsync());
        Assert.Empty(js.Session);
    }

    // Disposal happens when the container tears the app down, which is not a
    // logout. It drops the in-flight login handshake and nothing else, so a
    // session picked back up by TryRestoreSessionAsync still has its refresh
    // token.
    [Fact]
    public async Task DisposeAsync_DropsTheHandshakeButNotTheSession()
    {
        var js = new FakeJsRuntime();
        var store = new TokenStore(js, RefreshTokenStorage.SessionStorage);
        await store.SetRefreshTokenAsync("refresh-value");
        await store.SetPkceVerifierAsync("verifier-value");
        await store.SetStateAsync("state-value");

        await store.DisposeAsync();

        Assert.DoesNotContain("vault_pkce_verifier", js.Session.Keys);
        Assert.DoesNotContain("vault_state", js.Session.Keys);
        Assert.Equal("refresh-value", js.Session["vault_rt"]);
    }

    [Fact]
    public void RefreshMode_DefaultsToTheCookieOnlyPath()
    {
        Assert.Equal(RefreshTokenStorage.HttpOnlyCookieOnly, new TokenStore(new FakeJsRuntime()).RefreshMode);
    }

    // An enum value outside the three declared modes can only arrive from a cast,
    // but the read path answers null rather than falling through to a storage
    // backend it does not recognise. Fail-closed on a value nobody meant to pass.
    [Fact]
    public async Task AnUnrecognisedRefreshMode_ReadsAsNoToken()
    {
        var store = new TokenStore(new FakeJsRuntime(), (RefreshTokenStorage)99);

        Assert.Null(await store.GetRefreshTokenAsync());
    }

    [Fact]
    public async Task ClearRefreshToken_UnderInMemoryMode_DropsTheHeldValue()
    {
        var store = new TokenStore(new FakeJsRuntime(), RefreshTokenStorage.InMemoryOnly);
        await store.SetRefreshTokenAsync("refresh-value");

        await store.ClearRefreshTokenAsync();

        Assert.Null(await store.GetRefreshTokenAsync());
    }
}
