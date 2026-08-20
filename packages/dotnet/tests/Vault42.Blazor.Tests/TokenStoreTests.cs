using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// The refresh-token half of TokenStore is covered by the CS-10/CS-11 hardening
/// suite. The rest was not: the access-token validity window and what
/// ClearAllAsync takes with it.
///
/// The PKCE verifier and OAuth state slots that used to live here went in 1.0.3
/// with the client-side handshake that wrote them. The Vault keeps both
/// server-side for the flow it runs against the upstream IdP and hands neither
/// back to the app, so a browser-side copy had nothing to be compared against.
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

    [Fact]
    public async Task ClearAll_ClearsTheAccessTokenAndEveryStoredSlot()
    {
        var js = new FakeJsRuntime();
        var store = new TokenStore(js, RefreshTokenStorage.SessionStorage);
        store.SetAccessToken("header.body.sig", 300);
        await store.SetRefreshTokenAsync("refresh-value");

        await store.ClearAllAsync();

        Assert.Null(store.AccessToken);
        Assert.Null(await store.GetRefreshTokenAsync());
        Assert.Empty(js.Session);
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
