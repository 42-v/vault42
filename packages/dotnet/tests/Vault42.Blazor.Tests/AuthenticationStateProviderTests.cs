using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Vault42.Blazor.Tests;

public class AuthenticationStateProviderTests
{
    [Fact]
    public async Task GetAuthenticationState_NoToken_ReturnsAnonymous()
    {
        var store = new TestTokenStore();
        var provider = new VaultAuthenticationStateProvider(store);

        var state = await provider.GetAuthenticationStateAsync();
        Assert.False(state.User.Identity?.IsAuthenticated);
    }

    [Fact]
    public async Task GetAuthenticationState_WithValidToken_ReturnsAuthenticated()
    {
        var store = new TestTokenStore();
        var token = BuildTestJwt(new
        {
            sub = "user-123",
            roles = new[] { "user", "admin" },
            scopes = new[] { "read", "write" },
            client_id = "test-client",
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
        });
        store.SetAccessToken(token, 3600);

        var provider = new VaultAuthenticationStateProvider(store);
        var state = await provider.GetAuthenticationStateAsync();

        Assert.True(state.User.Identity?.IsAuthenticated);
        Assert.Equal("user-123", state.User.FindFirst("sub")?.Value);
        Assert.Contains(state.User.Claims, c => c.Type == ClaimTypes.Role && c.Value == "user");
        Assert.Contains(state.User.Claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
        Assert.Contains(state.User.Claims, c => c.Type == "scope" && c.Value == "read");
        Assert.Contains(state.User.Claims, c => c.Type == "scope" && c.Value == "write");
    }

    [Fact]
    public async Task GetAuthenticationState_ExpiredStore_ReturnsAnonymous()
    {
        var store = new TestTokenStore();
        var token = BuildTestJwt(new { sub = "user-123", exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() });

        // Set with 0 expiry to simulate expired
        store.SetAccessToken(token, 0);

        // Manually expire
        store.ExpireAccessToken();

        var provider = new VaultAuthenticationStateProvider(store);
        var state = await provider.GetAuthenticationStateAsync();

        Assert.False(state.User.Identity?.IsAuthenticated);
    }

    private static string BuildTestJwt(object payload)
    {
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "JWT" }));
        var body = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload));

        // Signature is not validated client-side, so we can use a dummy
        var sig = Base64UrlEncode(new byte[32]);
        return $"{header}.{body}.{sig}";
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

/// <summary>
/// Test double for TokenStore that doesn't require IJSRuntime.
/// </summary>
internal class TestTokenStore : Vault42.Blazor.Internal.TokenStore
{
    internal TestTokenStore()
        : base(null!)
    {
    }

    internal void ExpireAccessToken()
    {
        ClearAccessToken();
    }
}
