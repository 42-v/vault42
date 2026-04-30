using System;
using System.Reflection;
using System.Text.Json;
using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests.Hardening;

/// <summary>
/// CS-10 / CS-11: refresh token storage strategy must default to HttpOnlyCookieOnly,
/// and TokenRequest serialization must omit the refresh_token field when the
/// cookie path is in use.
/// </summary>
public class RefreshStorageTests
{
    // CS-10: default must be HttpOnlyCookieOnly — no JS-readable storage.
    [Fact]
    public void Default_RefreshStorage_IsHttpOnlyCookieOnly()
    {
        var opts = new VaultBlazorOptions();
        Assert.Equal(RefreshTokenStorage.HttpOnlyCookieOnly, opts.RefreshStorage);
    }

    // CS-10: under HttpOnlyCookieOnly, SetRefreshTokenAsync MUST NOT touch sessionStorage.
    // (Verified via the test double which records every JS interop call.)
    [Fact]
    public async Task CookieOnly_SetRefreshToken_DoesNotTouchSessionStorage()
    {
        var jsRuntime = new RecordingJsRuntime();
        var store = new TokenStore(jsRuntime, RefreshTokenStorage.HttpOnlyCookieOnly);

        await store.SetRefreshTokenAsync("a-secret-refresh-token");

        Assert.DoesNotContain(jsRuntime.Calls, c => c.identifier.StartsWith("sessionStorage", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CookieOnly_GetRefreshToken_ReturnsNull()
    {
        var jsRuntime = new RecordingJsRuntime();
        var store = new TokenStore(jsRuntime, RefreshTokenStorage.HttpOnlyCookieOnly);

        var rt = await store.GetRefreshTokenAsync();

        Assert.Null(rt);
        Assert.DoesNotContain(jsRuntime.Calls, c => c.identifier.StartsWith("sessionStorage", StringComparison.Ordinal));
    }

    [Fact]
    public async Task InMemoryOnly_RoundTripsRefreshToken_NoSessionStorage()
    {
        var jsRuntime = new RecordingJsRuntime();
        var store = new TokenStore(jsRuntime, RefreshTokenStorage.InMemoryOnly);

        await store.SetRefreshTokenAsync("abc");
        var got = await store.GetRefreshTokenAsync();

        Assert.Equal("abc", got);
        Assert.DoesNotContain(
            jsRuntime.Calls,
            c => c.identifier.StartsWith("sessionStorage", StringComparison.Ordinal) && c.args.Any(a => a as string == "vault_rt"));
    }

    [Fact]
    public async Task SessionStorage_OptIn_RecordsToSessionStorage()
    {
        var jsRuntime = new RecordingJsRuntime();
        var store = new TokenStore(jsRuntime, RefreshTokenStorage.SessionStorage);

        await store.SetRefreshTokenAsync("xyz");

        Assert.Contains(
            jsRuntime.Calls,
            c => c.identifier == "sessionStorage.setItem" && (string)c.args[0]! == "vault_rt");
    }

    // CS-11: TokenRequest serializes WITHOUT a refresh_token field when the
    // cookie path is active (refresh_token property is null and
    // JsonIgnoreCondition.WhenWritingNull is honoured).
    [Fact]
    public void TokenRequest_NullRefreshToken_OmittedFromJson()
    {
        var req = new TokenRequest
        {
            GrantType = "refresh_token",
            ClientId = "test-app",
            RefreshToken = null, // cookie path
        };

        var json = JsonSerializer.Serialize(req);

        // "refresh_token" appears as a value of grant_type, but MUST NOT appear
        // as a field key — i.e. there is no `"refresh_token":` in the output.
        Assert.DoesNotContain("\"refresh_token\":", json);
        Assert.Contains("\"grant_type\":\"refresh_token\"", json);
        Assert.Contains("\"client_id\":\"test-app\"", json);
    }

    [Fact]
    public void TokenRequest_NonNullRefreshToken_PresentInJson()
    {
        var req = new TokenRequest
        {
            GrantType = "refresh_token",
            ClientId = "test-app",
            RefreshToken = "the-token",
        };

        var json = JsonSerializer.Serialize(req);
        Assert.Contains("\"refresh_token\":\"the-token\"", json);
    }
}

// -- helpers --
internal sealed class RecordingJsRuntime : Microsoft.JSInterop.IJSRuntime
{
    internal record Call(string identifier, object?[] args);

    internal List<Call> Calls { get; } = new ();

    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
    {
        Calls.Add(new Call(identifier, args ?? Array.Empty<object?>()));

        // sessionStorage.getItem returns string?; use default
        return ValueTask.FromResult<TValue>(default!);
    }

    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
    {
        return InvokeAsync<TValue>(identifier, args);
    }
}
