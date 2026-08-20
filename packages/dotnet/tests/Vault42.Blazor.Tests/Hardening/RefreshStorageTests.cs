using System;
using Vault42.Blazor;
using Vault42.Blazor.Internal;
using Xunit;

namespace Vault42.Blazor.Tests.Hardening;

/// <summary>
/// CS-10: the refresh token storage strategy must default to HttpOnlyCookieOnly,
/// and no other mode may write to sessionStorage behind the caller's back.
///
/// CS-11 used to be asserted here as "TokenRequest serialises without a
/// refresh_token field", which was a claim about a DTO this SDK wrote and then
/// read back to itself. POST /auth/refresh decodes no body at all -- it reads the
/// __Host-refresh_token cookie and nothing else -- so the request type went in
/// 1.0.3 and the assertion that matters, that the refresh request carries no body,
/// lives in VaultAuthServiceTests against the request the transport actually saw.
/// </summary>
public class RefreshStorageTests
{
    // CS-10: default must be HttpOnlyCookieOnly -- no JS-readable storage.
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
