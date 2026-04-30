using System.Net;
using Vault42.Blazor;
using Xunit;

namespace Vault42.Blazor.Tests.Hardening;

/// <summary>
/// CS-13: <see cref="VaultAuthorizationMessageHandler"/> must not auto-retry
/// non-idempotent methods on 401 — silently retrying POST/PATCH/DELETE could
/// duplicate state changes server-side.
/// </summary>
public class AuthHandlerHardeningTests
{
    [Theory]
    [InlineData("GET", true)]
    [InlineData("HEAD", true)]
    [InlineData("OPTIONS", true)]
    [InlineData("POST", false)]
    [InlineData("PUT", false)]
    [InlineData("PATCH", false)]
    [InlineData("DELETE", false)]
    public void IsSafeForAutoRetry_OnlyReadMethods(string method, bool expected)
    {
        // Reach the private static helper via reflection.
        var helper = typeof(VaultAuthorizationMessageHandler).GetMethod(
            "IsSafeForAutoRetry",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(helper);

        var actual = (bool)helper!.Invoke(null, new object[] { new HttpMethod(method) })!;
        Assert.Equal(expected, actual);
    }
}
