using System.Text.RegularExpressions;
using Vault42.Blazor;
using Xunit;

namespace Vault42.Blazor.Tests;

/// <summary>
/// The defaults on <see cref="VaultBlazorOptions"/> are the endpoint paths the
/// SDK concatenates onto Authority and the refresh behaviour it arms without
/// being asked.
///
/// A path default that drifts from the Vault's routes is the defect this file
/// exists to make impossible. Until 1.0.3 the defaults named /auth/authorize and
/// /auth/token, routes the server has never registered, and the test that was
/// here asserted those two strings against a copy of themselves -- so it agreed
/// with the SDK and both were wrong together. The pinning test below reads
/// internal/server/server.go and checks the paths against the route table
/// itself, which is the only version of this assertion that can fail.
/// </summary>
public class VaultBlazorOptionsTests
{
    [Fact]
    public void EndpointPaths_AreRoutesTheVaultServerRegisters()
    {
        var routes = ServerRoutes();

        // A regex that matched nothing would make every assertion below vacuous.
        Assert.True(routes.Count > 20, $"only {routes.Count} routes parsed out of server.go; the parser is broken, not the SDK");

        var options = new VaultBlazorOptions();

        Assert.Contains(("GET", options.AuthorizePath), routes);
        Assert.Contains(("POST", options.ExchangePath), routes);
        Assert.Contains(("POST", options.RefreshPath), routes);
        Assert.Contains(("POST", options.LogoutPath), routes);
        Assert.Contains(("GET", options.ProfilePath), routes);
    }

    // And the two the SDK used to point at are still absent, which is what made
    // the old defaults a silent failure rather than a 404 the caller could see:
    // with VAULT_SERVE_FRONTEND the SPA catch-all answers an unrouted POST with
    // 200 and index.html.
    [Theory]
    [InlineData("/auth/authorize")]
    [InlineData("/auth/token")]
    public void ThePre103Defaults_AreNotRoutesAtAll(string path)
    {
        Assert.DoesNotContain(ServerRoutes(), r => r.Path == path);
    }

    [Fact]
    public void EndpointPathDefaults_AreTheOnesThePinningTestChecked()
    {
        var options = new VaultBlazorOptions();

        Assert.Equal("/auth/oauth2/authorize", options.AuthorizePath);
        Assert.Equal("/auth/oauth2/exchange", options.ExchangePath);
        Assert.Equal("/auth/refresh", options.RefreshPath);
        Assert.Equal("/auth/logout", options.LogoutPath);
        Assert.Equal("/user/profile", options.ProfilePath);
        Assert.Equal("/", options.PostLogoutRedirectUri);
    }

    [Fact]
    public void RefreshDefaults_AreProactiveAndOn()
    {
        var options = new VaultBlazorOptions();

        Assert.True(options.AutoRefresh);
        Assert.Equal(60, options.RefreshBeforeExpirySecs);
        Assert.Equal(new[] { "read", "write" }, options.Scopes);
    }

    // No provider is configured by default, because the Vault has no default one:
    // GET /auth/oauth2/authorize looks the name up in the configured map and
    // answers 400 unknown_provider on a miss.
    [Fact]
    public void Provider_HasNoDefault()
    {
        Assert.Equal(string.Empty, new VaultBlazorOptions().Provider);
    }

    // Authority is concatenated with a path that already starts with '/', so a
    // trailing slash on the configured value would produce "//auth/refresh".
    [Theory]
    [InlineData("https://vault.example.com", "https://vault.example.com")]
    [InlineData("https://vault.example.com/", "https://vault.example.com")]
    [InlineData("https://vault.example.com///", "https://vault.example.com")]
    public void EffectiveAuthority_DropsTrailingSlashes(string configured, string expected)
    {
        var options = new VaultBlazorOptions { Authority = configured };

        Assert.Equal(expected, options.EffectiveAuthority);
    }

    // The default is the only mode where the refresh token never enters
    // JS-reachable memory, and the only one a Vault server can feed at all.
    [Fact]
    public void RefreshStorage_DefaultsToTheCookieOnlyMode()
    {
        Assert.Equal(RefreshTokenStorage.HttpOnlyCookieOnly, new VaultBlazorOptions().RefreshStorage);
        Assert.Equal(0, (int)RefreshTokenStorage.HttpOnlyCookieOnly);
    }

    /// <summary>
    /// Every route <c>internal/server/server.go</c> registers, as (method, path).
    /// </summary>
    /// <remarks>
    /// Go 1.22 patterns are "METHOD /path", registered through either mux.Handle or
    /// mux.HandleFunc. Wildcard segments such as {provider} are left as written; none of the paths
    /// this SDK builds contains one, so a route that grew a wildcard would stop matching and the
    /// test would say so.
    /// </remarks>
    private static List<(string Method, string Path)> ServerRoutes()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "internal", "server", "server.go"));
        return Regex
            .Matches(source, @"mux\.Handle(?:Func)?\(""(GET|POST|PUT|PATCH|DELETE) ([^""]+)""", RegexOptions.None, TimeSpan.FromSeconds(5))
            .Select(m => (m.Groups[1].Value, m.Groups[2].Value))
            .ToList();
    }

    /// <summary>
    /// Walks up from the test assembly to the directory holding go.mod.
    /// </summary>
    /// <remarks>
    /// The test binary lives under packages/dotnet/tests/.../bin/Debug/net10.0, and how deep that
    /// is depends on the configuration, so the depth is searched for rather than counted.
    /// </remarks>
    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "go.mod")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return dir.FullName;
    }
}
