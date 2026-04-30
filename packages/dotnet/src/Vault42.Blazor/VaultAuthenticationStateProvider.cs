using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using Vault42.Blazor.Internal;

namespace Vault42.Blazor;

/// <summary>
/// Blazor AuthenticationStateProvider that derives claims from the Vault JWT access token.
/// Parses the JWT payload client-side (signature already validated server-side during exchange).
/// </summary>
public class VaultAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly TokenStore _store;
    private static readonly AuthenticationState Anonymous = new (new ClaimsPrincipal(new ClaimsIdentity()));

    internal VaultAuthenticationStateProvider(TokenStore store)
    {
        _store = store;
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!_store.IsAccessTokenValid)
            return Task.FromResult(Anonymous);

        var claims = ParseJwtClaims(_store.AccessToken!);
        if (claims is null)
            return Task.FromResult(Anonymous);

        var identity = new ClaimsIdentity(claims, "Vault", "sub", ClaimTypes.Role);
        return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(identity)));
    }

    internal void NotifyStateChanged()
    {
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    private static List<Claim>? ParseJwtClaims(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
            return null;

        try
        {
            var payload = Base64UrlDecode(parts[1]);
            using var doc = JsonDocument.Parse(payload);
            var claims = new List<Claim>();

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                switch (prop.Value.ValueKind)
                {
                    case JsonValueKind.String:
                        claims.Add(new Claim(prop.Name, prop.Value.GetString()!));
                        break;
                    case JsonValueKind.Number:
                        claims.Add(new Claim(prop.Name, prop.Value.GetRawText()));
                        break;
                    case JsonValueKind.True:
                    case JsonValueKind.False:
                        claims.Add(new Claim(prop.Name, prop.Value.GetRawText()));
                        break;
                    case JsonValueKind.Array:
                        // Map arrays (roles, scopes) to individual claims
                        if (prop.Name == "roles")
                        {
                            foreach (var item in prop.Value.EnumerateArray())
                            {
                                if (item.ValueKind == JsonValueKind.String)
                                    claims.Add(new Claim(ClaimTypes.Role, item.GetString()!));
                            }
                        }
                        else if (prop.Name == "scopes")
                        {
                            foreach (var item in prop.Value.EnumerateArray())
                            {
                                if (item.ValueKind == JsonValueKind.String)
                                    claims.Add(new Claim("scope", item.GetString()!));
                            }
                        }
                        else
                        {
                            claims.Add(new Claim(prop.Name, prop.Value.GetRawText()));
                        }

                        break;
                    default:
                        claims.Add(new Claim(prop.Name, prop.Value.GetRawText()));
                        break;
                }
            }

            return claims;
        }
        catch
        {
            return null;
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }

        return Convert.FromBase64String(s);
    }
}
