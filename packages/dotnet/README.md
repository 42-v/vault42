# Vault42 .NET SDK

Client libraries for [Vault42](https://github.com/42-v/vault42) — a production-grade Go JWT authentication server.

This repository ships two NuGet packages:

| Package | Purpose |
|---|---|
| **`Vault42.AspNetCore`** | ASP.NET Core authentication middleware. Validates RS256 JWTs against Vault42's JWKS endpoint, with auto-refresh, claim mapping, fingerprint validation, and authorization policies. |
| **`Vault42.Blazor`** | Blazor WebAssembly authentication library. Implements OAuth2 Authorization Code + PKCE (S256) and integrates with `AuthenticationStateProvider`. |

Both target **.NET 10.0**.

## Install

```bash
dotnet add package Vault42.AspNetCore
dotnet add package Vault42.Blazor
```

## `Vault42.AspNetCore` — minimal usage

```csharp
using Vault42.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(VaultDefaults.AuthenticationScheme)
    .AddVault(options =>
    {
        options.Authority = "https://vault42.example.com";
        // Defaults — override if needed:
        // options.MaxTokenSize       = 8192;          // 8 KB cap (matches server)
        // options.JwksRefreshInterval = TimeSpan.FromMinutes(5);
        // options.MaxJwksBytes       = 1L * 1024 * 1024;
        // options.JwksHttpTimeout    = TimeSpan.FromSeconds(10);
        // options.RequireHttpsMetadata = true;
        // options.ValidateFingerprint = false;
    });

var app = builder.Build();
await app.Services.UseVaultAuthenticationAsync();
app.UseAuthentication();
app.UseAuthorization();
```

Security defaults (cannot be disabled by configuration):

- Algorithm whitelist: `RS256` only — `none`, `HS256`, etc. are rejected.
- Dangerous JWT headers (`jku`, `x5u`, `x5c`, `jwk`) are rejected.
- JWKS keys must declare `use=sig` (or no `use`) and `alg=RS256` (or no `alg`).
- RSA modulus < 2048 bits is rejected.
- JWKS body is bounded by `MaxJwksBytes`.
- Token validation failures return a generic `invalid_token` reason — no validator-specific leakage.

## `Vault42.Blazor` — minimal usage

```csharp
using Vault42.Blazor;

builder.Services.AddVaultAuth(options =>
{
    options.Authority   = "https://vault42.example.com";
    options.ClientId    = "my-blazor-app";
    options.RedirectUri = "https://myapp.com/auth/callback";
    // Defaults — override if needed:
    // options.RefreshStorage = RefreshTokenStorage.HttpOnlyCookieOnly;
});
```

`RefreshStorage` trade-offs:

- **`HttpOnlyCookieOnly` (default)** — refresh token never touches JS storage. Vault42 server issues `HttpOnly + Secure + SameSite=Strict` cookies; the browser auto-attaches them. Best XSS resistance. Requires same-origin or CORS-with-credentials origin.
- **`InMemoryOnly`** — refresh token kept in process memory; lost on full reload. XSS-resistant.
- **`SessionStorage`** — legacy XSS-readable persistence. Opt-in only; document the risk in your app.

## Versioning

| Line | Targets | Status |
|---|---|---|
| 0.2.x | net10.0 | Current — see `CHANGELOG.md` |
| 0.1.x | net8.0, net10.0 | Maintenance — pin if you cannot leave net8 |

## License

MIT. See repository root `LICENSE`.

## Security

Report vulnerabilities to **<vault@42-v.com>** (Tuta, end-to-end encrypted). Do not open a public GitHub issue. Full policy: [`SECURITY.md`](https://github.com/42-v/vault42/blob/main/SECURITY.md).
