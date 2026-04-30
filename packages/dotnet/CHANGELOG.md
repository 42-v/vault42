# Vault42 .NET SDK — Changelog

## 0.2.0 — 2026-04-25

Security re-audit ship. **Breaking** for net8 consumers; defense-in-depth + dependency uplift for everyone else. See full audit at `docs/security-audit-2026-04-25.md`.

### Breaking

- **Dropped `net8.0` target.** Both `Vault42.AspNetCore` and `Vault42.Blazor` now target `net10.0` only. Pin `0.1.x` for net8 consumers.
- **`RefreshTokenStorage` default changed** to `HttpOnlyCookieOnly` for `Vault42.Blazor`. Apps that depended on the old default (sessionStorage) must explicitly set `options.RefreshStorage = RefreshTokenStorage.SessionStorage` and accept the documented XSS risk. See README "RefreshStorage trade-offs".
- **`VaultAuthenticationOptions.RequireHttpsMetadata = true`** by default for `Vault42.AspNetCore`. `AddVault` now throws when `Authority` is non-HTTPS. Set `RequireHttpsMetadata = false` for local dev only.
- **`VaultAuthorizationMessageHandler` only auto-retries safe HTTP methods** (`GET`/`HEAD`/`OPTIONS`) on 401. Apps that relied on auto-retry of `POST`/`PATCH`/`DELETE` must handle the 401 themselves.

### Security

- Removed transitive HIGH-severity vuln `Microsoft.Bcl.Memory 9.0.0` (GHSA-73j8-2gch-69rq) by dropping net8.0 + bumping IdentityModel.
- Bumped `Microsoft.IdentityModel.Tokens` and `System.IdentityModel.Tokens.Jwt` 8.7.0 → 8.17.0.
- Bumped `Microsoft.AspNetCore.Components.Authorization`, `Components.Web`, `Extensions.Http` to 10.0.7.
- JWKS validator (`VaultJwksManager`) now rejects: keys with `use=enc`, keys with declared `alg ≠ RS256`, RSA modulus < 2048 bits, response bodies > `MaxJwksBytes` (default 1 MiB).
- JWKS HTTP client honours `JwksHttpTimeout` (default 10 s) instead of the framework default of 100 s.
- `VaultAuthenticationHandler.HandleChallengeAsync` uses boundary-aware path-prefix matching — `/login` no longer matches `/login-other-route`.
- `SecurityTokenException.Message` is no longer leaked into 401 `WWW-Authenticate` / `AuthenticateResult.Failure`. Validation reasons (`expired`, `bad signature`, etc.) are logged at debug; the response carries a generic `invalid_token`.
- Refresh tokens default to the `HttpOnly + Secure + SameSite=Strict` cookie path; refresh token never written to JS-readable storage unless explicitly opted in via `RefreshTokenStorage.SessionStorage`.
- `TokenRequest` JSON serialization now omits null fields (`refresh_token`, `code`, etc.) to support the cookie-only refresh flow.

### Packaging

- `<EnablePackageValidation>true</EnablePackageValidation>`.
- `<Deterministic>true</Deterministic>` + `<ContinuousIntegrationBuild>` (CI-gated) for reproducible builds.
- `Microsoft.SourceLink.GitHub` 10.0.203 (PrivateAssets=all) — symbol packages (`.snupkg`) embed source link to GitHub.
- `<EmbedUntrackedSources>true</EmbedUntrackedSources>`.
- Shared `packages/dotnet/README.md` shipped inside both `.nupkg` files via `<PackageReadmeFile>`.
- nuspec embeds `<repository url=... type=git commit=...>`.
- `<Authors>` corrected to `42-v`.

### Dev

- Test SDK `Microsoft.NET.Test.Sdk` bumped 17.12.0 → 18.5.0.
- `xunit.runner.visualstudio` bumped 2.8.2 → 3.1.5 (xunit kept on 2.9.3; v3 deferred).
- 17 new hardening tests under `Hardening/` (auth, JWKS, refresh storage, retry idempotency).
- All NuGet production dependencies signature-verified by `dotnet nuget verify --all` (NuGet.org Microsoft repository signature).

## 0.1.1 — prior release line

Initial release line; multi-target net8.0 + net10.0. See git history.
