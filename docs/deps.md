# Dependencies

3 direct dependencies. Everything else — TOTP, CORS, JWKS, config, migrations, password hashing — is stdlib or hand-written.

## Direct

| Dependency | Version | Purpose | Stars | Updated |
|---|---|---|---|---|
| `github.com/go-webauthn/webauthn` | v0.17.0 | WebAuthn/FIDO2 passkey support | ![stars](https://img.shields.io/github/stars/go-webauthn/webauthn?style=flat&label=) | 2026-04-21 |
| `github.com/jackc/pgx/v5` | v5.9.2 | PostgreSQL driver + connection pool | ![stars](https://img.shields.io/github/stars/jackc/pgx?style=flat&label=) | 2026-04-19 |
| `golang.org/x/crypto` | v0.50.0 | Argon2id password hashing | ![stars](https://img.shields.io/github/stars/golang/crypto?style=flat&label=) | 2026-04-09 |

## Transitive (18 pulled by the above)

| Dependency | Version | Pulled by | Stars | Updated |
|---|---|---|---|---|
| `github.com/cespare/xxhash/v2` | v2.3.0 |  | ![stars](https://img.shields.io/github/stars/cespare/xxhash?style=flat&label=) | 2024-04-04 |
| `github.com/fxamacker/cbor/v2` | v2.9.1 | webauthn (CBOR encoding) | ![stars](https://img.shields.io/github/stars/fxamacker/cbor?style=flat&label=) | 2026-03-30 |
| `github.com/go-logr/logr` | v1.4.3 |  | ![stars](https://img.shields.io/github/stars/go-logr/logr?style=flat&label=) | 2025-05-19 |
| `github.com/go-logr/stdr` | v1.2.2 |  | ![stars](https://img.shields.io/github/stars/go-logr/stdr?style=flat&label=) | 2021-12-14 |
| `github.com/go-viper/mapstructure/v2` | v2.5.0 | webauthn | ![stars](https://img.shields.io/github/stars/go-viper/mapstructure?style=flat&label=) | 2026-01-12 |
| `github.com/go-webauthn/x` | v0.2.3 | webauthn | ![stars](https://img.shields.io/github/stars/go-webauthn/x?style=flat&label=) | 2026-04-09 |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 |  | ![stars](https://img.shields.io/github/stars/golang-jwt/jwt?style=flat&label=) | 2026-01-28 |
| `github.com/google/go-tpm` | v0.9.8 | webauthn (TPM attestation) | ![stars](https://img.shields.io/github/stars/google/go-tpm?style=flat&label=) | 2025-12-29 |
| `github.com/google/uuid` | v1.6.0 | webauthn | ![stars](https://img.shields.io/github/stars/google/uuid?style=flat&label=) | 2024-01-23 |
| `github.com/jackc/pgpassfile` | v1.0.0 | pgx | ![stars](https://img.shields.io/github/stars/jackc/pgpassfile?style=flat&label=) | 2019-03-30 |
| `github.com/jackc/pgservicefile` | v0.0.0-5a60cdf6a761 | pgx | ![stars](https://img.shields.io/github/stars/jackc/pgservicefile?style=flat&label=) | 2024-06-06 |
| `github.com/jackc/puddle/v2` | v2.2.2 | pgx (connection pool) | ![stars](https://img.shields.io/github/stars/jackc/puddle?style=flat&label=) | 2024-09-10 |
| `github.com/philhofer/fwd` | v1.2.0 |  | ![stars](https://img.shields.io/github/stars/philhofer/fwd?style=flat&label=) | 2024-09-16 |
| `github.com/tinylib/msgp` | v1.6.4 |  | ![stars](https://img.shields.io/github/stars/tinylib/msgp?style=flat&label=) | 2026-03-16 |
| `github.com/x448/float16` | v0.8.4 | cbor | ![stars](https://img.shields.io/github/stars/x448/float16?style=flat&label=) | 2020-01-17 |
| `golang.org/x/sync` | v0.20.0 | pgx | ![stars](https://img.shields.io/github/stars/golang/sync?style=flat&label=) | 2026-02-23 |
| `golang.org/x/sys` | v0.43.0 | x/crypto | ![stars](https://img.shields.io/github/stars/golang/sys?style=flat&label=) | 2026-03-27 |
| `golang.org/x/text` | v0.36.0 | x/crypto | ![stars](https://img.shields.io/github/stars/golang/text?style=flat&label=) | 2026-04-09 |

## Coverage by Package

| Package | Coverage |
|---|---|
| `internal/useragent` | 100.0% |
| `internal/rbac` | 100.0% |
| `internal/model` | 100.0% |
| `internal/metrics` | 100.0% |
| `internal/frontend` | 100.0% |
| `internal/oauth2` | 97.5% |
| `internal/sanitize` | 97.2% |
| `internal/jwt` | 94.8% |
| `internal/crypto` | 89.5% |
| `internal/honeypot` | 87.1% |
| `internal/email` | 86.4% |
| `internal/middleware` | 82.8% |
| `internal/redis` | 79.0% |
| `internal/config` | 78.9% |
| `internal/audit` | 75.9% |
| `internal/handler` | 71.3% |
| `internal/service` | 70.2% |
| `internal/seed` | 64.2% |
| `internal/cli` | 63.6% |
| `internal/server` | 55.3% |
| `internal/cache` | 51.9% |
| `internal/httputil` | 44.4% |
| `internal/adminapi` | 12.1% |
| `internal/keystore` | 9.3% |
| `internal/migrate` | 2.5% |
| `internal/repository/postgres` | 0.0% |
## Maintainers

12 maintainers behind Vault42's dependency tree.

| Creator | Type | Packages | Repos | Followers | Since |
|---|---|---|---|---|---|
| [cespare](https://github.com/cespare) | User | xxhash | 148 | ![followers](https://img.shields.io/github/followers/cespare?style=flat&label=) | 2010-06-30 |
| [fxamacker](https://github.com/fxamacker) | User | cbor | 35 | ![followers](https://img.shields.io/github/followers/fxamacker?style=flat&label=) | 2017-10-29 |
| [golang](https://github.com/golang) | Org | crypto, sync, sys, text | 61 | ![followers](https://img.shields.io/github/followers/golang?style=flat&label=) | 2013-05-01 |
| [golang-jwt](https://github.com/golang-jwt) | — | jwt | — | — | — |
| [go-logr](https://github.com/go-logr) | — | logr, stdr | — | — | — |
| [google](https://github.com/google) | — | go-tpm, uuid | — | — | — |
| [go-viper](https://github.com/go-viper) | — | mapstructure | — | — | — |
| [go-webauthn](https://github.com/go-webauthn) | — | webauthn, x | — | — | — |
| [jackc](https://github.com/jackc) | — | pgpassfile, pgservicefile, pgx, puddle | — | — | — |
| [philhofer](https://github.com/philhofer) | — | fwd | — | — | — |
| [tinylib](https://github.com/tinylib) | — | msgp | — | — | — |
| [x448](https://github.com/x448) | — | float16 | — | — | — |

