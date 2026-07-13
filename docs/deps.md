# Dependencies

3 direct dependencies. Everything else — TOTP, CORS, JWKS, config, migrations, password hashing — is stdlib or hand-written.

## Direct

| Dependency | Version | Purpose | Stars | Updated |
|---|---|---|---|---|
| `github.com/go-webauthn/webauthn` | v0.17.4 | WebAuthn/FIDO2 passkey support | ![stars](https://img.shields.io/github/stars/go-webauthn/webauthn?style=flat&label=) | 2026-05-22 |
| `github.com/jackc/pgx/v5` | v5.10.0 | PostgreSQL driver + connection pool | ![stars](https://img.shields.io/github/stars/jackc/pgx?style=flat&label=) | 2026-06-03 |
| `golang.org/x/crypto` | v0.53.0 (latest: v0.54.0) | Argon2id password hashing | ![stars](https://img.shields.io/github/stars/golang/crypto?style=flat&label=) | 2026-07-08 |

## Transitive (18 pulled by the above)

| Dependency | Version | Pulled by | Stars | Updated |
|---|---|---|---|---|
| `github.com/cespare/xxhash/v2` | v2.3.0 |  | ![stars](https://img.shields.io/github/stars/cespare/xxhash?style=flat&label=) | 2024-04-04 |
| `github.com/fxamacker/cbor/v2` | v2.9.2 | webauthn (CBOR encoding) | ![stars](https://img.shields.io/github/stars/fxamacker/cbor?style=flat&label=) | 2026-05-04 |
| `github.com/go-logr/logr` | v1.4.3 |  | ![stars](https://img.shields.io/github/stars/go-logr/logr?style=flat&label=) | 2025-05-19 |
| `github.com/go-logr/stdr` | v1.2.2 |  | ![stars](https://img.shields.io/github/stars/go-logr/stdr?style=flat&label=) | 2021-12-14 |
| `github.com/go-viper/mapstructure/v2` | v2.5.0 | webauthn | ![stars](https://img.shields.io/github/stars/go-viper/mapstructure?style=flat&label=) | 2026-01-12 |
| `github.com/go-webauthn/x` | v0.2.6 | webauthn | ![stars](https://img.shields.io/github/stars/go-webauthn/x?style=flat&label=) | 2026-05-22 |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 |  | ![stars](https://img.shields.io/github/stars/golang-jwt/jwt?style=flat&label=) | 2026-01-28 |
| `github.com/google/go-tpm` | v0.9.8 | webauthn (TPM attestation) | ![stars](https://img.shields.io/github/stars/google/go-tpm?style=flat&label=) | 2025-12-29 |
| `github.com/google/uuid` | v1.6.0 | webauthn | ![stars](https://img.shields.io/github/stars/google/uuid?style=flat&label=) | 2024-01-23 |
| `github.com/jackc/pgpassfile` | v1.0.0 | pgx | ![stars](https://img.shields.io/github/stars/jackc/pgpassfile?style=flat&label=) | 2019-03-30 |
| `github.com/jackc/pgservicefile` | v0.0.0-5a60cdf6a761 | pgx | ![stars](https://img.shields.io/github/stars/jackc/pgservicefile?style=flat&label=) | 2024-06-06 |
| `github.com/jackc/puddle/v2` | v2.2.2 | pgx (connection pool) | ![stars](https://img.shields.io/github/stars/jackc/puddle?style=flat&label=) | 2024-09-10 |
| `github.com/philhofer/fwd` | v1.2.0 |  | ![stars](https://img.shields.io/github/stars/philhofer/fwd?style=flat&label=) | 2024-09-16 |
| `github.com/tinylib/msgp` | v1.6.4 |  | ![stars](https://img.shields.io/github/stars/tinylib/msgp?style=flat&label=) | 2026-03-16 |
| `github.com/x448/float16` | v0.8.4 | cbor | ![stars](https://img.shields.io/github/stars/x448/float16?style=flat&label=) | 2020-01-17 |
| `golang.org/x/sync` | v0.21.0 | pgx | ![stars](https://img.shields.io/github/stars/golang/sync?style=flat&label=) | 2026-07-01 |
| `golang.org/x/sys` | v0.46.0 | x/crypto | ![stars](https://img.shields.io/github/stars/golang/sys?style=flat&label=) | 2026-06-30 |
| `golang.org/x/text` | v0.38.0 | x/crypto | ![stars](https://img.shields.io/github/stars/golang/text?style=flat&label=) | 2026-07-08 |

## Coverage by Package

| Package | Coverage |
|---|---|
| `internal/useragent` | 100.00% |
| `internal/sanitize` | 100.00% |
| `internal/rbac` | 100.00% |
| `internal/model` | 100.00% |
| `internal/metrics` | 100.00% |
| `internal/httputil` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/config` | 98.11% |
| `internal/oauth2` | 97.69% |
| `internal/jwt` | 96.81% |
| `internal/audit` | 94.87% |
| `internal/middleware` | 94.35% |
| `internal/seed` | 93.85% |
| `internal/crypto` | 93.52% |
| `internal/cache` | 92.21% |
| `internal/adminapi` | 91.92% |
| `internal/service` | 90.85% |
| `internal/handler` | 89.71% |
| `internal/email` | 89.51% |
| `internal/redis` | 89.35% |
| `internal/honeypot` | 89.11% |
| `internal/kms` | 87.50% |
| `internal/cli` | 86.44% |
| `internal/keystore` | 84.83% |
| `internal/repository/postgres` | 82.04% |
| `internal/migrate` | 77.50% |
| `internal/server` | 74.87% |
## Maintainers

12 maintainers behind Vault's dependency tree.

| Creator | Type | Packages | Repos | Followers | Since |
|---|---|---|---|---|---|
| [cespare](https://github.com/cespare) | User | xxhash | 150 | ![followers](https://img.shields.io/github/followers/cespare?style=flat&label=) | 2010-06-30 |
| [fxamacker](https://github.com/fxamacker) | User | cbor | 36 | ![followers](https://img.shields.io/github/followers/fxamacker?style=flat&label=) | 2017-10-29 |
| [golang](https://github.com/golang) | Org | crypto, sync, sys, text | 61 | ![followers](https://img.shields.io/github/followers/golang?style=flat&label=) | 2013-05-01 |
| [golang-jwt](https://github.com/golang-jwt) | Org | jwt | 3 | ![followers](https://img.shields.io/github/followers/golang-jwt?style=flat&label=) | 2021-05-14 |
| [go-logr](https://github.com/go-logr) | Org | logr, stdr | 7 | ![followers](https://img.shields.io/github/followers/go-logr?style=flat&label=) | 2017-01-17 |
| [google](https://github.com/google) | Org | go-tpm, uuid | 2883 | ![followers](https://img.shields.io/github/followers/google?style=flat&label=) | 2012-01-18 |
| [go-viper](https://github.com/go-viper) | Org | mapstructure | 2 | ![followers](https://img.shields.io/github/followers/go-viper?style=flat&label=) | 2020-09-30 |
| [go-webauthn](https://github.com/go-webauthn) | Org | webauthn, x | 4 | ![followers](https://img.shields.io/github/followers/go-webauthn?style=flat&label=) | 2021-12-09 |
| [jackc](https://github.com/jackc) | User | pgpassfile, pgservicefile, pgx, puddle | 190 | ![followers](https://img.shields.io/github/followers/jackc?style=flat&label=) | 2009-06-10 |
| [philhofer](https://github.com/philhofer) | User | fwd | 47 | ![followers](https://img.shields.io/github/followers/philhofer?style=flat&label=) | 2012-12-01 |
| [tinylib](https://github.com/tinylib) | Org | msgp | 3 | ![followers](https://img.shields.io/github/followers/tinylib?style=flat&label=) | 2015-01-12 |
| [x448](https://github.com/x448) | User | float16 | 54 | ![followers](https://img.shields.io/github/followers/x448?style=flat&label=) | 2019-10-27 |

