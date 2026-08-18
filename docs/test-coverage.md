# Test Coverage Report

Generated: 2026-08-18 | Tests: 4996 | Total: 98.52% statement coverage

Measured across the full suite (unit + attack + fuzz + integration +
compliance) against `./internal/...`. Regenerate with `scripts/coverage.sh`.

## Package Summary

| Package | Coverage |
|---------|----------|
| `internal/useragent` | 100.00% |
| `internal/server` | 100.00% |
| `internal/seed` | 100.00% |
| `internal/sanitize` | 100.00% |
| `internal/redis` | 100.00% |
| `internal/rbac` | 100.00% |
| `internal/outbound` | 100.00% |
| `internal/model` | 100.00% |
| `internal/migrate` | 100.00% |
| `internal/middleware` | 100.00% |
| `internal/metrics` | 100.00% |
| `internal/kms` | 100.00% |
| `internal/ipintel` | 100.00% |
| `internal/httputil` | 100.00% |
| `internal/honeypot` | 100.00% |
| `internal/frontend` | 100.00% |
| `internal/dpop` | 100.00% |
| `internal/deferwork` | 100.00% |
| `internal/config` | 100.00% |
| `internal/cli` | 100.00% |
| `internal/cache` | 100.00% |
| `internal/audit` | 100.00% |
| `internal/alert` | 100.00% |
| `internal/repository/postgres` | 99.91% |
| `internal/adminapi` | 99.83% |
| `internal/oauth2` | 99.74% |
| `cmd/admin-gateway` | 99.72% |
| `internal/handler` | 99.69% |
| `internal/keystore` | 99.62% |
| `internal/service` | 99.28% |
| `internal/jwt` | 99.22% |
| `internal/email` | 98.71% |
| `cmd/vault` | 98.39% |
| `internal/crypto` | 98.16% |
| `cmd/recover` | 98.15% |
| `internal/firstboot` | 96.88% |
| `cmd/bridge` | 83.02% |

## Uncovered Functions

| Function | File |
|----------|------|
| `joinHeader` | cmd/bridge/proxy.go:526 |
| `main` | cmd/recover/main.go:134 |

## Low Coverage (1-74%)

| Function | File | Coverage |
|----------|------|----------|
| `obfuscatedIP` | cmd/bridge/proxy.go:402 | 33.3% |
| `setProxyHeaders` | cmd/bridge/proxy.go:441 | 27.8% |
| `stripConnectionTokens` | cmd/bridge/proxy.go:483 | 42.9% |
| `rightmostUntrusted` | cmd/bridge/proxy.go:545 | 31.2% |
| `clientIP` | cmd/bridge/proxy.go:563 | 58.6% |
| `isTrustedProxy` | cmd/bridge/proxy.go:603 | 35.7% |
| `extractIP` | cmd/bridge/proxy.go:619 | 50.0% |
| `StartReaper` | cmd/bridge/proxy.go:628 | 46.7% |
| `Close` | cmd/bridge/proxy.go:643 | 33.3% |
| `NewWebhookSender` | cmd/bridge/proxy.go:681 | 33.3% |
| `Send` | cmd/bridge/proxy.go:717 | 23.1% |
| `Close` | cmd/bridge/proxy.go:741 | 44.4% |
| `deliver` | cmd/bridge/proxy.go:760 | 45.0% |
| `hardenProcess` | cmd/recover/harden_linux.go:23 | 66.7% |
