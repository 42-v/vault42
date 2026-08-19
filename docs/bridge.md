# Honeypot Bridge

> Transparent reverse proxy that silently reroutes attackers to a honeypot Vault42 instance.

## Architecture

```text
                Internet
                   │
          ┌────────▼────────┐
          │  Cloudflare      │
          │  Tunnel / Ingress│
          └────────┬────────┘
                   │
          ┌────────▼────────┐
          │     Bridge       │  ← Scoring, detection, decoy pages
          │   (port 8080)    │
          └───┬─────────┬───┘
              │         │
     Clean    │         │  Flagged
     traffic  │         │  traffic
              │         │
    ┌─────────▼──┐  ┌───▼──────────┐
    │ Real Vault42 │  │ Honeypot     │
    │ (prod DB)  │  │ Vault42        │
    └─────┬──────┘  │ (honeypot DB)│
          │         └──────┬───────┘
    ┌─────▼──────┐  ┌──────▼───────┐
    │  Real      │  │  Honeypot    │
    │  PostgreSQL│  │  PostgreSQL  │
    └────────────┘  └──────────────┘
```

The bridge sits in front of two isolated Vault42 instances. Both run the same binary with the same
`VAULT_ORIGIN`, producing identical response shapes and timing (including Argon2id dummy burns for
anti-enumeration). What that buys is described precisely below: the switch is invisible in the shape
of a response, and it is **not** invisible to an attacker who inspects signing key material. The two
instances deliberately do not share a Secret, so they do not share a signing key.

## Quick Start

```bash
# Build both images
scripts/build-all.sh

# Deploy with Helm
helm install vault42 charts/vault -f charts/vault/values-bridge.yaml \
  --set origin="https://auth.example.com" \
  --set secrets.existingSecret=vault42-secrets
```

## Detection Signals

Score-based detection -- cumulative score >= `BRIDGE_FLAG_THRESHOLD` (default: 100) triggers flagging:

| Signal | Score | How |
|--------|-------|-----|
| Automation User-Agent | +30 | curl, sqlmap, nikto, gobuster, nuclei, etc. |
| Rate exceeded | +50 | Sliding window counter per IP exceeds threshold |
| Failed login | +20 each | `ModifyResponse` inspects 401 on `POST /auth/login` |
| Decoy path hit | +100 | `/wp-admin`, `/phpmyadmin`, etc. -- instant flag |
| Admin manual flag | +100 | `POST /bridge/flag` |

## Routing Logic

```text
Request
  │
  ├─ /bridge/* path? ──────────── Admin/health handlers
  │
  ├─ Decoy path? ─────────────── Flag IP (+100) + serve fake login page
  │
  ├─ IP already flagged? ─────── Route to honeypot
  │
  ├─ Run scoring ──────────────── Score >= threshold? → Flag + honeypot
  │
  └─ Clean ────────────────────── Route to real vault42
```

The `ModifyResponse` callback on the real proxy inspects `POST /auth/login` responses returning 401 and increments the login failure counter for that IP.

## Decoy Pages

Built-in fake login pages served directly by the bridge (never proxied):

| Path pattern | Mimics |
|---|---|
| `/wp-admin*`, `/wp-login.php` | WordPress login |
| `/phpmyadmin*`, `/pma*` | phpMyAdmin login |
| `/cpanel*`, `/webmail*` | cPanel login |
| `/administrator*` | Generic admin panel (Joomla) |

`/admin*` is deliberately absent. vault42 serves its own admin SPA and roughly
thirty documented API routes under `/admin/`, and decoy matching is by prefix, so
listing it aimed the honeypot at the operator: opening the admin console through
a bridge flagged them for the full `BRIDGE_FLAG_TTL` and then answered every
later request with fabricated key, user, session and audit data. `/administrator`
stays because it is Joomla's and nothing under it is registered.

POST on decoy forms returns fake "invalid credentials". All subsequent requests from that IP route to the honeypot.

## Admin API

Protected by `BRIDGE_ADMIN_TOKEN_FILE` (constant-time comparison via `crypto/subtle`):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/bridge/flag` | Flag an IP: `{"ip":"...","reason":"..."}` |
| `DELETE` | `/bridge/flag` | Unflag an IP: `{"ip":"..."}` |
| `GET` | `/bridge/flags` | List all flagged IPs |
| `GET` | `/bridge/healthz` | Liveness probe |
| `GET` | `/bridge/readyz` | Readiness (checks both upstreams) |

```bash
# Flag an IP
curl -X POST https://bridge/bridge/flag \
  -H "Authorization: Bearer $BRIDGE_ADMIN_TOKEN" \
  -d '{"ip":"1.2.3.4","reason":"manual investigation"}'

# List flags
curl https://bridge/bridge/flags \
  -H "Authorization: Bearer $BRIDGE_ADMIN_TOKEN"

# Unflag
curl -X DELETE https://bridge/bridge/flag \
  -H "Authorization: Bearer $BRIDGE_ADMIN_TOKEN" \
  -d '{"ip":"1.2.3.4"}'
```

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `BRIDGE_LISTEN_ADDR` | `:8080` | Listen address |
| `BRIDGE_REAL_UPSTREAM` | required | URL of real Vault42 service |
| `BRIDGE_HONEYPOT_UPSTREAM` | required | URL of honeypot Vault42 service |
| `BRIDGE_RATE_THRESHOLD` | `60` | Requests per window before scoring |
| `BRIDGE_RATE_WINDOW` | `1m` | Rate counting window |
| `BRIDGE_LOGIN_FAIL_THRESHOLD` | `5` | Failed logins before scoring |
| `BRIDGE_LOGIN_FAIL_WINDOW` | `15m` | Login failure counting window |
| `BRIDGE_FLAG_TTL` | `24h` | How long an IP stays flagged |
| `BRIDGE_FLAG_THRESHOLD` | `100` | Score threshold to trigger flag |
| `BRIDGE_WEBHOOK_URL` | -- | Optional webhook for flag events |
| `BRIDGE_ADMIN_TOKEN_FILE` | -- | Admin token (`_FILE` convention) |
| `BRIDGE_REDIS_ADDR` | -- | Optional Redis for persistent flags |
| `BRIDGE_TRUSTED_PROXIES` | -- | CIDR list for proxy IP detection |
| `BRIDGE_REAL_IP_HEADER` | -- | Header from proxy (e.g. `CF-Connecting-IP`) |
| `BRIDGE_LOG_LEVEL` | `info` | Log level (`info`, `debug`) |
| `BRIDGE_MAX_BODY_BYTES` | `16777216` | Cap on a proxied request body |
| `BRIDGE_MAX_INFLIGHT` | `512` | Cap on concurrently proxied requests (`0` disables) |

Every number above is range-checked at startup and the bridge refuses to start
outside the range. The thresholds, the windows and `BRIDGE_MAX_BODY_BYTES` must
be positive; `BRIDGE_MAX_INFLIGHT` may be `0`, which its own documentation
defines as "no cap". The reason for refusing rather than clamping is that the
code applying each cap guards on a positive value, so a negative one does not
lower the limit, it removes it -- and after startup nothing distinguishes an
operator who asked for that from one who typed a minus sign.

A value that does not parse is treated differently: it falls back to the
default, because a bridge that will not start over one mistyped threshold takes
the whole edge down with it. It now logs a `WARNING` naming the variable and the
value in force, so "the setting did not take" is something an operator can find.

## State Persistence

- **Primary:** `sync.Map` for zero-latency reads on the hot path
- **Optional:** Inline RESP2 Redis client (GET/SET/DEL/SCAN only)
  - On startup: SCAN `bridge:flag:*` → populate memory
  - On flag: write to memory + Redis SET with EX
  - On unflag: delete from both
  - On request: read memory only (never blocks on Redis)

## Network Isolation (Kubernetes)

When `bridge.enabled=true`, network policies enforce:

```text
Bridge → Real Vault42:       ALLOW
Bridge → Honeypot Vault42:   ALLOW
Bridge → Redis:            ALLOW (if enabled)
Real Vault42 → Real PG:      ALLOW
Honeypot Vault42 → HP PG:    ALLOW
Real Vault42 ↔ Honeypot:     BLOCKED
Cross-DB access:           BLOCKED
External → Bridge:         ALLOW (port 8080)
External → Vaults:         BLOCKED (only bridge can reach them)
```

## What Switching Does And Does Not Conceal

Concealed:

- Both Vaults share the same `VAULT_ORIGIN`, so cookie names, domains and attributes are identical
- Both run the same binary, so response shapes, status codes and error bodies are identical
- Argon2id dummy burns on user-not-found prevent timing leaks
- The attacker's refresh token is invalid on the honeypot (different DB), which presents as an
  ordinary rejected session rather than as a distinct error
- The bridge adds no headers to the response an attacker sees

Not concealed, deliberately:

- **Signing key material.** `vault.honeypotSecretName` refuses to resolve to the production Secret,
  so the honeypot holds its own master key, HMAC secret, pepper and signing key: the same key names
  with different values. The honeypot therefore serves a different `/.well-known/jwks.json`, with a
  different `kid` and a different modulus. An attacker who fetched JWKS before the switch and fetches
  it again after can see that it changed, and an access token minted by the real vault fails on the
  honeypot as an unknown `kid` rather than as an expiry.
- This is the correct trade and not a defect to fix. Sharing key material to make the decoy
  indistinguishable would mean handing the production signing key to the component whose entire
  purpose is to be broken into, which is exactly the finding that separated the two Secrets in the
  first place. The deception is designed to survive a casual attacker and an automated one; it is not
  designed to survive an attacker who diffs key sets, and claiming otherwise would be the kind of
  guarantee an operator would plan around.

## Cloudflare Tunnel Setup

When using Cloudflare Tunnel, point the tunnel at the bridge service instead of Vault42 service:

```yaml
# In your Cloudflare Tunnel config
ingress:
  - hostname: auth.example.com
    service: http://vault42-bridge:8080
  - service: http_status:404
```

In the Helm chart, set `cloudflared.enabled=true` with the bridge overlay:

```bash
helm install vault42 charts/vault \
  -f charts/vault/values-bridge.yaml \
  --set cloudflared.enabled=true \
  --set cloudflared.tunnelToken="$TUNNEL_TOKEN"
```

## E2E Testing

End-to-end tests are available under `tests/honeypot/` with the `honeypot_e2e` build tag. They spin up real containers via testcontainers-go:

```bash
# Build images first
scripts/build-all.sh

# Run E2E tests (requires Docker)
go test -tags honeypot_e2e -count=1 -v -timeout 5m ./tests/honeypot/...
```
