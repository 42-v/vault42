# Deployment Guide

> Vault42 -- RPi5 / MicroK8s / Ubuntu Core

## Overview

This guide covers deploying Vault42 on a Raspberry Pi 5 or similar ARM64 device running Ubuntu Core with MicroK8s. For production x86 Kubernetes deployments, see the Helm chart documentation in `charts/vault/values.yaml`.

## Prerequisites

- Raspberry Pi 5 (4GB+ RAM) or ARM64 device
- Ubuntu Core 24+ or Ubuntu Server 24.04+
- Internet access for pulling container images
- A domain name pointed at the device (optional, for TLS)

## Quick Start

The automated setup script handles everything:

```bash
VERSION=1.0.0

# Download the release tarball and verify it before unpacking. See
# ../SECURITY.md for the full signature-verification procedure.
curl -LO "https://github.com/42-v/vault42/releases/download/v${VERSION}/vault42_${VERSION}_linux_arm64.tar.gz"
tar xzf "vault42_${VERSION}_linux_arm64.tar.gz"

# Run the setup script. The argument is a container image tag, which carries
# no leading "v"; it defaults to "latest".
./scripts/setup-microk8s.sh "$VERSION"
```

This will:

1. Install MicroK8s (if not present)
2. Enable required addons (dns, storage, ingress, helm3)
3. Generate all secrets
4. Create the Kubernetes namespace and secret
5. Install the Helm chart with embedded profile values
6. Wait for the deployment to be ready

## Manual Setup

### 1. Install MicroK8s

```bash
sudo snap install microk8s --classic
sudo usermod -aG microk8s $USER
newgrp microk8s

microk8s status --wait-ready
microk8s enable dns storage ingress helm3
```

### 2. Generate Secrets

```bash
./scripts/generate-secrets.sh ./secrets
```

This generates all required secrets including `signing-key` (RSA-2048 PKCS#8 PEM for JWT signing). Save the admin token printed at the end -- it is shown only once.

That token is the admin credential, not a placeholder. Mounted as `ADMIN_TOKEN_FILE`, it seeds `admin_config.admin_token_hash` on first boot and is what `--admin-token` is checked against from then on. Mount a file holding its Argon2id hash instead if you would rather the secret in the cluster not be usable as a credential; both forms are accepted. See [config.md](config.md#admin-token-provisioning).

### 3. Create Kubernetes Resources

```bash
microk8s kubectl create namespace vault42

microk8s kubectl -n vault42 create secret generic vault42-secrets \
  --from-file=./secrets/master-key \
  --from-file=./secrets/hmac-secret \
  --from-file=./secrets/admin-token \
  --from-file=./secrets/db-mig-password \
  --from-file=./secrets/db-app-password \
  --from-file=./secrets/pepper \
  --from-file=./secrets/signing-key
```

**Note:** The `signing-key` is required for multi-pod deployments -- all pods must share the same signing key so that JWTs issued by one pod can be validated by any other. Without it, each pod generates an ephemeral key at startup. `redis-password` is left out of the block above because the embedded profile uses an in-memory cache; `generate-secrets.sh` still produces it, so add `--from-file=./secrets/redis-password` when the cache backend is Redis, or the server comes up with no `REDIS_PASS_FILE`.

The whole Secret is mounted as a directory at `secrets.mountPath` (default `/run/secrets`), so any additional key you add to it appears as a file there without a chart change. What the chart does *not* do is invent the matching `_FILE` environment variable -- see [KMS root key](#kms-root-key-optional) below.

### KMS root key (optional)

The KEK envelope-unwrap oracle `POST /kms/unwrap` is mounted **only** when `KMS_ROOT_KEY_FILE` points at a readable file of at least 32 bytes (the `POST /kms/unwrap` mount in `internal/server/server.go`). Leave it unset and the endpoint does not exist, which is the right default for a deployment that has no envelope-encryption consumer.

`scripts/generate-secrets.sh` does not generate this key and the Helm chart does not template the variable. Both steps are manual:

```bash
# 1. Generate the root secret. It is a KDF input, not a key: 32 random bytes.
openssl rand 32 > ./secrets/kms-root-key

# 2. Add it to the same Secret the chart already mounts.
microk8s kubectl -n vault42 create secret generic vault42-secrets \
  --from-file=./secrets/kms-root-key \
  --dry-run=client -o yaml | microk8s kubectl apply -f -

# 3. Point the server at it. The chart has no values key for this, so set it on
#    the Deployment directly and re-apply after every `helm upgrade`.
microk8s kubectl -n vault42 set env deployment/vault42 \
  KMS_ROOT_KEY_FILE=/run/secrets/kms-root-key
```

Operational properties worth knowing before you enable it:

- **Per-kid KEKs are derived, not stored.** One root secret produces every KEK via HKDF-SHA256 under a versioned, domain-separated label, cryptographically separate from `MASTER_KEY_FILE`. You do not provision a secret per kid.
- **Losing the root secret is unrecoverable.** Every envelope wrapped under it becomes permanently unopenable. Back it up the way you back up the master key, which is to say offline.
- **Rotating it invalidates every existing envelope.** There is no dual-root overlap window. Re-wrap with `vault kms wrap` before swapping the root.
- **The endpoint is a key-release oracle**, so it ships with a fail-closed per-IP rate limit (30/min) and a synchronous audit record per attempt. A Redis outage rejects unwraps rather than degrading to a per-pod counter. Read [security.md](security.md) AR-10 before exposing it: the authorizing token comes from `POST /client/token`, which is not a DPoP issuance path, so it is a plain Bearer token even when `VAULT_DPOP_ENABLED` is on.

### DPoP

`VAULT_DPOP_ENABLED` is a working sender-constraint for access tokens issued with a DPoP proof. Turning it on mounts the DPoP middleware on login, refresh, the 2FA verify endpoints and every authenticated route. A login, refresh or 2FA-challenge request that presents a valid `DPoP` proof has that proof's JWK thumbprint written into the issued access or challenge token as `cnf.jkt` (RFC 9449 §6.1, `internal/service/token.go`). A later request presenting that token must use the `DPoP` authorization scheme and a matching proof (`internal/middleware/dpop.go`). A token issued without a proof stays an ordinary bearer token, so enabling the flag does not break existing clients.

Two limits are real: refresh tokens are opaque and are not sender-bound, and the server neither issues nor requires a `DPoP-Nonce`. `POST /client/token` is not a DPoP issuance path, so client-credential tokens used by `/kms/unwrap` and `/mint` stay unbound. Enable it when user-facing clients can send proofs. Leaving it at the default (`false`) leaves that control off.

### 4. Install the Helm Chart

```bash
microk8s helm3 upgrade --install vault42 charts/vault \
  -n vault42 \
  -f charts/vault/values-embedded.yaml \
  --set image.tag=1.0.0 \
  --set secrets.existingSecret=vault42-secrets \
  --set origin=https://vault42.local
```

### 5. Verify

```bash
microk8s kubectl -n vault42 get pods
microk8s kubectl -n vault42 logs deploy/vault42
```

## Resource Usage

### Production

Production defaults (in `charts/vault/values.yaml`):

| Component | CPU Request | Memory Request | CPU Limit | Memory Limit |
|-----------|-----------|---------------|-----------|-------------|
| Vault42 | 250m | 256Mi | 1 | 512Mi |

**512 MiB minimum memory limit is required.** Each Argon2id password hash allocates 46 MiB. Vault42 limits concurrent Argon2id operations to 4 via a counting semaphore, so peak Argon2id memory is 184 MiB. Combined with the Go runtime and other allocations, pods below 512 MiB risk OOM kills under load.

The HPA scales on both CPU (60% target) and memory (70% target). Scaling behavior: up to 2 pods per 60 seconds with 30-second stabilization (scale up), 1 pod per 120 seconds with 300-second stabilization (scale down).

### Embedded (Raspberry Pi 5)

The embedded profile targets minimal resource usage:

| Component | CPU Request | Memory Request | CPU Limit | Memory Limit |
|-----------|-----------|---------------|-----------|-------------|
| Vault42 | 50m | 64Mi | 200m | 128Mi |
| PostgreSQL | 50m | 64Mi | 200m | 128Mi |

Total idle memory: ~60-80 MB for Vault42 process.

## Configuration

The embedded profile uses:

- **Cache**: In-memory (no Redis required)
- **Database**: 5 max connections
- **Auto-migrate**: Enabled
- **Frontend**: Embedded in Go binary (when `VAULT_SERVE_FRONTEND=true`)
- **TLS**: Disabled (handle at ingress level)

### IP Access Control (Cloudflare / Proxy)

When deployed behind a reverse proxy, configure IP-based access control and geo-fencing. **Only `TRUSTED_PROXIES` has a chart value today**; the rest are read by the server but are not templated by `charts/vault`, so setting them takes a second step.

```yaml
# my-overrides.yaml -- this one the chart understands
trustedProxies: "173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22"
```

```bash
# The rest go on the Deployment directly, and must be re-applied after every
# `helm upgrade`, which regenerates the pod spec from the chart.
microk8s kubectl -n vault42 set env deployment/vault42 \
  REAL_IP_HEADER=CF-Connecting-IP \
  GEO_IP_HEADER=CF-IPCountry \
  IP_ALLOWLIST=203.0.113.0/24 \
  GEO_ALLOWLIST=SK,CZ,HU \
  GEO_BLOCKLIST=T1
```

`REAL_IP_HEADER` and `GEO_IP_HEADER` are proxy-agnostic: set them to whatever header your proxy injects (`X-Real-IP` for nginx, a custom header for anything else). Geo-fencing is inert without `GEO_IP_HEADER` -- an absent header is not a country match, so `GEO_ALLOWLIST` alone blocks nobody. Use `T1` in `GEO_BLOCKLIST` for Cloudflare's Tor exit-node code. The IP blocklist supports runtime updates for dynamic banning.

**Get `TRUSTED_PROXIES` right or the rest is theatre.** Client IP resolution only honours `REAL_IP_HEADER` and `X-Forwarded-For` when the direct peer is on the trusted list; leave the list empty and every header is ignored, so rate limiting and audit attribution both key on the proxy's own address. Set it too wide and a caller can forge its own IP. The evaluation order is IP allowlist, IP blocklist, geo allowlist, geo blocklist; `/healthz` and `/readyz` bypass all four.

To customize, create a values override file:

```bash
microk8s helm3 upgrade vault42 charts/vault \
  -n vault42 \
  -f charts/vault/values-embedded.yaml \
  -f my-overrides.yaml
```

## Bridge Deployment (Honeypot Bridge)

For a transparent reverse proxy that detects attackers and silently reroutes them to a honeypot, see the dedicated [Bridge Deployment Guide](bridge.md).

Quick start:

```bash
# Build images
scripts/build-all.sh

# Deploy with Helm (bridge mode: dual vaults + bridge proxy)
helm install vault42 charts/vault -f charts/vault/values-bridge.yaml \
  --set origin=https://auth.example.com \
  --set secrets.existingSecret=vault42-secrets
```

The bridge deployment creates three components: a real Vault42 (production DB), a honeypot Vault42 (separate DB), and the bridge proxy.

**What "isolated" means here, concretely.** This document used to say network
policies ensure complete isolation, which was a claim about intent rather than
about the manifests. It was not true: the honeypot deployment mounted the
*production* Secret -- master key, HMAC secret, pepper, signing key, admin token
and both database passwords -- into the one component whose entire purpose is to
be attacked. Code execution in the decoy reached the real estate's keys.

The isolation the chart now provides is four specific things, each of which you
can check in a rendered manifest rather than take on trust:

1. The honeypot workload mounts its **own Secret**, not the production one. The
   names are separate values, and neither defaults to the other.
2. The chart **refuses to render** when the two Secret names resolve to the same
   value, so the collision cannot be reintroduced by an operator copying a
   values file.
3. The honeypot runs against its **own PostgreSQL** (`honeypot-postgres`), with
   NetworkPolicies that permit the decoy no egress to the production database or
   Redis.
4. Tests hold the boundary **in both directions**: that the honeypot cannot
   reach production secrets, and that production is not accidentally pointed at
   the honeypot's.

Treat any deployment whose honeypot and production Secret names match as
compromised in the direction that matters, and rotate before redeploying.

## Honeypot Deployment

To deploy as a standalone honeypot for threat observation:

```bash
microk8s helm3 upgrade --install vault42-honeypot charts/vault \
  -n vault42-honeypot \
  -f charts/vault/values-embedded.yaml \
  --set profile=honeypot \
  --set secrets.existingSecret=vault42-secrets \
  --set origin=https://honeypot.example.com
```

Trap users and the alert webhook are not chart values either. Set them on the Deployment, and re-apply after each `helm upgrade`:

```bash
microk8s kubectl -n vault42-honeypot set env deployment/vault42-honeypot \
  VAULT_HONEYPOT_WEBHOOK=https://your-webhook.example.com/alerts \
  VAULT_HONEYPOT_TRAP_USERS=admin@example.com,root@example.com,test@example.com
```

Both are required for alerting: the webhook fires only on a login attempt against a name in the trap list, and an unset webhook means the attempt is audited (risk 100) but nothing is pushed anywhere. Never point a honeypot at a real SMTP relay -- use Mailpit or discard.

## Upgrades

### The mechanics

```bash
microk8s helm3 upgrade vault42 charts/vault \
  -n vault42 \
  -f charts/vault/values-embedded.yaml \
  --set image.tag=<target-version>

microk8s kubectl -n vault42 rollout status deployment/vault42
```

`helm upgrade` regenerates the whole pod spec from the chart. Anything you applied with
`kubectl set env` -- the KMS root key path, the IP and geo settings, honeypot trap users --
is discarded and must be re-applied before the rollout completes. Check with
`kubectl -n vault42 set env deployment/vault42 --list` after every upgrade.

### Migrations

Migrations are numbered, forward-only and applied in filename order against the
`public.schema_migrations` ledger (`migrate.Run`, `internal/migrate/migrate.go`). They run as the
`vault_mig` role, whose connection is closed once they finish; there is no down-migration and
no rollback path. Two ways to run them:

- **`VAULT_AUTO_MIGRATE=true`** (the default in the `embedded`, `dev` and `honeypot` profiles):
  each pod migrates at startup. Fine for a single replica.
- **Manually, before the rollout** (the default in `production`, where `autoMigrate` is
  `false`): several replicas racing the same DDL is not a supported configuration. Run the new
  image once as a job, or exec a single pod, then roll the rest.

Take a database backup before an upgrade that adds migrations. See [Backup](#backup).

### Upgrading 0.9.x to 1.0.0

1.0.0 is the first release under the semantic-versioning commitment in
[SECURITY.md](../SECURITY.md#versioning-and-compatibility). Read the `CHANGELOG.md` entry in
full before upgrading; the notes below are the deployment-affecting parts.

**Order of operations.**

1. Back up PostgreSQL. Migrations are forward-only.
2. Verify the new images (`cosign verify`, see
   [SECURITY.md](../SECURITY.md#verifying-releases)). An unverified image is not an upgrade.
3. Apply migrations, then roll the Deployment.
4. Re-apply any `kubectl set env` values.
5. Confirm `/readyz` is green and that logins and refreshes both succeed before removing the
   old replica set.

**Things that need a decision, not just a rollout.**

- **Signing keys: file to database.** If you are still on `SIGNING_KEY_FILE` alone, setting
  `VAULT_KEY_ROTATION_DB=true` imports the mounted key into `auth.signing_keys` on first boot
  and every pod then polls the table (`VAULT_KEY_REFRESH_INTERVAL`, default 60s). This is the
  prerequisite for zero-downtime rotation from the admin gateway. Two traps: revocation is
  terminal and keyed by a kid derived from the public key, so re-importing a revoked PEM fails
  startup with `keystore: key is revoked` rather than reactivating it; and revoking the only
  active key stops token issuance entirely (`keystore: no active signing key`). Rotate first,
  then revoke. Once the key is in the database you can unmount `SIGNING_KEY_FILE`.
- **`VAULT_AUDIT_RETENTION_DAYS` and `VAULT_RECOVERY_RETENTION_DAYS` both default to `0`,
  meaning never purge.** Audit rows and account-recovery escrow records both hold personal
  data, so an operator processing personal data under GDPR needs a horizon on each. Set them
  deliberately; see [PRIVACY.md](PRIVACY.md) §4.
- **Check for undocumented escape hatches in your own manifests.** If your 0.9.x deployment
  set `VAULT_ALLOW_PLAINTEXT`, `VAULT_ALLOW_RATE_LIMIT_DISABLED` or
  `VAULT_EMBEDDED_TRUSTED_UPSTREAM`, each is a security guard you are running without. They
  are now documented together in
  [config.md](config.md#fail-closed-overrides-read-this-before-production). 1.0.0 is a good
  moment to remove them.
- **`VAULT_DPOP_ENABLED` is a working control.** Default remains `false` so existing
  Bearer clients keep working. Turn it on when user-facing clients can send DPoP proofs;
  see [DPoP](#dpop) above. Do not count it as a mitigation for `/kms/unwrap` or `/mint`:
  those tokens come from `POST /client/token`, which does not stamp `cnf.jkt`.

**What does not change.** Route paths, the JWT claim set and the error-code vocabulary are the
1.0.0 stability contract, so a 0.9.x client keeps working. Root paths are v1; there is no
`/v1` prefix and adding one would be a major bump.

## The bundled PostgreSQL

`charts/vault` ships an optional in-cluster PostgreSQL behind
`postgres.enabled`, labelled "dev/embedded only" and **disabled by default**.
Two things about it are worth knowing before you reach for it.

**It has never started, on any released version.** The initialisation script's
second here-document closed with an indented `EOSQL` against a `<<-` heredoc.
`<<-` strips leading *tabs*, not spaces, so the delimiter was never recognised;
bash parses the whole script before executing any of it, so the container exited
2 having run nothing at all and the `vault_app` role was never created. It was
reproduced against the base commit and fixed. If you tried `postgres.enabled` on
1.0.0 or earlier and it failed in a way that looked like a database problem,
that was the reason.

**It is a development convenience, not a supported production path.** It runs a
single replica against a `ReadWriteOnce` PVC with no backup, no failover and no
connection pooler, and it is the one workload in the chart that does not meet
the Kubernetes Pod Security Standards restricted profile -- it sets no
`runAsNonRoot` and does not drop capabilities. The compliance register excludes
it from that claim by name rather than by silence. For anything you care about,
run PostgreSQL as a managed service or as its own operator-managed cluster and
point `database.host` at it.

## Backup

The only stateful component is PostgreSQL. Back up the PVC:

```bash
microk8s kubectl -n vault42 exec deploy/vault42-postgres -- \
  pg_dump -U vault_mig vault42 > vault42-backup-$(date +%Y%m%d).sql
```

## Branding

Vault42 uses neon green (#00FF42) on pure black (#000000) as the default color scheme. This applies to email templates and the embedded Vue frontend.

Customize via environment variables:

- `VAULT_PRIMARY_COLOR`: Hex color code (default: `#00FF42`)
- `VAULT_LOGO_URL`: URL to your logo image
- `VAULT_APP_NAME`: Application display name (default: `Vault42`)
