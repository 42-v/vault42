# Deployment Guide

> Vault42 -- RPi5 / MicroK8s / Ubuntu Core

## Overview

This guide covers deploying Vault42 on a Raspberry Pi 5 or similar ARM64 device running Ubuntu Core with MicroK8s. For production x86 Kubernetes deployments, see the Helm chart documentation in `charts/vault42/values.yaml`.

## Prerequisites

- Raspberry Pi 5 (4GB+ RAM) or ARM64 device
- Ubuntu Core 24+ or Ubuntu Server 24.04+
- Internet access for pulling container images
- A domain name pointed at the device (optional, for TLS)

## Quick Start

The automated setup script handles everything:

```bash
# Download the release tarball
curl -LO https://github.com/42-v/vault42/releases/latest/download/vault_*_linux_arm64.tar.gz
tar xzf vault_*_linux_arm64.tar.gz

# Run the setup script
./scripts/setup-microk8s.sh v1.0.0
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

**Note:** The `signing-key` is required for multi-pod deployments -- all pods must share the same signing key so that JWTs issued by one pod can be validated by any other. Without it, each pod generates an ephemeral key at startup.

### 4. Install the Helm Chart

```bash
microk8s helm3 upgrade --install vault42 charts/vault42 \
  -n vault42 \
  -f charts/vault42/values-embedded.yaml \
  --set image.tag=v1.0.0 \
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

Production defaults (in `charts/vault42/values.yaml`):

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

When deployed behind a reverse proxy, configure IP-based access control and geo-fencing:

```yaml
env:
  TRUSTED_PROXIES: "173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22"
  REAL_IP_HEADER: "CF-Connecting-IP"    # or "X-Real-IP" for nginx
  GEO_IP_HEADER: "CF-IPCountry"        # or custom header from your proxy
  IP_ALLOWLIST: "203.0.113.0/24"       # optional: restrict to known IPs
  GEO_ALLOWLIST: "SK,CZ,HU"           # optional: restrict to countries
  GEO_BLOCKLIST: "T1"                  # optional: block Tor exit nodes
```

The `REAL_IP_HEADER` and `GEO_IP_HEADER` settings are proxy-agnostic -- set them to whatever header your proxy injects. The IP blocklist supports runtime updates for dynamic banning.

To customize, create a values override file:

```bash
microk8s helm3 upgrade vault42 charts/vault42 \
  -n vault42 \
  -f charts/vault42/values-embedded.yaml \
  -f my-overrides.yaml
```

## Bridge Deployment (Honeypot Bridge)

For a transparent reverse proxy that detects attackers and silently reroutes them to a honeypot, see the dedicated [Bridge Deployment Guide](bridge.md).

Quick start:

```bash
# Build images
scripts/build-all.sh

# Deploy with Helm (bridge mode: dual vaults + bridge proxy)
helm install vault42 charts/vault42 -f charts/vault42/values-bridge.yaml \
  --set origin=https://auth.example.com \
  --set secrets.existingSecret=vault42-secrets
```

The bridge deployment creates three components: a real Vault42 (production DB), a honeypot Vault42 (separate DB), and the bridge proxy. Network policies ensure complete isolation between real and honeypot environments.

## Honeypot Deployment

To deploy as a standalone honeypot for threat observation:

```bash
microk8s helm3 upgrade --install vault42-honeypot charts/vault42 \
  -n vault42-honeypot \
  -f charts/vault42/values-embedded.yaml \
  --set profile=honeypot \
  --set secrets.existingSecret=vault42-secrets \
  --set origin=https://honeypot.example.com
```

Set trap users and webhook via ConfigMap or values override:

```yaml
# honeypot-values.yaml
profile: honeypot
env:
  VAULT_HONEYPOT_WEBHOOK: "https://your-webhook.example.com/alerts"
  VAULT_HONEYPOT_TRAP_USERS: "admin@example.com,root@example.com,test@example.com"
```

## Upgrades

```bash
microk8s helm3 upgrade vault42 charts/vault42 \
  -n vault42 \
  -f charts/vault42/values-embedded.yaml \
  --set image.tag=v1.1.0

microk8s kubectl -n vault42 rollout status deployment/vault42
```

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
