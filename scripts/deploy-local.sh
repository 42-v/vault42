#!/usr/bin/env bash
# Deploy Vault locally with Cloudflare Tunnel for real HTTPS.
# Usage: scripts/deploy-local.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="vault-local"
RELEASE="vault"
CHART="$PROJECT_ROOT/charts/vault"
VALUES="$CHART/values-local.yaml"
TUNNEL_NAME="vault-local"
DOMAIN="vault.42-v.com"

echo "=== Vault Local Production Deployment (Cloudflare Tunnel) ==="

# Step 0: Prerequisites
echo ""
echo "--- Step 0: Prerequisites ---"
for cmd in docker kubectl helm cloudflared; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not found"
        exit 1
    fi
done
echo "All prerequisites found."

# Check for old dev namespace
if kubectl get namespace vault-dev &>/dev/null; then
    echo ""
    echo "WARNING: Old vault-dev namespace detected."
    read -r -p "Delete vault-dev namespace? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        kubectl delete namespace vault-dev
        echo "Deleted vault-dev namespace."
    fi
fi

# Step 1: Build Docker image (multi-stage, includes frontend)
echo ""
echo "--- Step 1: Build Docker Image ---"
docker build -t vault42:dev "$PROJECT_ROOT"

# Step 2: Create namespace
echo ""
echo "--- Step 2: Kubernetes Namespace ---"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Step 3: Create vault secrets (if not existing)
echo ""
echo "--- Step 3: Vault Secrets ---"
if ! kubectl -n "$NAMESPACE" get secret vault-secrets &>/dev/null; then
    MASTER_KEY=$(openssl rand -hex 16)
    HMAC_SECRET=$(openssl rand -hex 32)
    ADMIN_TOKEN=$(openssl rand -hex 32)

    kubectl -n "$NAMESPACE" create secret generic vault-secrets \
        --from-literal=master-key="$MASTER_KEY" \
        --from-literal=db-mig-password="local-mig-password" \
        --from-literal=db-app-password="local-app-password" \
        --from-literal=hmac-secret="$HMAC_SECRET" \
        --from-literal=admin-token="$ADMIN_TOKEN" \
        --from-literal=redis-password=""
    echo "Created vault-secrets (admin-token: $ADMIN_TOKEN)"
else
    echo "vault-secrets already exists, keeping existing"
fi

# Step 4: Cloudflare Tunnel setup
echo ""
echo "--- Step 4: Cloudflare Tunnel ---"

# Check if logged in
if ! cloudflared tunnel list &>/dev/null; then
    echo "Not logged in to Cloudflare. Running login..."
    cloudflared tunnel login
fi

# Create tunnel if it doesn't exist
if ! cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
    echo "Creating tunnel: $TUNNEL_NAME"
    cloudflared tunnel create "$TUNNEL_NAME"
fi

# Get tunnel token
echo "Retrieving tunnel token..."
TUNNEL_TOKEN=$(cloudflared tunnel token "$TUNNEL_NAME")

# Create k8s secret for tunnel token
kubectl -n "$NAMESPACE" create secret generic cloudflared-token \
    --from-literal=tunnel-token="$TUNNEL_TOKEN" \
    --dry-run=client -o yaml | kubectl apply -f -
echo "Tunnel token stored in cloudflared-token secret."

# Step 5: Helm install/upgrade
echo ""
echo "--- Step 5: Helm Install ---"
helm upgrade --install "$RELEASE" "$CHART" \
    -n "$NAMESPACE" \
    -f "$VALUES" \
    --set cloudflared.existingSecret=cloudflared-token \
    --wait \
    --timeout 5m

# Step 6: Create DNS route (idempotent)
echo ""
echo "--- Step 6: DNS Route ---"
cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null || echo "DNS route already exists for $DOMAIN"

# Step 7: Wait for rollout
echo ""
echo "--- Step 7: Rollout Status ---"
kubectl -n "$NAMESPACE" rollout status deploy/"$RELEASE" --timeout=120s || true

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Access:  https://$DOMAIN"
echo "Health:  curl https://$DOMAIN/healthz"
echo "Mailpit: kubectl -n $NAMESPACE port-forward svc/$RELEASE-mailpit 8025:8025"
echo ""
echo "Admin token (if just created): kubectl -n $NAMESPACE get secret vault-secrets -o jsonpath='{.data.admin-token}' | base64 -d"
