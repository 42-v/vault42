#!/usr/bin/env bash
# Deploy the full Vault dev stack to Kubernetes.
# Usage: scripts/deploy-dev.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="vault-dev"
RELEASE="vault"
CHART="$PROJECT_ROOT/charts/vault"
VALUES="$CHART/values-dev.yaml"
CERT_DIR="$PROJECT_ROOT/k8s/dev/certs"

echo "=== Vault Dev Deployment ==="

# Step 1: Generate/refresh TLS certs
echo ""
echo "--- Step 1: TLS Certificates ---"
"$SCRIPT_DIR/dev-certs.sh"

# Step 1b: Generate admin gateway mTLS certs
echo ""
echo "--- Step 1b: Admin Gateway mTLS Certificates ---"
ADMIN_CERT_DIR="$PROJECT_ROOT/k8s/dev/admin-certs"
"$SCRIPT_DIR/generate-admin-certs.sh" "$ADMIN_CERT_DIR"

# Step 2: Build Docker images (frontend embedded in Go binary via go:embed)
echo ""
echo "--- Step 2: Build Docker Images ---"
docker build -t vault:dev "$PROJECT_ROOT"
docker build -t vault-admin-gateway:dev -f "$PROJECT_ROOT/Dockerfile.admin-gateway" "$PROJECT_ROOT"

# Step 3: Create namespace
echo ""
echo "--- Step 3: Kubernetes Namespace ---"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Step 4: Create TLS secret from mkcert certs
echo ""
echo "--- Step 4: TLS Secret ---"
kubectl -n "$NAMESPACE" create secret tls vault-tls \
    --cert="$CERT_DIR/tls.crt" \
    --key="$CERT_DIR/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f -

# Step 5: Create vault secrets (dev defaults)
echo ""
echo "--- Step 5: Vault Secrets ---"

# Generate secrets if they don't exist, otherwise keep existing
if ! kubectl -n "$NAMESPACE" get secret vault-secrets &>/dev/null; then
    MASTER_KEY=$(openssl rand -hex 16)
    HMAC_SECRET=$(openssl rand -hex 32)
    ADMIN_TOKEN=$(openssl rand -hex 32)

    kubectl -n "$NAMESPACE" create secret generic vault-secrets \
        --from-literal=master-key="$MASTER_KEY" \
        --from-literal=db-mig-password="dev-mig-password" \
        --from-literal=db-app-password="dev-app-password" \
        --from-literal=db-admin-password="dev-admin-password" \
        --from-literal=hmac-secret="$HMAC_SECRET" \
        --from-literal=admin-token="$ADMIN_TOKEN" \
        --from-literal=redis-password=""
    echo "Created vault-secrets (admin-token: $ADMIN_TOKEN)"
else
    echo "vault-secrets already exists, keeping existing"
fi

# Step 5b: Create admin gateway TLS secret
echo ""
echo "--- Step 5b: Admin Gateway TLS Secret ---"
kubectl -n "$NAMESPACE" create secret generic vault-admin-tls \
    --from-file=tls.crt="$ADMIN_CERT_DIR/server.crt" \
    --from-file=tls.key="$ADMIN_CERT_DIR/server.key" \
    --from-file=ca.crt="$ADMIN_CERT_DIR/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f -

# Step 6: Helm install/upgrade
echo ""
echo "--- Step 6: Helm Install ---"
helm upgrade --install "$RELEASE" "$CHART" \
    -n "$NAMESPACE" \
    -f "$VALUES" \
    --wait \
    --timeout 5m

# Step 7: Wait for rollout
echo ""
echo "--- Step 7: Rollout Status ---"
kubectl -n "$NAMESPACE" rollout status deploy/"$RELEASE" --timeout=120s || true
kubectl -n "$NAMESPACE" rollout status deploy/"$RELEASE"-admin-gateway --timeout=120s || true

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Vault:         https://vault.localhost"
echo "Health:        curl -k https://vault.localhost/healthz"
echo "Mailpit:       http://mail.localhost"
echo ""
echo "Admin Gateway: https://localhost:9443/admin/login (via SSH tunnel or hostNetwork)"
echo "  Client cert: $ADMIN_CERT_DIR/client.crt"
echo "  Client key:  $ADMIN_CERT_DIR/client.key"
echo "  CA cert:     $ADMIN_CERT_DIR/ca.crt"
echo "  curl:        curl --cert $ADMIN_CERT_DIR/client.crt --key $ADMIN_CERT_DIR/client.key --cacert $ADMIN_CERT_DIR/ca.crt https://localhost:9443/admin/status"
echo ""
echo "Admin token (if just created): kubectl -n $NAMESPACE get secret vault-secrets -o jsonpath='{.data.admin-token}' | base64 -d"
