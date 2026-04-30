#!/usr/bin/env bash
# Bootstrap The Vault on MicroK8s (Ubuntu Core / RPi5).
# Usage: ./setup-microk8s.sh [vault-image-tag]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TAG="${1:-latest}"
NAMESPACE="vault"
SECRETS_DIR="${SCRIPT_DIR}/../secrets"
CHART_DIR="${SCRIPT_DIR}/../charts/vault"

echo "=== The Vault — MicroK8s Setup ==="
echo "Image tag: $TAG"
echo ""

# 1. Check MicroK8s
if ! command -v microk8s &>/dev/null; then
    echo "MicroK8s not found. Installing..."
    sudo snap install microk8s --classic
    sudo usermod -aG microk8s "$USER"
    echo "Added $USER to microk8s group. Re-run this script after logging out/in."
    exit 1
fi

echo "Waiting for MicroK8s to be ready..."
microk8s status --wait-ready

# 2. Enable required addons
echo "Enabling addons..."
microk8s enable dns storage ingress helm3

# 3. Generate secrets if not present
if [ ! -d "$SECRETS_DIR" ]; then
    echo "Generating secrets..."
    "$SCRIPT_DIR/generate-secrets.sh" "$SECRETS_DIR"
fi

# 4. Create namespace
microk8s kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | microk8s kubectl apply -f -

# 5. Create Kubernetes secret from generated files
echo "Creating Kubernetes secret..."
microk8s kubectl -n "$NAMESPACE" create secret generic vault-secrets \
    --from-file="$SECRETS_DIR/master-key" \
    --from-file="$SECRETS_DIR/hmac-secret" \
    --from-file="$SECRETS_DIR/admin-token" \
    --from-file="$SECRETS_DIR/db-mig-password" \
    --from-file="$SECRETS_DIR/db-app-password" \
    --from-file="$SECRETS_DIR/pepper" \
    --dry-run=client -o yaml | microk8s kubectl apply -f -

# 6. Install Helm chart with embedded values
echo "Installing Helm chart..."
microk8s helm3 upgrade --install vault "$CHART_DIR" \
    -n "$NAMESPACE" \
    -f "$CHART_DIR/values-embedded.yaml" \
    --set "image.tag=$TAG" \
    --set "secrets.existingSecret=vault-secrets"

# 7. Wait for rollout
echo "Waiting for deployment..."
microk8s kubectl -n "$NAMESPACE" rollout status deployment/vault --timeout=120s

# 8. Print access info
echo ""
echo "=== The Vault is running ==="
echo ""
echo "Namespace: $NAMESPACE"
echo "Image:     ghcr.io/42-v/vault:$TAG"
echo "Profile:   embedded"
echo ""
echo "Admin token:"
cat "$SECRETS_DIR/admin-token"
echo ""
echo ""
echo "Access (via ingress):"
echo "  https://vault.local"
echo ""
echo "Check status:"
echo "  microk8s kubectl -n $NAMESPACE get pods"
echo "  microk8s kubectl -n $NAMESPACE logs deploy/vault"
