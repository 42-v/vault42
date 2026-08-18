#!/usr/bin/env bash
# Generate all Vault secrets for production deployment.
# Usage: ./generate-secrets.sh [output-dir]
set -euo pipefail

# shellcheck source=lib/credential-output.sh
source "$(dirname "$0")/lib/credential-output.sh"

SECRETS_DIR="${1:-./secrets}"
mkdir -p "$SECRETS_DIR"

echo "Generating Vault secrets in $SECRETS_DIR..."

# Master key: 32 raw bytes for AES-256
openssl rand 32 > "$SECRETS_DIR/master-key"

# HMAC secret: 64 hex chars = 32 bytes
openssl rand -hex 32 > "$SECRETS_DIR/hmac-secret"

# Admin CLI token: shown once, user must save
openssl rand -hex 32 > "$SECRETS_DIR/admin-token"

# Database passwords
openssl rand -hex 16 > "$SECRETS_DIR/db-mig-password"
openssl rand -hex 16 > "$SECRETS_DIR/db-app-password"

# Redis password
openssl rand -hex 16 > "$SECRETS_DIR/redis-password"

# Password pepper
openssl rand -hex 32 > "$SECRETS_DIR/pepper"

# RSA signing key: shared across all pods for JWT signing (PKCS#8 PEM)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM > "$SECRETS_DIR/signing-key" 2>/dev/null

# Lock down permissions
chmod 400 "$SECRETS_DIR"/*

echo ""
echo "Secrets generated in $SECRETS_DIR"
echo ""
show_credential_file "Admin token (save this — shown once)" "$SECRETS_DIR/admin-token"
echo ""
echo "Next steps:"
echo "  1. Create Kubernetes secret:"
echo "     kubectl create secret generic vault-secrets \\"
echo "       --from-file=$SECRETS_DIR/master-key \\"
echo "       --from-file=$SECRETS_DIR/hmac-secret \\"
echo "       --from-file=$SECRETS_DIR/admin-token \\"
echo "       --from-file=$SECRETS_DIR/db-mig-password \\"
echo "       --from-file=$SECRETS_DIR/db-app-password \\"
echo "       --from-file=$SECRETS_DIR/redis-password \\"
echo "       --from-file=$SECRETS_DIR/pepper \\"
echo "       --from-file=$SECRETS_DIR/signing-key"
echo "  2. Reference the secret name in your Helm values: secrets.existingSecret"
