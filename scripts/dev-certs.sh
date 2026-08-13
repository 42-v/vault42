#!/usr/bin/env bash
# Generate locally-trusted TLS certificates for dev using mkcert.
# Certificates are placed in k8s/dev/certs/ (gitignored).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$PROJECT_ROOT/k8s/dev/certs"
DOMAIN="vault.localhost"

# Check mkcert is installed
if ! command -v mkcert &>/dev/null; then
    echo "ERROR: mkcert is not installed."
    echo ""
    echo "Install it:"
    echo "  macOS:  brew install mkcert"
    echo "  Linux:  https://github.com/FiloSottile/mkcert#installation"
    echo "  Windows: choco install mkcert  OR  scoop install mkcert"
    exit 1
fi

# Install local CA (idempotent)
mkcert -install 2>/dev/null || true

# Create cert directory
mkdir -p "$CERT_DIR"

# Generate cert + key
mkcert -cert-file "$CERT_DIR/tls.crt" -key-file "$CERT_DIR/tls.key" "$DOMAIN"

# Copy root CA for trust store (ingress controller, test clients)
CAROOT="$(mkcert -CAROOT)"
if [ -f "$CAROOT/rootCA.pem" ]; then
    cp "$CAROOT/rootCA.pem" "$CERT_DIR/rootCA.pem"
fi

echo "Certificates generated in $CERT_DIR"
echo "  tls.crt, tls.key — for $DOMAIN"
echo "  rootCA.pem — local CA root (for trust)"
