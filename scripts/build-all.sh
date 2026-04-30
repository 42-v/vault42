#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== @vault/vue package ==="
pnpm -C packages/vue build

echo "=== Web frontend ==="
rm -rf web/dist
pnpm -C web build

echo "=== Embedding frontend in Go binary ==="
rm -rf internal/frontend/dist
cp -r web/dist internal/frontend/dist

echo "=== Go build + vet ==="
scripts/check.sh

echo "=== Bridge binary ==="
CGO_ENABLED=0 go build -ldflags="-s -w" -o bridge ./cmd/bridge

echo "=== Admin Gateway binary ==="
CGO_ENABLED=0 go build -ldflags="-s -w" -o admin-gateway ./cmd/admin-gateway

echo "=== Docker images ==="
docker build -t vault:dev .
docker build -t vault-bridge:dev -f Dockerfile.bridge .
docker build -t vault-admin-gateway:dev -f Dockerfile.admin-gateway .

echo ""
echo "All builds OK. To deploy:"
echo "  kubectl -n vault-dev rollout restart deploy/vault"
