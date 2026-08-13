#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== @vault42/vue package ==="
pnpm -C packages/vue build

echo "=== Web frontend ==="
rm -rf web/dist
pnpm -C web build

echo "=== Embedding frontend in Go binary ==="
rm -rf internal/frontend/dist
cp -r web/dist internal/frontend/dist

echo "=== Go build + vet ==="
scripts/check.sh

# Stamp the same version the release pipeline stamps, so a locally built binary
# does not report "dev" while claiming to be the thing that shipped.
LDFLAGS="-s -w $(scripts/version-bump.sh --ldflags)"

echo "=== Bridge binary ==="
CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -o bridge ./cmd/bridge

echo "=== Admin Gateway binary ==="
CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -o admin-gateway ./cmd/admin-gateway

echo "=== Docker images ==="
docker build -t vault42:dev .
docker build -t vault42-bridge:dev -f Dockerfile.bridge .
docker build -t vault42-admin-gateway:dev -f Dockerfile.admin-gateway .

echo ""
echo "All builds OK. To deploy:"
echo "  kubectl -n vault42-dev rollout restart deploy/vault42"
