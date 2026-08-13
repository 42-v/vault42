#!/bin/bash
set -e

echo "=== The Vault Test Suite ==="
echo ""

# Start test infrastructure
echo "Starting test infrastructure..."
docker compose -f docker-compose.test.yml up -d --wait
echo "Infrastructure ready."
echo ""

# Unit tests (internal packages)
echo "--- Unit Tests (internal) ---"
go test ./internal/... -count=1 -race -timeout 120s
echo ""

# Handler tests
echo "--- Handler Tests ---"
go test ./tests/unit/... -count=1 -timeout 120s
echo ""

# Attack tests (crypto-level)
echo "--- Attack Tests ---"
go test ./tests/attack/... -count=1 -timeout 300s
echo ""

# Fuzz tests (short run)
echo "--- Fuzz Tests (10s each) ---"
go test ./tests/fuzz/... -count=1 -timeout 120s
echo ""

echo "=== All tests passed ==="

# Cleanup
echo "Stopping test infrastructure..."
docker compose -f docker-compose.test.yml down -v
echo "Done."
