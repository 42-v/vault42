#!/bin/bash
# Step 3: Go tests (verbose + coverage)
# Outputs: COVER_FILE and TEST_FILE paths to stdout (last 2 lines)
set -eo pipefail
cd "$(dirname "$0")/../.."

COVER_FILE=$(mktemp)
TEST_FILE=$(mktemp)

go test -count=1 -v -coverprofile="$COVER_FILE" ./internal/... > "$TEST_FILE" 2>&1 || true
# -p 1: serialize package test binaries. tests/integration, tests/e2e/multireplica
# and tests/compliance each spin their own Postgres testcontainer; running the
# package binaries in parallel exhausts container/port resources and flakes.
go test -count=1 -v -p 1 ./tests/... >> "$TEST_FILE" 2>&1 || true

PASS=$(grep -c '^--- PASS' "$TEST_FILE" || true)
FAIL=$(grep -c '^--- FAIL' "$TEST_FILE" || true)
PKGS=$(grep -cE '^(ok|FAIL)\s' "$TEST_FILE" || true)

if [ "$FAIL" -gt 0 ]; then
  grep -B1 '^--- FAIL' "$TEST_FILE" >&2
  grep '^FAIL\s' "$TEST_FILE" >&2
fi

printf "%d %d %d\n" "$PASS" "$FAIL" "$PKGS"
echo "$COVER_FILE"
echo "$TEST_FILE"
