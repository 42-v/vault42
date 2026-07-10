#!/bin/bash
# Step 3: Go tests (verbose + coverage)
# Outputs: COVER_FILE and TEST_FILE paths to stdout (last 2 lines)
set -eo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=../lib/coverage-env.sh
source "$(dirname "$0")/../lib/coverage-env.sh"

COVER_FILE=$(mktemp)
TEST_FILE=$(mktemp)

# The canonical coverage run (scripts/lib/coverage-env.sh). Step 6 feeds this
# profile straight into readme-gen + coverage.sh, so the README badge,
# docs/badges.json and docs/test-coverage.md all describe one measurement
# instead of three subtly different ones.
cov_require_runtime
cov_run "$COVER_FILE" "$TEST_FILE"

# The remaining suites gate the commit but stay out of the profile: e2e's
# in-process replicas double-count under coverage instrumentation, honeypot
# exercises cmd/bridge rather than internal/, and stress measures throughput.
# -p 1: each spins its own Postgres testcontainer; parallel package binaries
# exhaust container/port resources and flake.
go test -count=1 -v -p 1 ./tests/e2e/... ./tests/honeypot/... ./tests/stress/... >> "$TEST_FILE" 2>&1 || true

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
