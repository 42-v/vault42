#!/bin/bash
# coverage-full.sh — TRUE statement coverage of internal/ across the FULL test
# suite, including the DB-backed integration + compliance suites that the default
# coverage.sh deliberately excludes (they need a live Postgres/Redis via
# testcontainers, so the standard metric is unit+attack+fuzz only).
#
# The default `scripts/coverage.sh` number (~78%) is therefore a UNIT-ONLY floor:
# large parts of internal/ (repository/postgres, keystore, migrate, cache
# backends, the wired server) are only exercised through integration/e2e. This
# script counts those, giving the real figure (~85% as of 0.8.9).
#
# Requires a container runtime. Honors DOCKER_HOST for rootless podman, e.g.:
#   DOCKER_HOST=unix:///run/user/1000/podman/podman.sock \
#   TESTCONTAINERS_RYUK_DISABLED=true scripts/coverage-full.sh
#
# -p 1 serializes the package test binaries so the integration + multireplica
# suites don't contend for testcontainer ports/resources.
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${COVER_FILE:-$(mktemp)}"
export GOTOOLCHAIN=auto GOFLAGS=-mod=mod

echo "Running FULL-suite coverage (internal/ via unit+attack+fuzz+integration+compliance)..."
# e2e/multireplica is excluded: its two in-process replicas + shared containers
# are flaky under coverage instrumentation and double-count in-process code.
go test -count=1 -p 1 -coverprofile="$PROFILE" -coverpkg=./internal/... \
    ./internal/... ./tests/unit/... ./tests/attack/... ./tests/fuzz/... \
    ./tests/integration/... ./tests/compliance/... \
    > /tmp/coverage-full.out 2>&1 || true

if grep -q '^--- FAIL:' /tmp/coverage-full.out; then
  echo "ERROR: test failures during full-coverage run:" >&2
  grep '^--- FAIL:' /tmp/coverage-full.out >&2
  exit 1
fi

TOTAL=$(go tool cover -func="$PROFILE" | awk '$1 == "total:" {print $NF}')
echo "TRUE coverage (internal/, full suite): $TOTAL"
