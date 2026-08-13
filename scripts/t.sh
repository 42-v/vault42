#!/bin/bash
# Run tests. Args passed to go test (default: all).
# Usage: scripts/t.sh                       — all tests, summary
#        scripts/t.sh ./internal/crypto/...  — single package
#        scripts/t.sh -run TestFoo ./...     — single test
#        scripts/t.sh -v ./tests/attack/...  — verbose
#        scripts/t.sh honeypot               — bridge E2E (-tags honeypot_e2e)
#        scripts/t.sh stress                 — load suite (-tags stress)
#        scripts/t.sh admin                  — admin-gateway E2E
#        scripts/t.sh -tags browser          — browser tests (separate module)
#        scripts/t.sh e2e-browser            — Playwright E2E tests
set -e

root="$(cd "$(dirname "$0")/.." && pwd)"

# Honeypot bridge E2E (needs -tags honeypot_e2e and local vault:dev images).
if [[ "${1:-}" == "honeypot" ]]; then
  shift
  go test -C "$root" -tags honeypot_e2e -count=1 -timeout 5m "$@" ./tests/honeypot/...
  exit $?
fi

# Load/stress suite (needs -tags stress and a live vault).
if [[ "${1:-}" == "stress" ]]; then
  shift
  go test -C "$root" -tags stress -count=1 -timeout 30m "$@" ./tests/stress/...
  exit $?
fi

# Admin gateway E2E (needs mTLS + ADMIN_FIRST_PASSWORD).
if [[ "${1:-}" == "admin" ]]; then
  shift
  go test -C "$root" -count=1 "$@" ./tests/admin/...
  exit $?
fi

# Browser tests live in a separate module (tests/browser/).
# Detect -tags browser and run them from that module.
if [[ " $* " == *" browser "* ]] || [[ " $* " == *"-tags browser"* ]]; then
  go test -C "$root/tests/browser" -count=1 "$@" ./...
  exit $?
fi

# Playwright E2E tests (tests/e2e-browser/). The wrapper is the TestMain:
# no live vault prints SKIP and names VAULT_E2E_BROWSER_REQUIRED.
if [[ "${1:-}" == "e2e-browser" ]]; then
  shift
  bash "$root/tests/e2e-browser/run.sh" "$@"
  exit $?
fi

ARGS="${@:-./...}"
go test -count=1 $ARGS 2>&1
