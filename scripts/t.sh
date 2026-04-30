#!/bin/bash
# Run tests. Args passed to go test (default: all).
# Usage: scripts/t.sh                       — all tests, summary
#        scripts/t.sh ./internal/crypto/...  — single package
#        scripts/t.sh -run TestFoo ./...     — single test
#        scripts/t.sh -v ./tests/attack/...  — verbose
#        scripts/t.sh -tags browser          — browser tests (separate module)
#        scripts/t.sh e2e-browser            — Playwright E2E tests
set -e

# Browser tests live in a separate module (tests/browser/).
# Detect -tags browser and run them from that module.
if [[ " $* " == *" browser "* ]] || [[ " $* " == *"-tags browser"* ]]; then
  cd "$(dirname "$0")/../tests/browser"
  go test -count=1 "$@" ./... 2>&1
  exit $?
fi

# Playwright E2E tests (tests/e2e-browser/).
if [[ "$1" == "e2e-browser" ]]; then
  shift
  cd "$(dirname "$0")/../tests/e2e-browser"
  npx playwright test "$@" 2>&1
  exit $?
fi

ARGS="${@:-./...}"
go test -count=1 $ARGS 2>&1
