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

# cov_check_failures is the only thing that can see a run which did not finish.
# `go test` killed by a timeout or an OOM emits "FAIL\tpkg\t1800s" with no
# "--- FAIL:" line, so the grep below counts zero, the verdict reads OK, and
# step 6 regenerates the badge and docs/test-coverage.md from a truncated
# profile -- which then looks like a coverage regression rather than a suite
# that never completed. Run the guard in a subshell so this step keeps its
# contract of printing counts and both file paths, and fold the verdict into
# FAIL so scripts/precommit.sh fails the commit through its existing path.
INCOMPLETE=0
( cov_check_failures "$TEST_FILE" ) || INCOMPLETE=1

# The remaining suites gate the commit but stay out of the profile: e2e's
# in-process replicas double-count under coverage instrumentation, honeypot
# exercises cmd/bridge rather than internal/, and stress measures throughput.
# -p 1: each spins its own Postgres testcontainer; parallel package binaries
# exhaust container/port resources and flake.
#
# honeypot/stress without their build tags, and admin without a live gateway,
# now print a loud SKIP rather than compiling to "no test files". browser and
# e2e-browser live outside this go test (nested module / Playwright) and are
# invoked via scripts/t.sh so the same skip is visible there.
go test -count=1 -v -p 1 ./tests/e2e/... ./tests/honeypot/... ./tests/stress/... ./tests/admin/... >> "$TEST_FILE" 2>&1 || true

PASS=$(grep -c '^--- PASS' "$TEST_FILE" || true)
FAIL=$(grep -c '^--- FAIL' "$TEST_FILE" || true)
PKGS=$(grep -cE '^(ok|FAIL)\s' "$TEST_FILE" || true)

if [ "$FAIL" -gt 0 ]; then
  grep -B1 '^--- FAIL' "$TEST_FILE" >&2
  grep '^FAIL\s' "$TEST_FILE" >&2
fi

# An incomplete run has no --- FAIL: line to count, so surface it as one. When
# FAIL is already non-zero the guard tripped on a genuine test failure that is
# counted above, and adding to it would just misreport the total.
if [ "$INCOMPLETE" -ne 0 ] && [ "$FAIL" -eq 0 ]; then
  echo "coverage run did not complete; treating as a failure" >&2
  FAIL=1
fi

printf "%d %d %d\n" "$PASS" "$FAIL" "$PKGS"
echo "$COVER_FILE"
echo "$TEST_FILE"
