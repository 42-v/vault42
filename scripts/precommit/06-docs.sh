#!/bin/bash
# Step 6: Update README badges, deps, and coverage
# Args: TEST_FILE COVER_FILE VUE_PASS VUE_LINES LOCALE_COUNT
set -eo pipefail
cd "$(dirname "$0")/../.."

TEST_FILE="$1"
COVER_FILE="$2"
VUE_PASS="$3"
VUE_LINES="$4"
LOCALE_COUNT="$5"

# Both generators gate on cov_check_failures. Swallowing their exit code with
# `|| true` discarded that guard: a partial profile still rewrote the badge,
# docs/badges.json and docs/test-coverage.md, publishing a coverage figure no
# completed run ever produced. Keep the output quiet on success, show it on
# failure, and let the failure stand.
run_generator() {
  local name="$1" out
  shift
  if ! out=$("$@" 2>&1); then
    echo "$name failed:" >&2
    echo "$out" >&2
    return 1
  fi
}

TEST_OUTPUT_FILE="$TEST_FILE" COVERAGE_FILE="$COVER_FILE" \
  VUE_TESTS="$VUE_PASS" VUE_LINES="$VUE_LINES" VUE_LOCALES="$LOCALE_COUNT" \
  run_generator readme-gen bash scripts/readme-gen.sh

TEST_OUTPUT_FILE="$TEST_FILE" COVERAGE_FILE="$COVER_FILE" \
  run_generator coverage bash scripts/coverage.sh
