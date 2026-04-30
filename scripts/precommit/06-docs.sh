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

TEST_OUTPUT_FILE="$TEST_FILE" COVERAGE_FILE="$COVER_FILE" \
  VUE_TESTS="$VUE_PASS" VUE_LINES="$VUE_LINES" VUE_LOCALES="$LOCALE_COUNT" \
  bash scripts/readme-gen.sh > /dev/null 2>&1 || true

TEST_OUTPUT_FILE="$TEST_FILE" COVERAGE_FILE="$COVER_FILE" \
  bash scripts/coverage.sh > /dev/null 2>&1 || true
