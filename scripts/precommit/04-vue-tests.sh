#!/bin/bash
# Step 4: Frontend tests (vitest)
# Outputs: PASS FAIL on last line
set -eo pipefail
cd "$(dirname "$0")/../.."

VUE_TEST_FILE=$(mktemp)
trap 'rm -f "$VUE_TEST_FILE"' EXIT

(cd web && npx vitest run 2>&1) > "$VUE_TEST_FILE" || true
(cd packages/vue && npx vitest run 2>&1) >> "$VUE_TEST_FILE" || true

VUE_PASS=$({ grep -oP '\d+(?= passed)' "$VUE_TEST_FILE" || true; } | awk '{s+=$1}END{print s+0}')
VUE_FAIL=$({ grep -oP '\d+(?= failed)' "$VUE_TEST_FILE" || true; } | awk '{s+=$1}END{print s+0}')

printf "%d %d\n" "$VUE_PASS" "$VUE_FAIL"
