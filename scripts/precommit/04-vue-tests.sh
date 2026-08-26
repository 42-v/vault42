#!/bin/bash
# Step 4: Frontend tests (vitest)
# Outputs: PASS FAIL on last line
set -eo pipefail
cd "$(dirname "$0")/../.."

VUE_TEST_FILE=$(mktemp)
trap 'rm -f "$VUE_TEST_FILE"' EXIT

(cd web && npx vitest run 2>&1) > "$VUE_TEST_FILE" || true
(cd packages/vue && npx vitest run 2>&1) >> "$VUE_TEST_FILE" || true

# shellcheck source=../lib/vitest-count.sh
source "$(dirname "$0")/../lib/vitest-count.sh"

read -r VUE_PASS VUE_FAIL VUE_SUMMARIES <<<"$(vitest_counts "$VUE_TEST_FILE")"

# Two suites ran above, so two summary lines is the only correct answer. This
# script's figure is handed to readme-gen.sh as VUE_TESTS and published, so a
# miscount here reaches the README rather than stopping at a developer's
# terminal.
if [ "$VUE_SUMMARIES" -ne 2 ]; then
  echo "ERROR: expected 2 vitest summaries (web, packages/vue), got ${VUE_SUMMARIES}." >&2
  sed -n '1,20p' "$VUE_TEST_FILE" >&2
  exit 1
fi

printf "%d %d\n" "$VUE_PASS" "$VUE_FAIL"
