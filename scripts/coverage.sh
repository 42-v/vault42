#!/usr/bin/env bash
# Generate the test coverage report: docs/test-coverage.md
#
# Measures internal/ across the FULL suite — unit, attack, fuzz, and the
# DB-backed integration + compliance suites. That needs a container runtime;
# see scripts/lib/coverage-env.sh for the package set and the reasoning.
#
# CI (and scripts/precommit) set TEST_OUTPUT_FILE + COVERAGE_FILE to reuse
# artifacts from an earlier run instead of re-running the suite.
#
# The profile outlives the run. It is the only artifact that can answer "which
# statements are uncovered", which is what scripts/cov-gaps.py and the exclusion
# gate in .coverage-exclusions.json need; writing it to a mktemp deleted on exit
# meant the canonical run destroyed its own evidence and left docs/test-coverage.md
# as the sole record, at package granularity.
#
# COVERAGE_FILE and TEST_OUTPUT_FILE keep their meaning: when they name a
# finished run they are reused as input; when they name a path that does not
# exist yet, this run writes there. Unset, both default under coverage/.
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=lib/coverage-env.sh
source "$(dirname "$0")/lib/coverage-env.sh"

COVER_FILE="${COVERAGE_FILE:-coverage/coverage.out}"
TEST_OUT="${TEST_OUTPUT_FILE:-coverage/test-output.txt}"
mkdir -p "$(dirname "$COVER_FILE")" "$(dirname "$TEST_OUT")"

if [ -n "${TEST_OUTPUT_FILE:-}" ] && [ -f "${TEST_OUTPUT_FILE}" ] && \
   [ -n "${COVERAGE_FILE:-}" ] && [ -f "${COVERAGE_FILE}" ]; then
  echo "Using pre-computed test artifacts"
else
  cov_require_runtime
  echo "Running full-suite tests with coverage (DOCKER_HOST=$DOCKER_HOST)..."
  cov_run "$COVER_FILE" "$TEST_OUT"
fi

TESTS=$(grep -c '^--- PASS:' "$TEST_OUT" || true)
TESTS=${TESTS:-0}
DATE=$(date +%Y-%m-%d)
TOTAL=$(cov_total "$COVER_FILE")

{
  echo "# Test Coverage Report"
  echo ""
  echo "Generated: $DATE | Tests: $TESTS | Total: $TOTAL statement coverage"
  echo ""
  echo "Measured across the full suite (unit + attack + fuzz + integration +"
  echo "compliance) against \`./internal/...\`. Regenerate with \`scripts/coverage.sh\`."
  echo ""
  echo "## Package Summary"
  echo ""
  echo "| Package | Coverage |"
  echo "|---------|----------|"
  cov_pkg_table "$COVER_FILE"

  echo ""
  echo "## Uncovered Functions"
  echo ""
  echo "| Function | File |"
  echo "|----------|------|"

  go tool cover -func="$COVER_FILE" | awk '$NF == "0.0%" {print}' | while IFS= read -r line; do
    file=$(echo "$line" | awk '{print $1}' | sed 's|github.com/42-v/vault42/||; s/:$//')
    func_name=$(echo "$line" | awk '{print $2}')
    echo "| \`$func_name\` | $file |"
  done

  echo ""
  echo "## Low Coverage (1-74%)"
  echo ""
  echo "| Function | File | Coverage |"
  echo "|----------|------|----------|"

  go tool cover -func="$COVER_FILE" | awk '$NF != "0.0%" && $NF != "100.0%" {print}' | grep -v '^total:' | while IFS= read -r line; do
    pct_str=$(echo "$line" | awk '{print $NF}')
    pct=$(echo "$pct_str" | tr -d '%')
    is_low=$(awk "BEGIN {print ($pct < 75) ? 1 : 0}")
    if [ "$is_low" = "1" ]; then
      file=$(echo "$line" | awk '{print $1}' | sed 's|github.com/42-v/vault42/||; s/:$//')
      func_name=$(echo "$line" | awk '{print $2}')
      echo "| \`$func_name\` | $file | $pct_str |"
    fi
  done
} > docs/test-coverage.md

echo "docs/test-coverage.md updated: $TESTS tests, $TOTAL coverage"
echo "profile kept at $COVER_FILE (scripts/cov-gaps.py $COVER_FILE --json for file:line gaps)"

# Gate last, so the report is written even on failure — but never exit 0 with a
# number that a build break or failing test quietly deflated.
cov_check_failures "$TEST_OUT"
