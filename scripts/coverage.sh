#!/usr/bin/env bash
# Generate test coverage report: docs/test-coverage.md
# CI runs this after tests; output is committed by readme-gen or equivalent.
set -euo pipefail
cd "$(dirname "$0")/.."

COVER_FILE=$(mktemp)
TEST_OUT=$(mktemp)
trap 'rm -f "$COVER_FILE" "$TEST_OUT"' EXIT

# CI sets TEST_OUTPUT_FILE + COVERAGE_FILE to skip re-running tests.
if [ -n "${TEST_OUTPUT_FILE:-}" ] && [ -f "${TEST_OUTPUT_FILE}" ] && \
   [ -n "${COVERAGE_FILE:-}" ] && [ -f "${COVERAGE_FILE}" ]; then
  echo "Using pre-computed test artifacts"
  cp "$TEST_OUTPUT_FILE" "$TEST_OUT"
  cp "$COVERAGE_FILE" "$COVER_FILE"
else
  # Run tests with coverage (non-verbose for clean package lines)
  echo "Running tests with coverage..."
  go test -coverprofile="$COVER_FILE" ./internal/... > "$TEST_OUT" 2>&1 || true
fi

# Get full test count — from verbose artifact if available, otherwise run tests
if [ -n "${TEST_OUTPUT_FILE:-}" ] && [ -f "${TEST_OUTPUT_FILE}" ]; then
  TESTS=$(grep -c '^--- PASS:' "$TEST_OUTPUT_FILE" || echo 0)
else
  TESTS=$(go test -v ./... 2>&1 | grep -c '^--- PASS:' || echo 0)
fi
TOTAL=$(go tool cover -func="$COVER_FILE" | tail -1 | awk '{print $NF}')
DATE=$(date +%Y-%m-%d)

# Generate markdown
{
  echo "# Test Coverage Report"
  echo ""
  echo "Generated: $DATE | Tests: $TESTS | Total: $TOTAL statement coverage"
  echo ""
  echo "## Package Summary"
  echo ""
  echo "| Package | Coverage |"
  echo "|---------|----------|"

  # Parse summary lines (^ok) — works with both verbose and non-verbose output
  while IFS= read -r line; do
    if echo "$line" | grep -q 'no test files'; then
      pkg=$(echo "$line" | grep -oP 'github\.com/42-v/vault/\S+' | sed 's|github.com/42-v/vault/||' || true)
      [ -n "$pkg" ] && echo "| \`$pkg\` | — |"
    elif echo "$line" | grep -qP 'coverage: [0-9.]+%'; then
      pkg=$(echo "$line" | grep -oP 'github\.com/42-v/vault/\S+' | sed 's|github.com/42-v/vault/||' || true)
      pct=$(echo "$line" | grep -oP 'coverage: [0-9.]+%' | grep -oP '[0-9.]+%' || true)
      [ -n "$pkg" ] && [ -n "$pct" ] && echo "| \`$pkg\` | $pct |"
    fi
  done < <(grep -P '^(ok\s|\?)\s' "$TEST_OUT") | sort -t'|' -k3 -rn

  echo ""
  echo "## Uncovered Functions"
  echo ""
  echo "| Function | File |"
  echo "|----------|------|"

  go tool cover -func="$COVER_FILE" | awk '$NF == "0.0%" {print}' | while IFS= read -r line; do
    file=$(echo "$line" | awk '{print $1}' | sed 's|github.com/42-v/vault/||; s/:$//')
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
      file=$(echo "$line" | awk '{print $1}' | sed 's|github.com/42-v/vault/||; s/:$//')
      func_name=$(echo "$line" | awk '{print $2}')
      echo "| \`$func_name\` | $file | $pct_str |"
    fi
  done
} > docs/test-coverage.md

echo "docs/test-coverage.md updated: $TESTS tests, $TOTAL coverage"
