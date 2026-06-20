#!/usr/bin/env bash
# Generate test coverage report: docs/test-coverage.md
# CI runs this after tests; output is committed by readme-gen or equivalent.
set -euo pipefail
cd "$(dirname "$0")/.."

# Disable Testcontainers' Ryuk reaper. Ryuk needs write access to docker.sock,
# which triggers SELinux AVC denials on Fedora hosts every time a test that
# uses testcontainers-go starts up. We don't need the reaper for short test
# runs — containers are torn down by the test code's defer/cleanup anyway.
export TESTCONTAINERS_RYUK_DISABLED=true

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
  # Run tests with coverage. -coverpkg=./internal/... makes tests under
  # tests/ (unit, attack, compliance) contribute to the internal-package
  # coverage profile too, instead of being a silent no-op for the report.
  # tests/compliance and tests/e2e need a live Postgres and are skipped
  # here; coverage.sh runs purely in-process.
  echo "Running tests with coverage (cross-pkg, ryuk disabled)..."
  # -count=1 disables Go's test cache. Without it, cached tests are skipped
  # but produce no coverage on rerun, so a second invocation reports lower
  # coverage than the first — making the number non-deterministic.
  go test -v -count=1 -coverprofile="$COVER_FILE" -coverpkg=./internal/... \
      ./internal/... ./tests/unit/... ./tests/attack/... ./tests/fuzz/... \
      > "$TEST_OUT" 2>&1 || true
fi

# Count passes from the test output we just generated (or the CI-provided one).
# We avoid a second `go test ./...` run because (a) it duplicates work and
# (b) it would sweep tests/compliance and tests/integration, both of which
# require a live Postgres via testcontainers.
if [ -n "${TEST_OUTPUT_FILE:-}" ] && [ -f "${TEST_OUTPUT_FILE}" ]; then
  TESTS=$(grep -c '^--- PASS:' "$TEST_OUTPUT_FILE" || true)
else
  TESTS=$(grep -c '^--- PASS:' "$TEST_OUT" || true)
fi
TESTS=${TESTS:-0}
DATE=$(date +%Y-%m-%d)

# Compute precise total and per-package coverage directly from the profile.
# go tool cover -func only reports 1 decimal; we want 2 (it matters for
# bullseye targets like 67.69%). Per-package stats come from the same source
# so they reflect actual coverage of each internal package — NOT the
# misleading "X% of statements in ./internal/..." each test pkg reports under
# -coverpkg, which is the per-test-package contribution, not the package's
# own coverage.
TOTAL=$(python3 - "$COVER_FILE" <<'PY'
import sys
seen = {}
with open(sys.argv[1]) as fh:
    next(fh)
    for line in fh:
        p = line.split()
        if len(p) < 3:
            continue
        k, s, c = p[0], int(p[1]), int(p[2])
        seen[k] = (s, seen.get(k, (s, False))[1] or c > 0)
total = sum(s for s, _ in seen.values())
covered = sum(s for s, c in seen.values() if c)
print(f"{100.0 * covered / total:.2f}%")
PY
)

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

  python3 - "$COVER_FILE" <<'PY'
import sys, re
from collections import defaultdict
pkg_re = re.compile(r'^(github\.com/42-v/vault42/[^/]+(?:/[^/]+)*)/[^/]+\.go:')
seen = {}
with open(sys.argv[1]) as fh:
    next(fh)
    for line in fh:
        p = line.split()
        if len(p) < 3:
            continue
        k, s, c = p[0], int(p[1]), int(p[2])
        seen[k] = (s, seen.get(k, (s, False))[1] or c > 0)
pkg_stmts = defaultdict(lambda: [0, 0])
for k, (s, c) in seen.items():
    m = pkg_re.match(k)
    if not m:
        continue
    pkg = m.group(1).replace("github.com/42-v/vault42/", "")
    pkg_stmts[pkg][0] += s
    if c:
        pkg_stmts[pkg][1] += s
rows = []
for pkg, (total, covered) in pkg_stmts.items():
    if total == 0:
        continue
    rows.append((covered / total, pkg, f"{100.0 * covered / total:.2f}%"))
rows.sort(reverse=True)
for _, pkg, pct in rows:
    print(f"| `{pkg}` | {pct} |")
PY

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

# Gate on test failures. The coverage `go test` above uses `|| true` so the
# report is always produced — but a failing test in ./internal/ or ./tests/unit
# must still fail this script (and therefore release-check), or regressions slip
# the gate while coverage stays green.
FAILS=$(grep -c '^--- FAIL:' "${TEST_OUTPUT_FILE:-$TEST_OUT}" 2>/dev/null || true)
FAILS=${FAILS:-0}
if [ "$FAILS" -gt 0 ]; then
  echo "ERROR: $FAILS test(s) FAILED during the coverage run:" >&2
  grep '^--- FAIL:' "${TEST_OUTPUT_FILE:-$TEST_OUT}" >&2 || true
  exit 1
fi
