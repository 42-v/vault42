#!/bin/bash
# Count passing/failing tests. Compact output for CI/agent use.
# Lists all failure messages at the end if any tests fail.
set -eo pipefail
OUTPUT=$(go test -count=1 -v ./... 2>&1) || true
PASS=$(echo "$OUTPUT" | grep -c '^--- PASS' || true)
FAIL=$(echo "$OUTPUT" | grep -c '^--- FAIL' || true)
PKGS=$(echo "$OUTPUT" | grep -cE '^(ok|FAIL)\s' || true)
FAIL_PKGS=$(echo "$OUTPUT" | grep -c '^FAIL\s' || true)
echo "${PASS} passed, ${FAIL} failed, ${PKGS} packages (${FAIL_PKGS} failed packages)"
if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "=== FAILURES ==="
  echo "$OUTPUT" | grep -A5 '^--- FAIL'
  echo ""
  echo "=== FAILED PACKAGES ==="
  echo "$OUTPUT" | grep '^FAIL\s'
  exit 1
fi
