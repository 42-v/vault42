#!/bin/bash
# Step 2: Security scan (gosec)
set -eo pipefail
cd "$(dirname "$0")/../.."

GOSEC_BIN=$(command -v gosec 2>/dev/null || echo "${HOME}/go/bin/gosec")
if [ ! -x "$GOSEC_BIN" ]; then
  echo "SKIP"
  exit 0
fi

GOSEC_OUT=$("$GOSEC_BIN" -quiet -fmt=text ./... 2>&1) || true
GOSEC_HIGH=$(echo "$GOSEC_OUT" | grep -c '^\[' || true)
if [ "$GOSEC_HIGH" -gt 0 ]; then
  echo "$GOSEC_OUT" | grep '^\[' | head -10
  exit 1
fi
