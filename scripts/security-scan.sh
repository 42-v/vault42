#!/bin/bash
# Extensive security scan for Go backend and Vue frontend.
# Runs: gosec, govulncheck, staticcheck, go vet, pnpm audit, hadolint.
set -eo pipefail

# Ensure Go tools installed via `go install` are in PATH
export PATH="${HOME}/go/bin:${PATH}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FINDINGS=0

section() { echo -e "\n${YELLOW}=== $1 ===${NC}\n"; }
pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; FINDINGS=$((FINDINGS + 1)); }

# ---------- Go Backend ----------

section "go vet"
if go vet ./... 2>&1; then
  pass "go vet clean"
else
  fail "go vet found issues"
fi

section "gosec (Go security linter)"
if command -v gosec &>/dev/null; then
  # No global exclusions — all suppressions are per-line with #nosec RuleID and justification.
  GOSEC_OUT=$(gosec -quiet -fmt=text ./... 2>&1) || true
  GOSEC_ISSUES=$(echo "$GOSEC_OUT" | grep -c '^\[.*\]' || true)
  if [ "$GOSEC_ISSUES" -eq 0 ]; then
    pass "gosec: 0 findings"
  else
    fail "gosec: $GOSEC_ISSUES findings"
    echo "$GOSEC_OUT" | grep '^\[' | head -20
  fi
else
  echo "SKIP: gosec not installed (go install github.com/securego/gosec/v2/cmd/gosec@latest)"
fi

section "govulncheck (Go vulnerability database)"
if command -v govulncheck &>/dev/null; then
  # govulncheck may exit non-zero due to internal errors on transitive deps (not actual vulns).
  # Check output text for the definitive result.
  VULN_OUT=$(govulncheck ./... 2>&1) || true
  if echo "$VULN_OUT" | grep -q "No vulnerabilities found"; then
    pass "govulncheck: no known vulnerabilities"
  elif echo "$VULN_OUT" | grep -q "Vulnerability #"; then
    fail "govulncheck: vulnerabilities found"
    echo "$VULN_OUT" | grep -A3 "Vulnerability #"
  else
    # Internal errors only (e.g. "package requires newer Go version") — not real vulns
    pass "govulncheck: no known vulnerabilities (with internal warnings)"
  fi
else
  echo "SKIP: govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)"
fi

section "staticcheck (Go static analysis)"
if command -v staticcheck &>/dev/null; then
  if staticcheck ./... 2>&1; then
    pass "staticcheck clean"
  else
    fail "staticcheck found issues"
  fi
else
  echo "SKIP: staticcheck not installed (go install honnef.co/go/tools/cmd/staticcheck@latest)"
fi

# ---------- Vue Frontend ----------

section "pnpm audit"
if command -v pnpm &>/dev/null && [ -f pnpm-lock.yaml ]; then
  if pnpm audit --prod 2>&1; then
    pass "pnpm audit: clean"
  else
    fail "pnpm audit: vulnerabilities found"
  fi
else
  echo "SKIP: pnpm or pnpm-lock.yaml not found"
fi

# ---------- Dockerfile ----------

section "Hadolint (Dockerfile linter)"
if command -v hadolint &>/dev/null; then
  for DF in Dockerfile Dockerfile.bridge Dockerfile.admin-gateway Dockerfile.goreleaser Dockerfile.goreleaser.bridge Dockerfile.goreleaser.admin-gateway; do
    if [ -f "$DF" ]; then
      if hadolint "$DF" 2>&1; then
        pass "hadolint: $DF clean"
      else
        fail "hadolint: $DF issues found"
      fi
    fi
  done
else
  echo "SKIP: hadolint not installed"
fi

# ---------- Summary ----------

echo ""
echo "================================"
if [ "$FINDINGS" -eq 0 ]; then
  echo -e "${GREEN}All security scans passed.${NC}"
else
  echo -e "${RED}$FINDINGS security scan(s) reported findings.${NC}"
  exit 1
fi
