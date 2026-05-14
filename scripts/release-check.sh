#!/bin/bash
# Local replay of .github/workflows/nightly-security.yml — run before cutting
# a release tag. Mirrors the same jobs the nightly scanner runs in CI, so a
# clean pass here means the next nightly run will also be clean.
#
# Jobs:
#   - govulncheck         (Go stdlib + transitive CVEs)
#   - gosec               (HIGH/CRITICAL only — workflow exit gate)
#   - trivy fs            (filesystem secret + vuln scan)
#   - go test attack      (full attack-vector suite)
#   - scripts/coverage.sh (regenerates docs/test-coverage.md)
#
# Exit code 0 means the branch is releasable.

set -eo pipefail
cd "$(dirname "$0")/.."

export PATH="${HOME}/go/bin:${PATH}"
export TESTCONTAINERS_RYUK_DISABLED=true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

section() { echo -e "\n${YELLOW}=== $1 ===${NC}"; }
pass()    { echo -e "${GREEN}PASS${NC}: $1"; }
fail()    { echo -e "${RED}FAIL${NC}: $1"; exit 1; }

# ---------- 1. govulncheck ----------
section "govulncheck"
if ! command -v govulncheck >/dev/null; then
  echo "Installing govulncheck..."
  go install golang.org/x/vuln/cmd/govulncheck@latest
fi
OUT=$(govulncheck ./... 2>&1) || true
if echo "$OUT" | grep -q "No vulnerabilities found"; then
  pass "no vulnerabilities"
else
  echo "$OUT"
  fail "govulncheck found vulnerabilities"
fi

# ---------- 2. gosec ----------
section "gosec (HIGH/CRITICAL only)"
if ! command -v gosec >/dev/null; then
  echo "Installing gosec..."
  go install github.com/securego/gosec/v2/cmd/gosec@latest
fi
GOSEC_JSON=$(mktemp)
trap 'rm -f "$GOSEC_JSON"' EXIT
gosec -quiet -fmt=json -out="$GOSEC_JSON" ./... 2>/dev/null || true
HIGH=$(python3 -c "
import json
d = json.load(open('$GOSEC_JSON'))
issues = d.get('Issues', [])
high = [i for i in issues if i.get('severity') in ('HIGH', 'CRITICAL')]
print(len(high))
for i in high[:10]:
    print(f\"  [{i['severity']}] {i['details']} {i['file']}:{i['line']}\")
")
HIGH_COUNT=$(echo "$HIGH" | head -1)
if [ "$HIGH_COUNT" -eq 0 ]; then
  pass "0 HIGH/CRITICAL findings"
else
  echo "$HIGH"
  fail "gosec: $HIGH_COUNT HIGH/CRITICAL"
fi

# ---------- 3. Trivy filesystem ----------
# Falls back across native trivy → docker → distrobox-host-exec docker so this
# works in any of the dev environments contributors use. SKIPs cleanly if none
# of those resolve (CI always has docker).
section "trivy fs"
TRIVY_CMD=""
# --scanners vuln matches the CI nightly workflow's effective gate (HIGH/CRITICAL
# CVEs in dependencies) — local trivy >=0.70 also flags secrets and fails on
# dev-only test certs in tests/integration/certs/, which CI does not.
if command -v trivy >/dev/null; then
  TRIVY_CMD="trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --quiet ."
elif command -v docker >/dev/null; then
  TRIVY_CMD="docker run --rm -v $PWD:/scan aquasec/trivy:latest fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --quiet /scan"
elif command -v distrobox-host-exec >/dev/null && distrobox-host-exec command -v docker >/dev/null 2>&1; then
  TRIVY_CMD="distrobox-host-exec docker run --rm -v $PWD:/scan aquasec/trivy:latest fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --quiet /scan"
fi
if [ -z "$TRIVY_CMD" ]; then
  echo "SKIP: no trivy or docker available"
elif eval "$TRIVY_CMD" >/dev/null 2>&1; then
  pass "no HIGH/CRITICAL findings"
else
  fail "trivy found HIGH/CRITICAL"
fi

# ---------- 4. Attack suite ----------
section "attack suite"
if go test ./tests/attack/... -count=1 -timeout 300s >/dev/null 2>&1; then
  pass "all attack tests green"
else
  go test ./tests/attack/... -count=1 -timeout 300s
  fail "attack suite has failures"
fi

# ---------- 5. Coverage gate ----------
section "coverage (regenerates docs/test-coverage.md)"
bash scripts/coverage.sh
COV=$(grep -oP 'Total: \K[0-9.]+' docs/test-coverage.md | head -1)
pass "coverage: ${COV}%"

echo -e "\n${GREEN}release-check: all gates green — safe to tag${NC}"
