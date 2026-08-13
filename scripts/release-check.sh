#!/bin/bash
# Everything that must be true before a vX.Y.Z tag is pushed.
#
# Releases fire from the tag (.github/workflows/release.yml), so this is the
# last place a bad tree can be stopped cheaply. The security jobs mirror
# .github/workflows/nightly-security.yml, which the release workflow now also
# runs on the release ref, so a clean pass here predicts a clean release.
#
#   scripts/release-check.sh                     every gate
#   scripts/release-check.sh --version-only VER  version consistency only
#   scripts/release-check.sh --coverage-only P   coverage gate over profile P
#
# Gates:
#   1  govulncheck             Go stdlib + transitive CVEs
#   2  gosec                   HIGH/CRITICAL only
#   3  trivy fs                dependency CVEs
#   4  attack suite            tests/attack/...
#   5  coverage                verified exclusions, full statement accounting
#   6  version consistency     VERSION == tag == every manifest
#   7  module hygiene          go mod verify, go mod tidy -diff
#   8  golangci-lint           issue count against the ratchet below
#   9  helm                    lint + template of every values file
#   10 docs                    no chart path that does not exist
#   11 changelog               a section for the version being cut
#   12 working tree            clean
#
# Exit code 0 means the branch is releasable.

set -eo pipefail
cd "$(dirname "$0")/.."

export PATH="${HOME}/go/bin:${PATH}"
export TESTCONTAINERS_RYUK_DISABLED=true

# Keep these in step with .github/workflows/nightly-security.yml, or a clean run
# here stops predicting a clean run there.
GOVULNCHECK_VERSION=v1.1.4
GOSEC_VERSION=v2.28.0

# Ratchet, not a target. golangci-lint has never run in CI, so the tree starts
# with a backlog; this locks in "no worse than today" and comes down as packages
# are cleaned. The gate below prints the new figure whenever a run comes in under
# the ratchet, so lowering it is a one-line edit against a measured number.
# CI blocks on new findings only (--new-from-merge-base), so this ratchet gates
# the release, not the pull request.
GOLANGCI_MAX_ISSUES=${GOLANGCI_MAX_ISSUES:-143}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

section() { echo -e "\n${YELLOW}=== $1 ===${NC}"; }
pass()    { echo -e "${GREEN}PASS${NC}: $1"; }
skip()    { echo -e "${YELLOW}SKIP${NC}: $1"; }
fail()    { echo -e "${RED}FAIL${NC}: $1"; exit 1; }

# ---------- gate 5: coverage ----------
#
# The old gate printed the number and returned 0, so a collapsed figure shipped
# as happily as a good one. The real assertion is that every statement in the
# tree is accounted for: covered, or on the reviewed exclusion list. Nothing may
# be neither.
#
# Both assertions below are relative to the profile, and --coverage-only takes
# that path from whoever ran this, so a profile from a narrower run would satisfy
# them on a fraction of the tree. cov-gaps.py --verify-exclusions is what rules
# that out: it holds the canonical statement count and package set as ratchets
# and rejects a profile that comes in under either. Keeping that check there
# rather than here leaves one place where the canonical figures are recorded.
#
# scripts/cov-gaps.py owns the exclusion file and its --verify-exclusions mode;
# this only consumes them.
coverage_gate() {
  local profile="$1"
  [ -f "$profile" ] || fail "coverage profile not found: $profile"

  echo "verifying the exclusion set against $profile"
  python3 scripts/cov-gaps.py "$profile" --verify-exclusions \
    || fail "cov-gaps --verify-exclusions rejected the exclusion set"

  local json
  json=$(mktemp)
  python3 scripts/cov-gaps.py "$profile" --json > "$json" \
    || { rm -f "$json"; fail "cov-gaps --json failed"; }
  python3 - "$json" <<'PY' || { rm -f "$json"; fail "coverage accounting is incomplete"; }
import json, sys

with open(sys.argv[1]) as fh:
    d = json.load(fh)
missing = [k for k in ("total_statements", "covered_statements", "excluded_statements") if k not in d]
if missing:
    sys.exit(f"cov-gaps.py --json is missing {', '.join(missing)}; "
             "the gate needs covered + excluded + total to prove full accounting")

total, covered, excluded = (d["total_statements"], d["covered_statements"], d["excluded_statements"])
unaccounted = total - covered - excluded
print(f"total {total}  covered {covered}  excluded {excluded}  unaccounted {unaccounted}")
if unaccounted != 0:
    sys.exit(f"{unaccounted} statements are neither covered nor excluded; "
             "cover them or add them to the reviewed exclusion set")
print(f"reachable coverage {100.0 * covered / (total - excluded):.2f}%"
      if total > excluded else "every statement is excluded")
PY
  rm -f "$json"
  pass "every statement is covered or explicitly excluded"
}

# ---------- gate 6: version consistency ----------
#
# The tag is the release input, so a tree whose manifests disagree with it would
# publish images, packages and a chart that name different versions.
version_gate() {
  local want="${1-}"
  [ -f VERSION ] || fail "no VERSION file; run scripts/version-bump.sh <version>"
  local have
  have=$(tr -d '[:space:]' < VERSION)
  if [ -n "$want" ]; then
    want=${want#v}
    [ "$have" = "$want" ] || fail "VERSION is $have but the release is $want"
  fi
  bash scripts/version-bump.sh --check || fail "manifests disagree with VERSION"

  # The README badge advertises the toolchain that builds the release, not the
  # language floor. go.mod carries both; they are different numbers.
  if [ -f README.md ] && grep -q 'Go-[0-9]' README.md; then
    local badge toolchain
    badge=$(grep -oE 'Go-[0-9]+\.[0-9]+(\.[0-9]+)?' README.md | head -1 | cut -d- -f2)
    toolchain=$(grep -oE '^toolchain go[0-9]+\.[0-9]+(\.[0-9]+)?' go.mod | head -1 | sed 's/^toolchain go//')
    if [ -n "$toolchain" ] && [ "$badge" != "$toolchain" ]; then
      fail "README Go badge says $badge, go.mod toolchain is $toolchain"
    fi
    pass "README Go badge matches the go.mod toolchain ($badge)"
  fi
  pass "VERSION = $have and every manifest agrees"
}

case "${1-}" in
  --version-only)
    version_gate "${2-}"
    echo -e "\n${GREEN}release-check: version consistency green${NC}"
    exit 0
    ;;
  --coverage-only)
    coverage_gate "${2:-coverage.out}"
    echo -e "\n${GREEN}release-check: coverage gate green${NC}"
    exit 0
    ;;
  -h | --help)
    sed -nE '2,30s/^# ?//p' "$0"
    exit 0
    ;;
  "") ;;
  *) fail "unknown argument: $1" ;;
esac

# ---------- 1. govulncheck ----------
section "govulncheck"
if ! command -v govulncheck >/dev/null; then
  echo "Installing govulncheck..."
  go install golang.org/x/vuln/cmd/govulncheck@"$GOVULNCHECK_VERSION"
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
  go install github.com/securego/gosec/v2/cmd/gosec@"$GOSEC_VERSION"
fi
GOSEC_JSON=$(mktemp)
trap 'rm -f "$GOSEC_JSON"' EXIT
gosec -quiet -fmt=json -out="$GOSEC_JSON" ./... 2>/dev/null || true
HIGH=$(python3 -c "
import json, os
# gosec -quiet writes nothing when there are no findings; an empty file is a pass
p = '$GOSEC_JSON'
d = json.load(open(p)) if os.path.getsize(p) > 0 else {}
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
  skip "no trivy or docker available"
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

# ---------- 5. Coverage ----------
section "coverage"
# shellcheck source=lib/coverage-env.sh
source scripts/lib/coverage-env.sh
COVER_PROFILE="$PWD/coverage.out"
COVER_TESTOUT=$(mktemp)
if [ -n "${COVERAGE_FILE:-}" ] && [ -f "${COVERAGE_FILE}" ] && \
   [ -n "${TEST_OUTPUT_FILE:-}" ] && [ -f "${TEST_OUTPUT_FILE}" ]; then
  echo "Using pre-computed test artifacts"
  cp "$COVERAGE_FILE" "$COVER_PROFILE"
  cp "$TEST_OUTPUT_FILE" "$COVER_TESTOUT"
else
  cov_require_runtime
  echo "Running the canonical coverage suite (DOCKER_HOST=$DOCKER_HOST)..."
  cov_run "$COVER_PROFILE" "$COVER_TESTOUT"
  cov_check_failures "$COVER_TESTOUT"
fi
# Regenerate docs/test-coverage.md from the same profile the gate reads, so the
# published report and the gate can never describe different runs.
TEST_OUTPUT_FILE="$COVER_TESTOUT" COVERAGE_FILE="$COVER_PROFILE" bash scripts/coverage.sh
coverage_gate "$COVER_PROFILE"

# ---------- 6. Version consistency ----------
section "version consistency"
version_gate "${RELEASE_VERSION:-}"

# ---------- 7. Module hygiene ----------
section "go module hygiene"
go mod verify >/dev/null || fail "go mod verify: a module in the cache does not match go.sum"
pass "go mod verify"
if go mod tidy -diff >/dev/null 2>&1; then
  pass "go mod tidy is a no-op"
else
  go mod tidy -diff || true
  fail "go.mod/go.sum are not tidy"
fi

# ---------- 8. golangci-lint ----------
section "golangci-lint"
# A missing linter is a failed gate, not a passed one. This was the last silent
# pass left in the script: on any machine without golangci-lint the ratchet below
# printed SKIP and returned success, so the release check reported green having
# measured nothing. That is the same shape as the coverage gate accepting no
# profile, which this release closed.
#
# RELEASE_CHECK_ALLOW_MISSING_TOOLS=1 restores the old behaviour for someone
# deliberately running a partial check, and says so in the output.
if ! command -v golangci-lint >/dev/null; then
  if [ "${RELEASE_CHECK_ALLOW_MISSING_TOOLS:-}" != "1" ]; then
    fail "golangci-lint is not installed, so the lint ratchet cannot run (go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.2). Set RELEASE_CHECK_ALLOW_MISSING_TOOLS=1 to run a deliberately partial check."
  fi
  skip "golangci-lint is not installed and RELEASE_CHECK_ALLOW_MISSING_TOOLS=1 (PARTIAL CHECK)"
else
  LINT_JSON=$(mktemp)
  golangci-lint run --timeout 15m --output.json.path="$LINT_JSON" ./... >/dev/null 2>&1 || true
  LINT_COUNT=$(python3 -c "
import json
d = json.load(open('$LINT_JSON'))
print(len(d.get('Issues') or []))
")
  rm -f "$LINT_JSON"
  if [ "$LINT_COUNT" -gt "$GOLANGCI_MAX_ISSUES" ]; then
    golangci-lint run --timeout 15m ./... || true
    fail "golangci-lint: $LINT_COUNT issues, ratchet is $GOLANGCI_MAX_ISSUES"
  elif [ "$LINT_COUNT" -lt "$GOLANGCI_MAX_ISSUES" ]; then
    pass "golangci-lint: $LINT_COUNT issues; lower GOLANGCI_MAX_ISSUES to $LINT_COUNT"
  else
    pass "golangci-lint: $LINT_COUNT issues, at the ratchet"
  fi
fi

# ---------- 9. Helm ----------
section "helm"
if ! command -v helm >/dev/null; then
  skip "helm is not installed"
else
  helm lint charts/vault >/dev/null || { helm lint charts/vault; fail "helm lint"; }
  helm template release-check charts/vault >/dev/null || fail "helm template (defaults)"
  for VALUES in charts/vault/values-*.yaml; do
    helm template release-check charts/vault -f "$VALUES" >/dev/null \
      || fail "helm template -f $VALUES"
  done
  # The default install resolves image.tag from Chart.AppVersion. A chart whose
  # appVersion names a tag that was never published is an ImagePullBackOff, which
  # is what shipped in every release before 1.0.0.
  RENDERED=$(helm template release-check charts/vault | grep -oE 'ghcr\.io/42-v/vault42:[^"]+' | head -1)
  APPVERSION=$(grep -oE '^appVersion: "?[^"]+' charts/vault/Chart.yaml | sed 's/^appVersion: "\?//')
  [ "$RENDERED" = "ghcr.io/42-v/vault42:${APPVERSION}" ] \
    || fail "default install renders $RENDERED, appVersion is $APPVERSION"
  pass "helm lint + template of every values file; default install renders $RENDERED"
fi

# ---------- 10. Docs paths ----------
section "documented chart paths"
# Only files that actually ship. docs/ holds gitignored working documents
# (spec-draft.md, the audit reports) whose historical paths are not a defect a
# reader can trip over, because no reader ever receives them.
# grep exits 1 on no match and xargs turns that into 123, which is the SUCCESS
# case here, so both are swallowed deliberately.
chart_path_hits() {
  git ls-files -- docs site README.md 2>/dev/null \
    | xargs -r grep -n 'charts/vault42' 2>/dev/null || true
}
BAD_PATHS=$(chart_path_hits | wc -l)
if [ "$BAD_PATHS" -eq 0 ]; then
  pass "no published file references a chart directory that does not exist"
else
  chart_path_hits | head -10
  fail "$BAD_PATHS published references to charts/vault42; the chart is at charts/vault"
fi

# ---------- 11. Changelog ----------
section "changelog"
CHANGELOG_VERSION=$(tr -d '[:space:]' < VERSION)
if grep -qE "^## +v?${CHANGELOG_VERSION}([^0-9]|\$)" CHANGELOG.md; then
  pass "CHANGELOG.md has a section for $CHANGELOG_VERSION"
else
  fail "CHANGELOG.md has no '## $CHANGELOG_VERSION' section"
fi

# ---------- 12. Working tree ----------
#
# docs/test-coverage.md is excluded because gate 5 regenerates it from the very
# profile it just measured. Without the exclusion a full run on a clean tree
# dirties that one file and then fails itself on it, which is a script that
# cannot pass, and the operator's only route through was to run it, commit the
# regenerated report, and run it again.
#
# It is excluded rather than the regeneration being moved, because the report and
# the gate must describe the same run: writing it after gate 12 would let the two
# diverge by a whole release. A stale report is caught by the coverage gate in CI
# and by readme-gen, not by this one.
section "working tree"
DIRTY=$(git status --porcelain -- . ':(exclude)docs/test-coverage.md')
if [ -z "$DIRTY" ]; then
  if ! git diff --quiet -- docs/test-coverage.md; then
    echo "note: docs/test-coverage.md was regenerated by gate 5; commit it with the release"
  fi
  pass "clean"
else
  printf '%s\n' "$DIRTY" | head -20
  fail "uncommitted changes; tag a committed tree"
fi

echo -e "\n${GREEN}release-check: all gates green — safe to tag${NC}"
