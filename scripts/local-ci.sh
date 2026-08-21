#!/usr/bin/env bash
# Run what CI runs, before pushing.
#
# This exists because the 1.0.3 release found three separate required-check
# failures one push at a time: golangci-lint had 18 findings nobody had run
# locally, the gosec test baseline had drifted under a test refactor, and a
# commit typed `tools:` had been sitting on the branch since before the PR.
# Each cost a push, a CI round trip and a context switch, and every one of them
# was reproducible on this machine in under two minutes.
#
# The gates below are the ones with a local equivalent. What is deliberately not
# here: Trivy image scans (they build the release images), CodeQL, Scorecard,
# and the attestation steps, all of which need the runner or the registry. Those
# stay CI's job, and this script says so at the end rather than implying it ran
# everything.
#
#   scripts/local-ci.sh            everything, roughly 30 minutes
#   scripts/local-ci.sh --fast     everything except the race suite and coverage
#   scripts/local-ci.sh --list     the gates and whether their tool is installed
#   scripts/local-ci.sh --at-tag   run the gates as the release workflow sees them
#
# Exit status is the number of failed gates, so `|| echo $?` counts them.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; DIM=$'\033[2m'; OFF=$'\033[0m'

FAST=0
LIST=0
ATTAG=0
for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    --list) LIST=1 ;;
    --at-tag) ATTAG=1 ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

GOBIN=$(go env GOPATH 2>/dev/null)/bin
export PATH="$GOBIN:$HOME/.local/bin:$PATH"

# The npm-delivered tools run through npx rather than being installed, because a
# global install is a version nobody pinned.
NPX="npx --yes"

FAILED=()
PASSED=0
SKIPPED=()

have() { command -v "$1" >/dev/null 2>&1; }

# gate <name> <tool-that-must-exist> <command...>
gate() {
  local name=$1 tool=$2; shift 2
  if [ -n "$tool" ] && ! have "$tool"; then
    SKIPPED+=("$name (missing: $tool)")
    printf '%sSKIP%s  %-34s %s\n' "$YELLOW" "$OFF" "$name" "${DIM}install $tool$OFF"
    return
  fi
  local out status
  out=$("$@" 2>&1); status=$?
  if [ $status -eq 0 ]; then
    PASSED=$((PASSED + 1))
    printf '%sPASS%s  %s\n' "$GREEN" "$OFF" "$name"
  else
    FAILED+=("$name")
    printf '%sFAIL%s  %s\n' "$RED" "$OFF" "$name"
    printf '%s\n' "$out" | tail -25 | sed 's/^/      /'
  fi
}

if [ "$LIST" -eq 1 ]; then
  printf '%-34s %s\n' "GATE" "TOOL"
  for pair in \
    "Version consistency:bash" "Go build:go" "Go vet:go" "gofmt:gofmt" \
    "golangci-lint:golangci-lint" "gosec baseline:gosec" "govulncheck:govulncheck" \
    "Trivy source:trivy" "Hadolint:hadolint" "Helm chart:helm" \
    "ruff:ruff" "shellcheck:shellcheck" "yamllint:yamllint" "markdownlint:node" \
    "commitlint:node" "GoReleaser config:goreleaser" "Frontend:node" ".NET:dotnet" \
    "Race suite:go" "Coverage gate:go"; do
    n=${pair%%:*}; t=${pair##*:}
    if have "$t"; then s="${GREEN}installed${OFF}"; else s="${RED}MISSING${OFF}"; fi
    printf '%-34s %-16s %b\n' "$n" "$t" "$s"
  done
  exit 0
fi

# --at-tag reproduces the one condition every other mode gets wrong.
#
# The release workflow checks out the tag it is building, so on a release HEAD
# *is* v<VERSION>. Nothing else runs that way: a branch, a PR and every local
# invocation above have the previous release as their most recent tag. A gate
# that reads `git describe` therefore answers something different on a release
# than it ever answers anywhere else.
#
# That is not hypothetical. TestUpgradingDocMigrationCountsMatchTheTree passed
# on the branch, passed on the PR, and failed the moment v1.0.3 was pushed,
# because `git describe --tags HEAD` returned the version being released and the
# gate compared the release against itself. It had never run in the situation it
# guards: it was written after v0.9.9, and 1.0.0, 1.0.1 and 1.0.2 were all
# merged without tags.
#
# The work happens in a throwaway local clone rather than a worktree, because
# tags are repository-global: creating v<VERSION> in a worktree would move the
# real tag out from under whatever else is using it.
if [ "$ATTAG" -eq 1 ]; then
  VERSION=$(tr -d '[:space:]' < VERSION)
  TAG="v${VERSION}"
  WORK=$(mktemp -d)
  # shellcheck disable=SC2064 # expand WORK now, not at trap time
  trap "rm -rf '$WORK'" EXIT

  echo "== gates at ${TAG} =="
  echo "${DIM}cloning into a scratch repo so the real tags are untouched${OFF}"
  # --no-hardlinks because the scratch directory and the repository are usually
  # on different filesystems, and a hardlink clone dies with "Invalid
  # cross-device link" when they are.
  if ! git clone --local --no-hardlinks --quiet . "$WORK/repo"; then
    echo "${RED}FAIL${OFF}  could not clone the repository into $WORK"
    exit 1
  fi

  # The clone carries committed history, which is what makes `git describe`
  # meaningful, and the committed *files*, which is not what we want to test:
  # the first version of this mode passed against a tree where the release bug
  # had been reinstated, because the change was still uncommitted. A mode that
  # only sees committed state cannot catch the defect you are about to commit,
  # which is the entire moment it exists for. So the working tree is copied over
  # the checkout, keeping .git.
  if ! rsync -a --delete --exclude '.git/' ./ "$WORK/repo/" 2>/dev/null; then
    echo "${RED}FAIL${OFF}  could not copy the working tree into $WORK"
    exit 1
  fi

  # Point the tag at what a release of this VERSION would actually build.
  git -C "$WORK/repo" tag -f "$TAG" HEAD >/dev/null 2>&1

  cd "$WORK/repo" || exit 1
  gate "spec suite at ${TAG}"       go go test ./tests/spec/
  gate "compliance suite at ${TAG}" go go test ./tests/compliance/

  echo
  echo "passed $PASSED, failed ${#FAILED[@]}"
  for f in "${FAILED[@]:-}"; do [ -n "$f" ] && echo "  ${RED}failed${OFF}  $f"; done
  echo
  echo "${DIM}Only the gates that read git history are run here. Everything else"
  echo "behaves the same at a tag as on a branch, so --fast covers it.${OFF}"
  exit "${#FAILED[@]}"
fi

echo "== fast gates =="
gate "Version consistency"  bash          bash scripts/release-check.sh --version-only
gate "Go build"             go            go build ./...
gate "Go vet"               go            go vet ./...
gate "Go module hygiene"    go            git diff --exit-code -- go.mod go.sum
gate "golangci-lint"        golangci-lint golangci-lint run --timeout 10m
gate "govulncheck"          govulncheck   govulncheck ./...
gate "GoReleaser config"    goreleaser    goreleaser check
gate "ruff"                 ruff          ruff check .
gate "shellcheck"           shellcheck    bash -c 'shellcheck scripts/*.sh'
gate "yamllint"             yamllint      yamllint -c .yamllint.yml .
gate "Helm chart"           helm          helm lint charts/vault

# gofmt reports by printing names, so an empty result is the pass condition.
# shellcheck disable=SC2016 # the child shell expands these, not this one
gate "gofmt" gofmt bash -c '
  out=$(gofmt -l . 2>/dev/null | grep -v "^web/")
  [ -z "$out" ] || { echo "$out"; exit 1; }'

# shellcheck disable=SC2016 # the child shell expands these, not this one
gate "Hadolint" hadolint bash -c '
  rc=0
  while IFS= read -r f; do hadolint "$f" || rc=1; done < <(git ls-files "*Dockerfile*")
  exit $rc'

gate "markdownlint" node bash -c "$NPX markdownlint-cli2@0.23.2 '**/*.md'"

# Every commit the PR would carry, which is what CI lints. A type outside the
# enum on any of them fails the check, including commits that predate the PR.
gate "commitlint" node bash -c "
  base=\$(git merge-base origin/main HEAD)
  $NPX --package @commitlint/cli --package @commitlint/config-conventional -- \
    commitlint --from \"\$base\" --to HEAD"

# Trivy scans an export of the tracked tree, not the working directory, because
# CI scans a fresh checkout and this machine is not one. k8s/dev/ holds
# generated development certificates -- gitignored, never pushed -- and scanning
# in place reports four private keys that no clone has ever contained. Skipping
# them by name would rot the moment another ignored path appears; exporting what
# git tracks cannot.
#
# The flags mirror .github/workflows/nightly-security.yml: all three scanners,
# the same severities, the same ignore file, and the file patterns for the two
# goreleaser Dockerfiles whose names Trivy does not recognise on its own.
# shellcheck disable=SC2016 # the child shell expands these, not this one
gate "Trivy source" trivy bash -c '
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" EXIT
  git archive HEAD | tar -x -C "$tmp" || exit 1
  TRIVY_FILE_PATTERNS=dockerfile:Dockerfile.goreleaser.admin-gateway,dockerfile:Dockerfile.goreleaser.bridge \
  trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL \
    --ignorefile .trivyignore.yaml --exit-code 1 --quiet "$tmp"'

# shellcheck disable=SC2016 # the child shell expands these, not this one
gate "gosec baseline" gosec bash -c '
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" EXIT
  gosec -tests -fmt json -out "$tmp/g.json" ./... >/dev/null 2>&1
  [ -s "$tmp/g.json" ] || { echo "gosec produced no report; that is a failed scan"; exit 1; }
  python3 scripts/gosec-baseline.py --check "$tmp/g.json"'

gate ".NET build + tests" dotnet bash -c '
  find packages/dotnet -type d \( -name obj -o -name bin \) -prune -exec rm -rf {} + 2>/dev/null
  dotnet build packages/dotnet -warnaserror -p:EnableSourceLink=false && dotnet test packages/dotnet'

gate ".NET coverage floor" dotnet bash -c './scripts/dotnet-coverage.sh'

if [ "$FAST" -eq 1 ]; then
  echo
  echo "${DIM}--fast: skipped the race suite and the coverage gate${OFF}"
else
  echo
  echo "== slow gates =="
  gate "Race suite"    go go test -race -count=1 ./...
  gate "Coverage gate" go bash -c './scripts/coverage.sh && ./scripts/release-check.sh --coverage-only'
fi

echo
echo "passed $PASSED, failed ${#FAILED[@]}, skipped ${#SKIPPED[@]}"
for s in "${SKIPPED[@]:-}"; do [ -n "$s" ] && echo "  ${YELLOW}skipped${OFF} $s"; done
for f in "${FAILED[@]:-}"; do [ -n "$f" ] && echo "  ${RED}failed${OFF}  $f"; done

echo
echo "${DIM}Still only CI can run: Trivy image scans, CodeQL, Scorecard, the"
echo "attestation and signing steps, and the container-backed suites when no"
echo "runtime is available here. A green run below is necessary, not sufficient.${OFF}"

exit "${#FAILED[@]}"
