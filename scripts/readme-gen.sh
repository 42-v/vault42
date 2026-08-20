#!/bin/bash
# Generate docs/badges.json, docs/deps.md, and update README.md static badges.
# Badges use sentinel comments in README.md so they work with private repos
# (no raw.githubusercontent.com access needed).
#
# CI sets TEST_OUTPUT_FILE + COVERAGE_FILE to reuse test artifacts.
set -eo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=lib/coverage-env.sh
source "$(dirname "$0")/lib/coverage-env.sh"

COVER_FILE=$(mktemp)
TEST_OUT=$(mktemp)
CREATOR_TMP=$(mktemp)
trap 'rm -f "$COVER_FILE" "$TEST_OUT" "$CREATOR_TMP"' EXIT

# ═══════════════════════════════════════════════════════════════
# 1. Run tests ONCE — get verbose output + coverage profile
#    CI sets TEST_OUTPUT_FILE + COVERAGE_FILE to skip re-running.
#    The package set and the number come from scripts/lib/coverage-env.sh, so
#    the README badge always matches docs/test-coverage.md.
# ═══════════════════════════════════════════════════════════════
if [ -n "${TEST_OUTPUT_FILE:-}" ] && [ -f "${TEST_OUTPUT_FILE}" ] && \
   [ -n "${COVERAGE_FILE:-}" ] && [ -f "${COVERAGE_FILE}" ]; then
  echo "Using pre-computed test artifacts"
  cp "$TEST_OUTPUT_FILE" "$TEST_OUT"
  cp "$COVERAGE_FILE" "$COVER_FILE"
else
  cov_require_runtime
  echo "Running full-suite tests (DOCKER_HOST=$DOCKER_HOST)..."
  cov_run "$COVER_FILE" "$TEST_OUT"
  # Without this a killed or timed-out run writes a partial profile and the
  # README badge is regenerated from it, reporting a coverage figure no run
  # actually produced.
  cov_check_failures "$TEST_OUT"
fi

PASSED=$(grep -c '^--- PASS' "$TEST_OUT" || true)
PKGS=$(grep -c '^ok\s' "$TEST_OUT" || true)
TOTAL_COV=$(cov_total "$COVER_FILE")

# ═══════════════════════════════════════════════════════════════
# 2. Code metrics (no tests needed — fast)
# ═══════════════════════════════════════════════════════════════
GO_FILES=$(find . -name '*.go' -not -path './vendor/*' | grep -cv '_test\.go$')
GO_LINES=$(find . -name '*.go' -not -path './vendor/*' -not -name '*_test.go' -exec cat {} + | wc -l | tr -d ' ')
TEST_FILES=$(find . -name '*_test.go' -not -path './vendor/*' | wc -l | tr -d ' ')

# ═══════════════════════════════════════════════════════════════
# 3. GitHub stars + latest version lookups
# ═══════════════════════════════════════════════════════════════
gh_repo() {
  case "$1" in
    github.com/*)
      echo "$1" | sed 's|^github.com/||; s|/v[0-9]*$||'
      ;;
    golang.org/x/*)
      echo "$1" | sed 's|^golang.org/x/|golang/|; s|/v[0-9]*$||'
      ;;
    go.uber.org/*)
      echo "$1" | sed 's|^go.uber.org/|uber-go/|; s|/v[0-9]*$||'
      ;;
    *) echo "" ;;
  esac
}

go_latest_info() {
  local mod="$1"
  GO_LATEST_VER=""
  GO_LATEST_TIME=""
  local json
  json=$(curl -sf --max-time 5 "https://proxy.golang.org/${mod}/@latest" 2>/dev/null) || return 0
  GO_LATEST_VER=$(echo "$json" | grep -oP '"Version"\s*:\s*"[^"]*"' | grep -oP 'v[^"]+') || true
  GO_LATEST_TIME=$(echo "$json" | grep -oP '"Time"\s*:\s*"[^"]*"' | grep -oP '\d{4}-\d{2}-\d{2}') || true
}

dep_note() {
  case "$1" in
    *jackc/pgx*)            echo "PostgreSQL driver + connection pool" ;;
    *go-webauthn/webauthn)  echo "WebAuthn/FIDO2 passkey support" ;;
    *golang.org/x/crypto*)  echo "Argon2id password hashing" ;;
    *fxamacker/cbor*)       echo "webauthn (CBOR encoding)" ;;
    *go-viper/mapstructure*)echo "webauthn" ;;
    *go-webauthn/x*)        echo "webauthn" ;;
    *google/go-tpm*)        echo "webauthn (TPM attestation)" ;;
    *google/uuid*)          echo "webauthn" ;;
    *jackc/pgpassfile*)     echo "pgx" ;;
    *jackc/pgservicefile*)  echo "pgx" ;;
    *jackc/puddle*)         echo "pgx (connection pool)" ;;
    *x448/float16*)         echo "cbor" ;;
    *golang.org/x/sync*)    echo "pgx" ;;
    *golang.org/x/sys*)     echo "x/crypto" ;;
    *golang.org/x/text*)    echo "x/crypto" ;;
    *)                      echo "" ;;
  esac
}

# ═══════════════════════════════════════════════════════════════
# 4. Parse go.mod for dependencies
# ═══════════════════════════════════════════════════════════════
DIRECT_ROWS=""
INDIRECT_ROWS=""
DIRECT_COUNT=0
INDIRECT_COUNT=0
IN_REQ=""

while IFS= read -r line; do
  if echo "$line" | grep -qP '^\s*require\s*\('; then
    IN_REQ="yes"; continue
  fi
  if [ "$IN_REQ" = "yes" ] && echo "$line" | grep -qP '^\s*\)'; then
    IN_REQ=""; continue
  fi
  [ "$IN_REQ" != "yes" ] && continue

  MOD=$(echo "$line" | awk '{print $1}')
  VER=$(echo "$line" | awk '{print $2}')
  [ -z "$MOD" ] && continue

  # Skip test-only dependencies
  case "$MOD" in
    github.com/testcontainers/*|github.com/chromedp/*) continue ;;
    github.com/docker/*|github.com/containerd/*|github.com/moby/*) continue ;;
    github.com/opencontainers/*|github.com/distribution/*) continue ;;
    github.com/cpuguy83/dockercfg*|github.com/mdelapenya/tlscert*) continue ;;
    github.com/cenkalti/backoff*|github.com/magiconair/properties*) continue ;;
    github.com/Azure/go-ansiterm*|github.com/Microsoft/go-winio*) continue ;;
    github.com/klauspost/compress*|github.com/morikuni/aec*) continue ;;
    github.com/shirou/gopsutil*|github.com/lufia/plan9stats*) continue ;;
    github.com/power-devops/perfstat*|github.com/tklauser/*) continue ;;
    github.com/yusufpapurcu/wmi*|github.com/go-ole/go-ole*) continue ;;
    github.com/ebitengine/purego*) continue ;;
    github.com/sirupsen/logrus*|github.com/stretchr/testify*) continue ;;
    github.com/davecgh/go-spew*|github.com/pmezard/go-difflib*) continue ;;
    github.com/gobwas/*|github.com/go-json-experiment/*) continue ;;
    go.opentelemetry.io/*|github.com/grpc-ecosystem/*) continue ;;
    google.golang.org/grpc*|google.golang.org/protobuf*) continue ;;
    github.com/felixge/httpsnoop*) continue ;;
    dario.cat/mergo*|gopkg.in/yaml.v3*) continue ;;
  esac

  # Shorten a Go pseudo-version by dropping its timestamp segment:
  # v0.0.0-20240101120000-abcdef123456 -> v0.0.0-abcdef123456.
  DISPLAY_VER="$VER"
  if [[ "$VER" =~ ^v0\.0\.0-[0-9]*-(.*)$ ]]; then
    DISPLAY_VER="v0.0.0-${BASH_REMATCH[1]}"
  fi
  NOTE=$(dep_note "$MOD")
  REPO=$(gh_repo "$MOD")

  # Track creator → packages
  if [ -n "$REPO" ]; then
    OWNER=$(echo "$REPO" | cut -d/ -f1)
    SHORT_PKG=$(echo "$REPO" | cut -d/ -f2)
    echo "${OWNER}	${SHORT_PKG}" >> "$CREATOR_TMP"
  fi

  go_latest_info "$MOD"
  UPDATED="${GO_LATEST_TIME:---}"

  if echo "$line" | grep -q '// indirect'; then
    if [ -n "$REPO" ]; then
      STARS="![stars](https://img.shields.io/github/stars/${REPO}?style=flat&label=)"
    else
      STARS=""
    fi
    INDIRECT_ROWS="${INDIRECT_ROWS}| \`${MOD}\` | ${DISPLAY_VER} | ${NOTE} | ${STARS} | ${UPDATED} |
"
    INDIRECT_COUNT=$((INDIRECT_COUNT + 1))
  else
    if [ -n "$GO_LATEST_VER" ] && [ "$GO_LATEST_VER" != "$VER" ]; then
      VER_STATUS="${VER} (latest: ${GO_LATEST_VER})"
    else
      VER_STATUS="${VER}"
    fi
    STARS="![stars](https://img.shields.io/github/stars/${REPO}?style=flat&label=)"
    DIRECT_ROWS="${DIRECT_ROWS}| \`${MOD}\` | ${VER_STATUS} | ${NOTE} | ${STARS} | ${UPDATED} |
"
    DIRECT_COUNT=$((DIRECT_COUNT + 1))
  fi
done < go.mod

# ═══════════════════════════════════════════════════════════════
# 5. Per-package coverage summary (derived from the profile, not from the
#    per-test-binary "coverage: X% of statements" lines, which under -coverpkg
#    report one binary's contribution rather than the package's own coverage)
# ═══════════════════════════════════════════════════════════════
COVERAGE_ROWS=""
if [ -s "$COVER_FILE" ]; then
  COVERAGE_ROWS=$(cov_pkg_table "$COVER_FILE")
fi

# ═══════════════════════════════════════════════════════════════
# 6. Dependency creators — unique GitHub orgs/users with stats
# ═══════════════════════════════════════════════════════════════
echo "Fetching creator stats..."
CREATOR_ROWS=""
CREATOR_COUNT=0

while IFS= read -r owner; do
  pkgs=$(grep "^${owner}	" "$CREATOR_TMP" | cut -f2 | sort -u | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g')
  gh_json=$(curl -sf --max-time 5 "https://api.github.com/users/${owner}" 2>/dev/null) || gh_json=""

  if [ -n "$gh_json" ]; then
    gh_type=$(echo "$gh_json" | grep -oP '"type"\s*:\s*"[^"]*"' | grep -oP '"[^"]*"$' | tr -d '"')
    gh_repos=$(echo "$gh_json" | grep -oP '"public_repos"\s*:\s*[0-9]+' | grep -oP '[0-9]+')
    gh_created=$(echo "$gh_json" | grep -oP '"created_at"\s*:\s*"[^"]*"' | grep -oP '\d{4}-\d{2}-\d{2}')

    if [ "$gh_type" = "Organization" ]; then
      TYPE_LABEL="Org"
    else
      TYPE_LABEL="User"
    fi

    CREATOR_ROWS="${CREATOR_ROWS}| [${owner}](https://github.com/${owner}) | ${TYPE_LABEL} | ${pkgs} | ${gh_repos:-—} | ![followers](https://img.shields.io/github/followers/${owner}?style=flat&label=) | ${gh_created:-—} |
"
  else
    CREATOR_ROWS="${CREATOR_ROWS}| [${owner}](https://github.com/${owner}) | — | ${pkgs} | — | — | — |
"
  fi
  CREATOR_COUNT=$((CREATOR_COUNT + 1))
done < <(cut -f1 "$CREATOR_TMP" | sort -u)

COV_NUM=$(echo "$TOTAL_COV" | tr -d '%')

# Reachable coverage comes from the same tool the release gate uses, so the badge
# cannot claim a figure the gate would reject. Excluded statements are the ones no
# test can reach; .coverage-exclusions.json records why, per statement.
#
# cov-gaps' exit code is load-bearing here. Discarding it and falling back to raw
# total coverage gives a broken exclusion set a badge in the same shape as every
# other run's, with nothing anywhere saying the set the figure is a claim about no
# longer resolves: the badge could not fail, only quietly mean something else.
# Either the set verifies against this profile or no badge is written.
COV_JSON=$(python3 scripts/cov-gaps.py "$COVER_FILE" --json) || {
  echo "ERROR: the exclusion set does not resolve against $COVER_FILE (see above)." >&2
  echo "Run: python3 scripts/cov-gaps.py $COVER_FILE --verify-exclusions" >&2
  echo "Refusing to publish a reachable-coverage badge no exclusion set backs." >&2
  exit 1
}
REACHABLE_COV=$(printf '%s' "$COV_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
reach = d["total_statements"] - d["excluded_statements"]
if reach <= 0:
    sys.exit("every instrumented statement is excluded; there is no reachable figure")
print("%.2f" % (100.0 * d["covered_statements"] / reach))
')

VERSION_STR=$(cat VERSION 2>/dev/null || echo "0.0.0")

mkdir -p docs

# ═══════════════════════════════════════════════════════════════
# 8. Generate docs/deps.md
# ═══════════════════════════════════════════════════════════════
# Every row set is normalised to carry no trailing newline, and every blank
# line in the document comes from the template below rather than from whichever
# variable happened to end in one.
#
# They did not agree before. DIRECT_ROWS, INDIRECT_ROWS and CREATOR_ROWS are
# built by appending literal newlines and so ended with one, while
# COVERAGE_ROWS comes from a command substitution, which strips them. The
# result was a heading pressed against the end of a table (MD022, MD058) and a
# double blank line at the end of the file (MD012) -- emitted afresh on every
# regeneration, so the markdownlint findings a previous commit cleared came
# straight back.
DIRECT_ROWS="${DIRECT_ROWS%"${DIRECT_ROWS##*[!$'\n']}"}"
INDIRECT_ROWS="${INDIRECT_ROWS%"${INDIRECT_ROWS##*[!$'\n']}"}"
CREATOR_ROWS="${CREATOR_ROWS%"${CREATOR_ROWS##*[!$'\n']}"}"

COVERAGE_BLOCK=""
if [ -n "$COVERAGE_ROWS" ]; then
  COVERAGE_BLOCK="

## Coverage by Package

| Package | Coverage |
|---|---|
${COVERAGE_ROWS}"
fi

CREATORS_BLOCK=""
if [ -n "$CREATOR_ROWS" ]; then
  CREATORS_BLOCK="

## Maintainers

${CREATOR_COUNT} maintainers behind Vault's dependency tree.

| Creator | Type | Packages | Repos | Followers | Since |
|---|---|---|---|---|---|
${CREATOR_ROWS}"
fi

cat > docs/deps.md <<EOF
# Dependencies

${DIRECT_COUNT} direct dependencies. Everything else — TOTP, CORS, JWKS, config, migrations, password hashing — is stdlib or hand-written.

## Direct

| Dependency | Version | Purpose | Stars | Updated |
|---|---|---|---|---|
${DIRECT_ROWS}

## Transitive (${INDIRECT_COUNT} pulled by the above)

| Dependency | Version | Pulled by | Stars | Updated |
|---|---|---|---|---|
${INDIRECT_ROWS}${COVERAGE_BLOCK}${CREATORS_BLOCK}
EOF

# ═══════════════════════════════════════════════════════════════
# 9. Collect Vue frontend stats
# ═══════════════════════════════════════════════════════════════
if [ -n "${VUE_TESTS:-}" ]; then
  FE_TESTS="$VUE_TESTS"
else
  FE_OUT=$(mktemp)
  (cd web && npx vitest run 2>&1) > "$FE_OUT" || true
  (cd packages/vue && npx vitest run 2>&1) >> "$FE_OUT" || true
  FE_TESTS=$({ grep -oP '\d+(?= passed)' "$FE_OUT" || true; } | awk '{s+=$1}END{print s+0}')
  # Both runs above are `|| true`, and awk turns "no matches" into 0, so a
  # frontend suite that cannot run at all -- no node_modules, no registry, a
  # renamed reporter -- used to publish a Vue_Tests badge reading 0 and a Total
  # counting only Go. That is the failure this repository spent a release
  # removing: a suite that cannot run reporting a number instead of saying so.
  # The Go side already refuses through cov_check_failures; this is the same
  # rule for the half that runs under node.
  if [ "$FE_TESTS" -eq 0 ]; then
    echo "ERROR: the frontend suites reported no passing tests." >&2
    echo "  Neither web nor packages/vue produced a '<n> passed' line, so there is no measurement" >&2
    echo "  to publish. Install the workspace (pnpm install --frozen-lockfile) and re-run, or pass" >&2
    echo "  VUE_TESTS=<n> from a run that did measure. Publishing 0 here would put a false count in" >&2
    echo "  the README badge and understate the total." >&2
    sed -n '1,20p' "$FE_OUT" >&2
    rm -f "$FE_OUT"
    exit 1
  fi
  rm -f "$FE_OUT"
fi

FE_LINES="${VUE_LINES:-$(find web/src packages/vue/src \( -name '*.vue' -o -name '*.ts' \) -not -path '*__tests__*' -not -name '*.test.*' -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')}"
FE_LOCALES="${VUE_LOCALES:-$(find web/src/locales -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')}"
FE_DEPS=$(python3 -c "
import json
web = json.load(open('web/package.json'))
vue = json.load(open('packages/vue/package.json'))
deps = set(list(web.get('dependencies',{}).keys()) + list(vue.get('peerDependencies',{}).keys()))
deps.discard('@vault42/vue')
print(len(deps))
")

# Frontend coverage, combined across the two packages. vitest already writes a
# json-summary for each; combining the raw counts rather than averaging the two
# percentages is the difference between a number and a number-shaped thing,
# because the packages are not the same size.
FE_COV="${VUE_COVERAGE:-}"
if [ -z "$FE_COV" ]; then
  FE_COV=$(python3 -c "
import json, sys

covered = total = 0
found = []
for path in ('web/coverage/coverage-summary.json', 'packages/vue/coverage/coverage-summary.json'):
    try:
        with open(path) as fh:
            stmts = json.load(fh)['total']['statements']
    except (OSError, KeyError, ValueError):
        continue
    covered += stmts['covered']
    total += stmts['total']
    found.append(path)

# Same rule the test count above follows: a measurement that did not happen is
# reported as absent, never as a number. Publishing a coverage badge derived
# from one of the two packages would understate or overstate it silently.
if len(found) != 2 or total == 0:
    sys.exit('MISSING')
print(f'{100.0 * covered / total:.2f}')
" 2>/dev/null) || {
    echo "ERROR: no combined frontend coverage summary." >&2
    echo "  web/coverage/coverage-summary.json and packages/vue/coverage/coverage-summary.json are" >&2
    echo "  what the Vue coverage badge quotes. Run 'pnpm -C web test:coverage' and" >&2
    echo "  'pnpm -C packages/vue test:coverage', or pass VUE_COVERAGE=<pct> from a run that did" >&2
    echo "  measure. A badge is a claim; there is nothing here to back one." >&2
    exit 1
  }
fi

# ═══════════════════════════════════════════════════════════════
# 9b. Collect C# SDK stats
#
# The two packages under packages/dotnet are published to nuget.org, and until
# 1.0.1 nothing on a pull request built them. They are a shipped language
# surface with their own suite and their own coverage gate, so they get their
# own badge column rather than being folded into a total that hides them.
# ═══════════════════════════════════════════════════════════════
CS_TESTS="${DOTNET_TESTS:-}"
CS_COV="${DOTNET_COVERAGE:-}"

if [ -z "$CS_COV" ] || [ -z "$CS_TESTS" ]; then
  CS_JSON=$(mktemp)
  if scripts/dotnet-coverage.sh --json "$CS_JSON" > "$CS_JSON.log" 2>&1; then
    [ -z "$CS_COV" ] && CS_COV=$(python3 -c "import json;print(f\"{json.load(open('$CS_JSON'))['percent']:.2f}\")")
    [ -z "$CS_TESTS" ] && CS_TESTS=$({ grep -oP '(?<=Passed:)\s*\d+' "$CS_JSON.log" || true; } | awk '{s+=$1}END{print s+0}')
  fi
  rm -f "$CS_JSON" "$CS_JSON.log"
fi

if [ -z "$CS_COV" ] || [ -z "${CS_TESTS:-}" ] || [ "${CS_TESTS:-0}" -eq 0 ]; then
  echo "ERROR: the .NET SDK suites reported no measurement." >&2
  echo "  scripts/dotnet-coverage.sh produced neither a test count nor a coverage figure, so" >&2
  echo "  there is nothing to put in the C# badge column. Install the .NET SDK and re-run, or" >&2
  echo "  pass DOTNET_TESTS=<n> DOTNET_COVERAGE=<pct> from a run that did measure. This refuses" >&2
  echo "  rather than publishing a zero, for the same reason the Go and Vue halves do." >&2
  exit 1
fi

CS_LINES=$(find packages/dotnet/src \( -name '*.cs' -o -name '*.razor' \) \
  -not -path '*/obj/*' -not -path '*/bin/*' -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')
CS_DEPS=$(grep -rhoP '(?<=<PackageReference Include=")[^"]+' \
  packages/dotnet/src/*/*.csproj 2>/dev/null | sort -u | wc -l | tr -d ' ')

# ═══════════════════════════════════════════════════════════════
# 9c. Generate docs/badges.json
#
# Written here rather than earlier because it now carries all three languages,
# and two of them are not measured until the sections above have run. The
# top-level keys are the Go ones and keep their old names and meanings: they
# were the only language when the file was designed, and a consumer reading
# `tests` should not silently start getting a different number.
# ═══════════════════════════════════════════════════════════════
cat > docs/badges.json <<EOF
{
  "schemaVersion": 1,
  "version": "${VERSION_STR}",
  "tests": ${PASSED},
  "passed": "${PASSED} passed",
  "coverage": "${TOTAL_COV}",
  "coverageNum": ${COV_NUM},
  "reachableCoverage": "${REACHABLE_COV}%",
  "reachableCoverageNum": ${REACHABLE_COV},
  "packages": ${PKGS},
  "goFiles": ${GO_FILES},
  "goLines": ${GO_LINES},
  "testFiles": ${TEST_FILES},
  "directDeps": ${DIRECT_COUNT},
  "transitiveDeps": ${INDIRECT_COUNT},
  "totalTests": $((PASSED + FE_TESTS + CS_TESTS)),
  "languages": {
    "go": {
      "tests": ${PASSED},
      "coverage": "${REACHABLE_COV}% of reachable",
      "coverageNum": ${REACHABLE_COV},
      "lines": ${GO_LINES},
      "deps": ${DIRECT_COUNT}
    },
    "vue": {
      "tests": ${FE_TESTS},
      "coverage": "${FE_COV}%",
      "coverageNum": ${FE_COV},
      "lines": ${FE_LINES},
      "deps": ${FE_DEPS}
    },
    "csharp": {
      "tests": ${CS_TESTS},
      "coverage": "${CS_COV}%",
      "coverageNum": ${CS_COV},
      "lines": ${CS_LINES},
      "deps": ${CS_DEPS}
    }
  }
}
EOF

# ═══════════════════════════════════════════════════════════════
# 10. Update badge table in README.md
#     Uses sentinel: <!-- badges -->...<!-- /badges -->
# ═══════════════════════════════════════════════════════════════
if [ -f README.md ]; then
  # The badge reports reachable coverage and says so, because the bare figure is
  # the one a reader will quote back. The unqualified total is in docs/badges.json
  # and docs/test-coverage.md for anyone who wants to check the difference.
  COV_ENCODED="${REACHABLE_COV}%25_reachable"
  if [ "$(echo "$COV_NUM >= 80" | bc)" -eq 1 ]; then
    COV_COLOR="155724"
  elif [ "$(echo "$COV_NUM >= 60" | bc)" -eq 1 ]; then
    COV_COLOR="7d6e00"
  else
    COV_COLOR="red"
  fi

  # Report what ships, not the floor the module declares it can build against. The
  # two differ exactly when it matters: a security bump moves `toolchain` and leaves
  # the `go` directive alone, so deriving from `go` published Go-1.26.0 on releases
  # cut specifically to clear a toolchain CVE.
  GO_VER=$(grep '^toolchain ' go.mod | awk '{print $2}' | sed 's/^go//')
  if [ -z "$GO_VER" ]; then
    GO_VER=$(grep '^go ' go.mod | awk '{print $2}')
  fi
  VUE_VER=$(grep '"vue":' web/package.json | grep -oP '[\d.]+' | head -1)
  CS_VER=$(grep -oP '(?<=<TargetFramework>net)[\d.]+' \
    packages/dotnet/src/Vault42.AspNetCore/Vault42.AspNetCore.csproj | head -1)
  TOTAL_TESTS=$((PASSED + FE_TESTS + CS_TESTS))

  # The register is the source for these two, so the badge cannot claim a
  # standard count the register does not carry.
  REG_STANDARDS=$(python3 -c "import json;print(len(json.load(open('docs/compliance-register.json'))['standards']))")
  REG_REQS=$(python3 -c "import json;print(len(json.load(open('docs/compliance-register.json'))['requirements']))")

  python3 -c "
import re

with open('README.md', 'r') as f:
    text = f.read()

S = 'https://img.shields.io/badge'


def colour(pct):
    \"\"\"Same thresholds the Go figure has always used, applied per language.\"\"\"
    value = float(pct)
    if value >= 80:
        return '155724'
    if value >= 60:
        return '7d6e00'
    return 'red'


go_colour = '${COV_COLOR}'
vue_colour = colour('${FE_COV}')
cs_colour = colour('${CS_COV}')

table = f'''| Go | Vue | C# | |
|---|---|---|---|
| ![Go]({S}/Go-${GO_VER}-00ADD8?style=flat&logo=go&logoColor=white) | ![Vue]({S}/Vue-${VUE_VER}-4FC08D?style=flat&logo=vuedotjs&logoColor=white) | ![.NET]({S}/.NET-${CS_VER}-512BD4?style=flat&logo=dotnet&logoColor=white) | ![License]({S}/License-MIT-155724?style=flat&labelColor=000) |
| ![Go Tests]({S}/Tests-${PASSED}-155724?style=flat&labelColor=000) | ![Vue Tests]({S}/Tests-${FE_TESTS}-155724?style=flat&labelColor=000) | ![C# Tests]({S}/Tests-${CS_TESTS}-155724?style=flat&labelColor=000) | ![Total]({S}/Total-${TOTAL_TESTS}_tests-155724?style=flat&labelColor=000) |
| ![Go Coverage]({S}/Coverage-${COV_ENCODED}-{go_colour}?style=flat&labelColor=000) | ![Vue Coverage]({S}/Coverage-${FE_COV}%25-{vue_colour}?style=flat&labelColor=000) | ![C# Coverage]({S}/Coverage-${CS_COV}%25-{cs_colour}?style=flat&labelColor=000) | ![Locales]({S}/Locales-${FE_LOCALES}-555?style=flat&labelColor=000) |
| ![Go Lines]({S}/Lines-${GO_LINES}-555?style=flat&labelColor=000) | ![Vue Lines]({S}/Lines-${FE_LINES}-555?style=flat&labelColor=000) | ![C# Lines]({S}/Lines-${CS_LINES}-555?style=flat&labelColor=000) | ![Standards]({S}/Standards-${REG_STANDARDS}-555?style=flat&labelColor=000) |
| ![Go Deps]({S}/Deps-${DIRECT_COUNT}-555?style=flat&labelColor=000) | ![Vue Deps]({S}/Deps-${FE_DEPS}-555?style=flat&labelColor=000) | ![C# Deps]({S}/Deps-${CS_DEPS}-555?style=flat&labelColor=000) | ![Requirements]({S}/Requirements-${REG_REQS}-555?style=flat&labelColor=000) |'''

text = re.sub(
    r'(<!-- badges -->\n).*?(\n<!-- /badges -->)',
    r'\1' + table + r'\2',
    text,
    flags=re.DOTALL
)

with open('README.md', 'w') as f:
    f.write(text)
"
  echo "README.md badges updated"
fi

echo "docs/badges.json + docs/deps.md updated: ${PASSED} Go (${REACHABLE_COV}% reachable) + "\
     "${FE_TESTS} Vue (${FE_COV}%) + ${CS_TESTS} C# (${CS_COV}%) tests, ${DIRECT_COUNT}+${INDIRECT_COUNT} Go deps"
