#!/bin/bash
# Shared coverage plumbing. Sourced by scripts/coverage.sh and scripts/readme-gen.sh
# so docs/test-coverage.md, docs/badges.json and the README badge can never
# disagree about what "coverage" means.
#
# ONE canonical package set, ONE canonical number.
#
# The set spans internal/ AND cmd/. It used to be internal/ only, which meant
# 996 statements of main(), CLI, config parsing, the offline recovery tool and
# the honeypot bridge sat in neither the numerator nor the denominator of a
# badge reading "100.00% reachable". They were not covered and not excluded, the
# one state the exclusion policy says is impossible. Two of those binaries had
# no test file at all, including cmd/recover, which reconstructs data from the
# GDPR erasure escrow.
#
# The set spans every suite that exercises internal/ in-process: unit, attack and
# fuzz, plus the DB-backed integration and compliance suites. Large parts of
# internal/ — repository/postgres, keystore, migrate, the cache backends, the
# wired server — are reachable ONLY through the DB-backed suites. Excluding them
# understated the total by ~6pp and reported a flat 0% for packages that are in
# fact thoroughly tested.
#
# tests/e2e/multireplica is excluded on purpose: its two in-process replicas are
# flaky under coverage instrumentation and double-count in-process code.
#
# tests/honeypot, tests/stress, tests/admin, tests/browser and tests/e2e-browser
# are also out of this set. None of them exercise internal/ in-process on a CI
# runner: honeypot needs locally-tagged vault:dev / vault-bridge:dev images and
# a five-container topology whose host-mapped DB ports do not reach siblings;
# stress, admin, browser and e2e-browser need a deployed cluster (and Chrome or
# Playwright for the last two). Adding a skip-only package would spend a test
# binary on a profile it cannot change. The suites are invoked from the test
# job so the skip is visible; they are not part of the coverage number.

# shellcheck disable=SC2034  # consumed by the sourcing script
COV_PKGS=(
  ./internal/...
  ./cmd/...
  ./tests/unit/...
  ./tests/attack/...
  ./tests/fuzz/...
  ./tests/integration/...
  ./tests/compliance/...
  ./tests/spec/...
)

# cov_detect_runtime exports DOCKER_HOST when a container runtime is reachable.
# Returns 1 when none is. Honors an already-set DOCKER_HOST.
#
# Ryuk (Testcontainers' reaper) needs write access to the container socket, which
# trips SELinux AVC denials on rootless podman + Fedora. Every suite tears down
# its own containers via defer, so the reaper is redundant.
# cov_socket_answers reports whether a container socket is not just present but
# serving. Returns 0 when the daemon answers, 1 when the socket exists and does
# not.
#
# The existence check alone is not enough, and the failure it lets through is the
# expensive kind. A rootless podman can leave its socket file in place while the
# API stops answering: /_ping still returns OK while /version and /info hang
# forever. Detection then succeeds, the coverage run starts, and every suite that
# wants a container blocks until the 40m per-binary timeout, burning most of an
# hour to arrive at a failure the first second could have reported.
#
# /version is the probe rather than /_ping precisely because /_ping is the
# endpoint that keeps answering when the daemon is wedged.
#
# When curl is unavailable this returns 0 rather than refusing, because a missing
# probe tool is not evidence about the daemon and refusing on it would break
# every machine that has a working runtime and no curl.
cov_socket_answers() {
  local sock=$1
  command -v curl >/dev/null 2>&1 || return 0
  curl --silent --fail --max-time 5 --unix-socket "$sock" \
       "http://d/v1.41/version" >/dev/null 2>&1
}

cov_detect_runtime() {
  export TESTCONTAINERS_RYUK_DISABLED=true

  [ -n "${DOCKER_HOST:-}" ] && return 0

  local sock
  for sock in "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock" \
              /run/podman/podman.sock \
              /var/run/docker.sock; do
    if [ -S "$sock" ] && cov_socket_answers "$sock"; then
      export DOCKER_HOST="unix://$sock"
      return 0
    fi
  done
  return 1
}

# cov_require_runtime aborts with an actionable message when no runtime is found.
# Failing loudly matters: without a runtime the DB-backed suites do not run, and
# their statements would silently read as uncovered — a missing Postgres would be
# indistinguishable from a coverage regression.
cov_require_runtime() {
  if ! cov_detect_runtime; then
    cat >&2 <<'MSG'
ERROR: no container runtime found (checked $DOCKER_HOST, podman.sock, docker.sock).

The coverage report needs Postgres + Redis via testcontainers. Start one, or point
DOCKER_HOST at an existing daemon:

  rootless podman:  systemctl --user start podman.socket
                    DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock

Refusing to emit a coverage number that silently omits the DB-backed suites.
MSG
    exit 1
  fi
}

# cov_run PROFILE TESTOUT — the canonical coverage test invocation.
#
# -coverpkg attributes coverage from tests that live under tests/ back to the
# packages they exercise; without it those suites are a silent no-op for the
# profile. cmd/ is listed alongside internal/ so the binaries are measured by the
# same run that measures the library, and cannot drift out of the claim again.
# -count=1 disables the test cache: a cached package is skipped but produces no
# coverage, so a second run would report a lower number than the first.
# -p 1 serializes package binaries — integration and compliance each spin up
# their own Postgres testcontainer and contend for ports when run in parallel.
# -timeout 30m: the integration suite spins a fresh container per test function,
# so its wall-clock grows with the suite; the default 10m/package timeout is not
# enough once integration + compliance are included.
# cov_container_pkgs lists the packages whose tests start a container, derived
# from what they import rather than from a hand-kept list. Five of the 44 do:
# internal/cache, internal/repository/postgres, and the attack, integration and
# compliance suites. The other 39 were serialized because -p 1 was applied to the
# whole run to protect those five.
cov_container_pkgs() {
  go list -f '{{.ImportPath}} {{join .TestImports " "}} {{join .XTestImports " "}}' \
      "${COV_PKGS[@]}" 2>/dev/null |
    grep testcontainers | awk '{print $1}'
}

cov_run() {
  local profile="$1" out="$2"
  # Swallow the exit code so the report is always produced (cov_check_failures
  # gates on it), but record it: `go test` exits 1 on a failed test, 2 on a
  # build error, and >128 when killed by a signal. A killed run writes a partial
  # profile with no FAIL line, so the raw code is the only signal that the number
  # is incomplete rather than a real regression.
  local rc=0 tmp
  tmp=$(mktemp -d)

  # Split the run. The container-bound packages keep -p 1, because each spins up
  # its own Postgres and they contend for ports; everything else has no such
  # constraint and was only ever serialized by association. -coverpkg is
  # identical across both halves so attribution cannot differ between them.
  local serial=() parallel=() pkg
  mapfile -t serial < <(cov_container_pkgs)
  mapfile -t parallel < <(go list "${COV_PKGS[@]}" 2>/dev/null |
    grep -vxF -f <(printf '%s\n' "${serial[@]:-__none__}"))

  local lanes; lanes=$(nproc 2>/dev/null || echo 4)

  if [ "${#parallel[@]}" -gt 0 ]; then
    go test -count=1 -p "$lanes" -timeout 40m -v \
        -coverprofile="$tmp/par.out" -coverpkg=./internal/...,./cmd/... \
        "${parallel[@]}" > "$tmp/par.txt" 2>&1 || rc=$?
  fi
  if [ "${#serial[@]}" -gt 0 ]; then
    local rc2=0
    go test -count=1 -p 1 -timeout 40m -v \
        -coverprofile="$tmp/ser.out" -coverpkg=./internal/...,./cmd/... \
        "${serial[@]}" > "$tmp/ser.txt" 2>&1 || rc2=$?
    [ "$rc" -eq 0 ] && rc=$rc2
  fi

  # One mode header, then every block from both halves. go tool cover and
  # cov-gaps.py both accept repeated blocks for the same statement. The header is
  # copied from the half that produced one rather than hardcoded, so a later
  # -covermode=atomic cannot leave the merged profile claiming "set".
  local mode
  mode=$(head -1 "$tmp/par.out" 2>/dev/null || true)
  case "$mode" in mode:*) ;; *) mode=$(head -1 "$tmp/ser.out" 2>/dev/null || true) ;; esac
  case "$mode" in
    mode:*) ;;
    *) echo "cov_run: neither half produced a coverage profile" >&2
       echo "1" > "${out}.rc"
       cat "$tmp/par.txt" "$tmp/ser.txt" > "$out" 2>/dev/null
       rm -rf "$tmp"
       return 0 ;;
  esac
  {
    echo "$mode"
    cat "$tmp/par.out" "$tmp/ser.out" 2>/dev/null | grep -v '^mode:'
  } > "$profile"
  cat "$tmp/par.txt" "$tmp/ser.txt" > "$out" 2>/dev/null
  rm -rf "$tmp"
  echo "$rc" > "${out}.rc"
}

# cov_check_failures TESTOUT — abort on any build or test failure.
#
# `FAIL\b` also catches `[build failed]`, which emits no `--- FAIL:` line. A
# package that does not compile contributes nothing to the profile, so its
# statements read as uncovered and a build break looks exactly like a coverage
# drop. Both must be fatal, or a regression slips the gate while coverage stays
# plausibly green.
cov_check_failures() {
  local out="$1"
  if grep -qE '^(--- FAIL:|FAIL\b)' "$out"; then
    echo "ERROR: build or test failures during the coverage run:" >&2
    grep -E '^(--- FAIL:|FAIL\b)|\[build failed\]' "$out" >&2 || true
    exit 1
  fi
  # A run killed by a signal (exit >128, e.g. 143=SIGTERM) leaves a partial
  # profile with no FAIL line, so the reported number would be silently deflated.
  # `go test` exits 1/2 on real test/build failures, which the grep above already
  # caught; anything else non-zero here means the run did not complete.
  if [ -f "${out}.rc" ]; then
    local rc
    rc=$(cat "${out}.rc")
    if [ "$rc" -gt 2 ]; then
      echo "ERROR: coverage run did not complete (go test exit $rc); the profile is partial." >&2
      exit 1
    fi
  fi
}

# cov_total PROFILE — total statement coverage to two decimals.
#
# `go tool cover -func` rounds to one decimal, which loses the bullseye targets
# (86.67 vs 86.7). It also cannot dedupe: under -coverpkg the same block appears
# once per test binary, so blocks are OR-folded by key here.
cov_total() {
  python3 - "$1" <<'PY'
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
if total == 0:
    print("0.00%")
else:
    covered = sum(s for s, c in seen.values() if c)
    print(f"{100.0 * covered / total:.2f}%")
PY
}

# cov_pkg_table PROFILE — markdown rows of per-package coverage, best first.
#
# Derived from the profile, NOT from the "X% of statements in ./internal/..."
# line each test package prints under -coverpkg. That line is the contribution of
# one test binary, not the coverage of the package named on it.
cov_pkg_table() {
  python3 - "$1" <<'PY'
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
rows = [(cov / tot, pkg, f"{100.0 * cov / tot:.2f}%")
        for pkg, (tot, cov) in pkg_stmts.items() if tot]
rows.sort(reverse=True)
for _, pkg, pct in rows:
    print(f"| `{pkg}` | {pct} |")
PY
}
