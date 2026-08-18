#!/bin/bash
# Pre-commit verification. Run BEFORE every commit.
# Outputs a structured report: build, tests, stats, git state, recent commits.
# Exit code 0 = safe to commit. Non-zero = fix issues first.
#
# Each step is a standalone script in scripts/precommit/ for isolation.
set -eo pipefail
cd "$(dirname "$0")/.."

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
RESET=$'\033[0m'

section() { printf '\n%s--- %s ---%s\n' "$BOLD" "$1" "$RESET"; }

echo ""
printf '%s=== PRE-COMMIT CHECK ===%s\n' "$BOLD" "$RESET"

# 1. Build + vet (gate — fail fast)
section "Build & Vet"
if bash scripts/precommit/01-build.sh; then
  printf '%sPASS%s\n' "$GREEN" "$RESET"
else
  printf '%sFAIL%s — fix build/vet errors before committing\n' "$RED" "$RESET"
  exit 1
fi

# 2. Security (gosec)
section "Security (gosec)"
GOSEC_RESULT=$(bash scripts/precommit/02-gosec.sh 2>&1) || {
  printf '%sFAIL%s — gosec found issues\n' "$RED" "$RESET"
  echo "$GOSEC_RESULT"
  exit 1
}
if [ "$GOSEC_RESULT" = "SKIP" ]; then
  printf '%sSKIP (gosec not installed)%s\n' "$DIM" "$RESET"
else
  printf '%sPASS%s\n' "$GREEN" "$RESET"
fi

# 3. Go tests (verbose + coverage)
section "Tests"
GO_TEST_RESULT=$(bash scripts/precommit/03-go-tests.sh)
# Last 3 lines: "PASS FAIL PKGS", COVER_FILE path, TEST_FILE path
TEST_FILE=$(echo "$GO_TEST_RESULT" | tail -1)
COVER_FILE=$(echo "$GO_TEST_RESULT" | tail -2 | head -1)
read -r PASS FAIL PKGS <<< "$(echo "$GO_TEST_RESULT" | tail -3 | head -1)"
printf "%d passed, %d failed, %d packages\n" "$PASS" "$FAIL" "$PKGS"
if [ "$FAIL" -gt 0 ]; then
  printf '%sFAILURES detected — see above%s\n' "$RED" "$RESET"
fi

# 4. Frontend tests
section "Frontend Tests"
VUE_RESULT=$(bash scripts/precommit/04-vue-tests.sh)
read -r VUE_PASS VUE_FAIL <<< "$VUE_RESULT"
printf "%d passed, %d failed\n" "$VUE_PASS" "$VUE_FAIL"
if [ "$VUE_FAIL" -gt 0 ]; then
  printf '%sFAIL%s — frontend tests have failures\n' "$RED" "$RESET"
  FAIL=$((FAIL + VUE_FAIL))
fi

# 5. Code stats
section "Stats"
read -r GO_FILES GO_LINES TEST_FILES VUE_FILES VUE_LINES LOCALE_COUNT <<< "$(bash scripts/precommit/05-stats.sh)"
printf "Go: %s source files, %s lines, %s test files, %d tests\n" "$GO_FILES" "$GO_LINES" "$TEST_FILES" "$PASS"
printf "Vue: %s source files, %s lines, %d tests, %s locales\n" "$VUE_FILES" "$VUE_LINES" "$VUE_PASS" "$LOCALE_COUNT"

# 6. Update README badges, deps, and coverage
section "Docs"
bash scripts/precommit/06-docs.sh "$TEST_FILE" "$COVER_FILE" "$VUE_PASS" "$VUE_LINES" "$LOCALE_COUNT"
printf '%sPASS%s — badges, deps, and coverage updated\n' "$GREEN" "$RESET"

# Cleanup temp files from step 3
rm -f "$COVER_FILE" "$TEST_FILE"

# 7. Git status
section "Git Status"
STATUS=$(git status --short 2>/dev/null)
if [ -z "$STATUS" ]; then
  printf '%sclean — nothing to commit%s\n' "$DIM" "$RESET"
else
  echo "$STATUS"
fi

# 8. Staged changes
STAGED=$(git diff --cached --stat 2>/dev/null)
if [ -n "$STAGED" ]; then
  section "Staged Changes"
  echo "$STAGED"
fi

# 9. Unstaged changes
UNSTAGED=$(git diff --stat 2>/dev/null)
if [ -n "$UNSTAGED" ]; then
  section "Unstaged Changes"
  echo "$UNSTAGED"
fi

# 10. Recent commits (for message style reference)
section "Recent Commits"
git log --oneline -5 2>/dev/null

# Verdict
echo ""
if [ "$FAIL" -gt 0 ]; then
  printf '%s%s=== VERDICT: FAIL (%d test failures) ===%s\n' "$RED" "$BOLD" "$FAIL" "$RESET"
  exit 1
else
  TOTAL=$((PASS + VUE_PASS))
  printf '%s%s=== VERDICT: OK (%d Go + %d Vue = %d tests, build clean) ===%s\n' "$GREEN" "$BOLD" "$PASS" "$VUE_PASS" "$TOTAL" "$RESET"
fi
