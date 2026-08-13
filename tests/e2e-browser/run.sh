#!/usr/bin/env bash
# Entry point for tests/e2e-browser. Playwright is not a GitHub Actions
# default and the suite talks to a deployed vault + Mailpit, so a CI job
# that just ran `npx playwright test` would either fail 20 ways or, if
# never invoked, pass by not existing.
#
# This script is the TestMain: it prints what did not run and names
# VAULT_E2E_BROWSER_REQUIRED, the env var that makes the skip fatal.
set -euo pipefail

url="${VAULT_URL:-https://vault.localhost}"
url="${url%/}"
required="${VAULT_E2E_BROWSER_REQUIRED:-}"

health_err=""
if ! health_err=$(curl -skf --max-time 3 "${url}/healthz" 2>&1); then
	if [ "$required" = 1 ]; then
		cat >&2 <<MSG
FAIL e2e-browser: VAULT_E2E_BROWSER_REQUIRED=1 but no vault42 answered at ${url}: ${health_err}
This suite needs a deployment, Playwright and a Chromium install. Bring one up
with scripts/deploy-dev.sh, or point VAULT_URL at an existing one. Unset
VAULT_E2E_BROWSER_REQUIRED only where a skipped run is genuinely acceptable,
which is not a release gate.
MSG
		exit 1
	fi
	cat >&2 <<MSG
SKIP e2e-browser: vault server not reachable at ${url}: ${health_err}
Nothing in this suite ran. Set VAULT_E2E_BROWSER_REQUIRED=1 to make this a failure.
Playwright and Chromium are also required; they are not a GitHub Actions default.
MSG
	exit 0
fi

cd "$(dirname "$0")"
if ! command -v npx >/dev/null 2>&1; then
	if [ "$required" = 1 ]; then
		echo "FAIL e2e-browser: VAULT_E2E_BROWSER_REQUIRED=1 but npx is not on PATH." >&2
		exit 1
	fi
	cat >&2 <<'MSG'
SKIP e2e-browser: npx is not on PATH (Playwright is not installed).
Nothing in this suite ran. Set VAULT_E2E_BROWSER_REQUIRED=1 to make this a failure.
MSG
	exit 0
fi

exec npx playwright test "$@"
