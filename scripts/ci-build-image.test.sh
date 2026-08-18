#!/usr/bin/env bash
# Tests for ci-build-image.sh. Uses a stub docker that reads its scripted
# behavior from a file, so no daemon or network is involved.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
subject="$here/ci-build-image.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/docker" <<'STUB'
#!/usr/bin/env bash
n=$(cat "$STUB_COUNT")
echo $((n + 1)) >"$STUB_COUNT"
line=$(sed -n "$((n + 1))p" "$STUB_SCRIPT")
printf '%s\n' "${line#*:}"
[ "${line%%:*}" = ok ] && exit 0
exit 1
STUB
chmod +x "$work/docker"

export DOCKER="$work/docker"
export STUB_COUNT="$work/count"
export STUB_SCRIPT="$work/script"
export CI_BUILD_RETRY_DELAY=0

failures=0
run_case() {
	local name=$1 want_status=$2 want_calls=$3
	shift 3
	printf '%s\n' "$@" >"$STUB_SCRIPT"
	echo 0 >"$STUB_COUNT"

	set +e
	"$subject" img:test Dockerfile . >/dev/null 2>&1
	local got_status=$?
	set -e
	local got_calls
	got_calls=$(cat "$STUB_COUNT")

	if [ "$got_status" = "$want_status" ] && [ "$got_calls" = "$want_calls" ]; then
		echo "ok   - $name"
	else
		echo "FAIL - $name: status $got_status (want $want_status), calls $got_calls (want $want_calls)"
		failures=$((failures + 1))
	fi
}

run_case "transient registry error is retried until it succeeds" 0 2 \
	'fail:ERROR: failed to solve: DeadlineExceeded: failed to do request: Head "https://registry-1.docker.io/v2/": dial tcp: i/o timeout' \
	'ok:done'

run_case "a broken build fails on the first attempt" 1 1 \
	'fail:ERROR: failed to solve: process "/bin/sh -c go build ./..." did not complete successfully: exit code: 2'

run_case "a permanently unreachable registry gives up after the attempt budget" 1 3 \
	'fail:i/o timeout' 'fail:i/o timeout' 'fail:i/o timeout' 'ok:unreachable'

[ "$failures" -eq 0 ] || exit 1
echo "all ci-build-image tests passed"
