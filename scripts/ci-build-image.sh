#!/usr/bin/env bash
# Build a container image for CI scanning.
#
# Registry reads (the BuildKit syntax frontend, base image manifests) go out to
# Docker Hub on every cold runner, and those reads time out often enough that an
# unguarded `docker build` turns the nightly scan red for reasons that have
# nothing to do with the code. Retry those, and only those: a genuine build
# error still fails on the first attempt so the signal stays honest.
set -euo pipefail

usage() {
	cat >&2 <<'EOF'
usage: ci-build-image.sh <tag> <dockerfile> [context]

env:
  CI_BUILD_ATTEMPTS      total attempts on transient registry errors (default 3)
  CI_BUILD_RETRY_DELAY   seconds before the first retry, doubled each time (default 15)
  DOCKER                 docker binary to invoke (default docker)
EOF
	exit 2
}

[ $# -ge 2 ] || usage

tag=$1
dockerfile=$2
context=${3:-.}
attempts=${CI_BUILD_ATTEMPTS:-3}
delay=${CI_BUILD_RETRY_DELAY:-15}
docker_bin=${DOCKER:-docker}

# Substrings that mean "the registry was unreachable", not "the build is broken".
transient_re='i/o timeout|TLS handshake timeout|DeadlineExceeded|failed to do request|toomanyrequests|429 Too Many Requests|503 Service Unavailable|connection reset by peer|temporary failure in name resolution|unexpected EOF|net/http: request canceled'

log() { printf '%s\n' "$*" >&2; }

attempt=1
while :; do
	log "==> building ${tag} from ${dockerfile} (attempt ${attempt}/${attempts})"

	set +e
	output=$("$docker_bin" build -t "$tag" -f "$dockerfile" "$context" 2>&1)
	status=$?
	set -e

	printf '%s\n' "$output"
	[ $status -eq 0 ] && exit 0

	if ! printf '%s' "$output" | grep -qE "$transient_re"; then
		log "==> build failed with a non-transient error, not retrying"
		exit $status
	fi

	if [ "$attempt" -ge "$attempts" ]; then
		log "==> registry still unreachable after ${attempts} attempts"
		exit $status
	fi

	log "==> transient registry error, retrying in ${delay}s"
	sleep "$delay"
	attempt=$((attempt + 1))
	delay=$((delay * 2))
done
