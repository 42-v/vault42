# nginx-unprivileged, not nginx. The stock image starts as root and drops to the
# nginx user for its workers, so the container runs with uid 0 present and the
# docroot writable. This variant runs entirely as uid 101 and writes its pid and
# temp paths under /tmp, which is what lets the chart set readOnlyRootFilesystem
# and runAsNonRoot without nginx failing to start.
#
# The three product images are distroless nonroot and the chart hardens the main
# Deployment; this one was the exception, and being the static asset server
# makes it the most likely thing in the chart to be handed hostile input.
#
# The listen port stays 3000 (see nginx.conf). It is above 1024, so binding it
# needs no capability, which is why the chart can drop them all.
# Digest-pinned so a tag repoint cannot swap the base image under a release.
# Resolved live from the Docker Hub registry API for THIS repository, not for
# stock nginx: Scorecard's remediation text suggests a digest for `nginx`, and
# that image starts as root. Pinning it here would break readOnlyRootFilesystem
# and runAsNonRoot in the chart, which is the whole reason this file uses
# nginx-unprivileged.
#
# The tag is the floating `alpine`, deliberately, and the digest is what makes
# the build reproducible. The previous pin was correct for its tag and still
# rotted: `1.27-alpine` is a maintenance branch whose Alpine base stopped being
# rebuilt, so the image sat at a 2025-06-23 build and accumulated 2 CRITICAL and
# 31 HIGH CVEs (measured with trivy 0.71.0), among them CVE-2026-31789 in
# OpenSSL, CVE-2026-40200 in musl and CVE-2026-22184 in zlib, the last two
# arbitrary code execution. Pinning a version branch selects the branch that
# will go stale next; `alpine` always names the freshest mainline build, and the
# digest still means no repoint can move this build.
#
# This digest, verified against the registry rather than taken on trust:
#   - `alpine`, `mainline-alpine`, `1.31-alpine` and `1.31.3-alpine` all resolve
#     to it, so the floating tag costs no precision today;
#   - it is an OCI image index carrying linux/amd64 and linux/arm64;
#   - both arch configs set User=101, which is what readOnlyRootFilesystem and
#     runAsNonRoot in charts/vault/templates/frontend.yaml depend on;
#   - labels say org.opencontainers.image.source =
#     https://github.com/nginx/docker-nginx-unprivileged and
#     org.opencontainers.image.version = 1.31.3-alpine, so it is the unprivileged
#     repository and not stock nginx;
#   - trivy reports 0 HIGH and 0 CRITICAL.
#
# `trivy-frontend-base` in .github/workflows/nightly-security.yml reads this FROM
# line, requires a digest, and fails on any HIGH or CRITICAL, so a repeat of the
# rot above is a red build rather than a quiet one. Dependabot's docker ecosystem
# raises the digest.
FROM nginxinc/nginx-unprivileged:alpine@sha256:d9083fe47768377ef55dedafd67d4da7c2f2bc2bece7554954f29359deb0dce9

COPY dist/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

USER 101
EXPOSE 3000
