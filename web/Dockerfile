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
# stock nginx: Scorecard's remediation text suggests a digest for `nginx`, whose
# 1.27-alpine digest also begins 65, and that image starts as root. Pinning it
# here would break readOnlyRootFilesystem and runAsNonRoot in the chart, which
# is the whole reason this file uses nginx-unprivileged.
#
# Verified: the digest is an OCI index carrying linux/amd64 and linux/arm64, its
# config sets User=101, and it is labelled "Unprivileged NGINX Dockerfiles".
# Dependabot's docker ecosystem keeps it current.
FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0

COPY dist/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

USER 101
EXPOSE 3000
