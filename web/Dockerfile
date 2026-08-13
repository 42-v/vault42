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
FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY dist/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

USER 101
EXPOSE 3000
