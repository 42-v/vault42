# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

# Frontend build stage: compile Vue SPA on the native build host. Output is static
# JS/HTML so target arch is irrelevant — pinning $BUILDPLATFORM avoids running Node
# under QEMU, which segfaults corepack/pnpm on arm64.
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS frontend
WORKDIR /build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/vue/package.json packages/vue/
COPY web/package.json web/
# corepack is no longer bundled with the node image; Node stopped shipping it
# before 26, so `corepack enable` is "not found" rather than a no-op and the
# whole frontend stage fails at exit 127.
#
# It is fetched by digest rather than by name. `npm install -g corepack@0.35.0`
# names a version and then trusts whatever the registry serves for it, which is
# the finding Scorecard raised against the first version of this line: a version
# is not a pin. The tarball is verified against a SHA-256 taken from a download
# whose SHA-512 matched the integrity npm publishes for 0.35.0, so a substituted
# artifact fails the check rather than executing in a release build.
#
# corepack is worth this because of what it does next: it reads `packageManager`
# from package.json, which pins pnpm by version AND by SHA-512, so the package
# manager that builds a release image is itself hash-verified.
ARG COREPACK_VERSION=0.35.0
ARG COREPACK_SHA256=f62535fc7be1f77e4b12cd1e420b8542b8e895cbb14178926963a41a9232a4fe
#
# The checksum goes to a file rather than through a pipe into `sha256sum -c -`.
# The pipe was safe -- echo cannot fail and sha256sum was last, so its status was
# the pipeline's -- but hadolint's DL4006 cannot know that, and the fix it asks
# for is to change SHELL for the whole stage. Not building a pipe is the smaller
# change and leaves nothing to reason about.
RUN set -eu; \
    wget -qO /tmp/corepack.tgz \
      "https://registry.npmjs.org/corepack/-/corepack-${COREPACK_VERSION}.tgz"; \
    printf '%s  /tmp/corepack.tgz\n' "${COREPACK_SHA256}" > /tmp/corepack.sha256; \
    sha256sum -c /tmp/corepack.sha256; \
    npm install -g /tmp/corepack.tgz; \
    rm /tmp/corepack.tgz /tmp/corepack.sha256; \
    corepack enable; \
    pnpm install --frozen-lockfile
COPY packages/vue/ packages/vue/
COPY web/ web/
RUN pnpm --filter @vault42/vue build && pnpm --filter @vault42/web build

# Go build stage: runs on native (amd64) host, cross-compiles for target arch.
# Go cross-compiles natively — no QEMU emulation needed, ~10x faster for ARM64.
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    go mod download
COPY . .
# Copy built frontend assets into go:embed location
COPY --from=frontend /build/web/dist internal/frontend/dist/
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    --mount=type=cache,id=gobuild-${TARGETARCH},target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    -o /vault ./cmd/vault

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
WORKDIR /app
COPY --from=builder /vault /app/vault
COPY migrations /app/migrations
# 65532:65532 is `nonroot` in the distroless base. Numeric so that a
# runtime with no /etc/passwd lookup -- and Kubernetes runAsNonRoot --
# can resolve it; charts/vault/values.yaml pins the same numbers.
USER 65532:65532
ENTRYPOINT ["/app/vault"]
