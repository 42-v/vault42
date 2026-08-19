# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

# Frontend build stage: compile Vue SPA on the native build host. Output is static
# JS/HTML so target arch is irrelevant — pinning $BUILDPLATFORM avoids running Node
# under QEMU, which segfaults corepack/pnpm on arm64.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:ab07539e0988b63558ff621f5fbe1077054c39d9809112974fb79993949d41cd AS frontend
WORKDIR /build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/vue/package.json packages/vue/
COPY web/package.json web/
RUN corepack enable && pnpm install --frozen-lockfile
COPY packages/vue/ packages/vue/
COPY web/ web/
RUN pnpm --filter @vault42/vue build && pnpm --filter @vault42/web build

# Go build stage: runs on native (amd64) host, cross-compiles for target arch.
# Go cross-compiles natively — no QEMU emulation needed, ~10x faster for ARM64.
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS builder

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
