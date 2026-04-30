# syntax=docker/dockerfile:1

# Frontend build stage: compile Vue SPA on the native build host. Output is static
# JS/HTML so target arch is irrelevant — pinning $BUILDPLATFORM avoids running Node
# under QEMU, which segfaults corepack/pnpm on arm64.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:cb15fca92530d7ac113467696cf1001208dac49c3c64355fd1348c11a88ddf8f AS frontend
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
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:80fbb8f9b2fa541a7d34378f1ad10f4f1c433817c4ed39ddb3e2f3ec3e961271 AS builder

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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:5074667eecabac8ac5c5d395100a153a7b4e8426181cca36181cd019530f00c8
WORKDIR /app
COPY --from=builder /vault /app/vault
COPY migrations /app/migrations
USER nonroot:nonroot
ENTRYPOINT ["/app/vault"]
