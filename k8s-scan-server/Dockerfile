# Build stage
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest AS builder

ARG TARGETARCH
ARG VERSION=dev

WORKDIR /workspace

# Copy go.mod and go.sum files first for better layer caching
# This layer will only be invalidated when dependencies change
COPY scanner-core/go.mod scanner-core/go.sum ./scanner-core/
COPY k8s-scan-server/go.mod k8s-scan-server/go.sum* ./k8s-scan-server/

# Download dependencies (cached unless go.mod/go.sum changes)
# Note: uid=65532 is the nonroot user in Chainguard images
WORKDIR /workspace/scanner-core
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    go mod download

WORKDIR /workspace/k8s-scan-server
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    go mod download

# Now copy source code (after dependency layers are cached)
WORKDIR /workspace
COPY scanner-core/ ./scanner-core/

WORKDIR /workspace/k8s-scan-server
COPY k8s-scan-server/main.go ./
COPY k8s-scan-server/k8s/ ./k8s/
COPY k8s-scan-server/podscanner/ ./podscanner/

# Build the binary
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    --mount=type=cache,target=/home/nonroot/.cache/go-build,uid=65532,gid=65532 \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-X main.version=${VERSION} -w -s" -o k8s-scan-server .

# Runtime stage
FROM cgr.dev/chainguard/static:latest
#FROM cgr.dev/chainguard/wolfi-base:latest

COPY --from=builder /workspace/k8s-scan-server/k8s-scan-server /k8s-scan-server

EXPOSE 8080

ENTRYPOINT ["/k8s-scan-server"]
