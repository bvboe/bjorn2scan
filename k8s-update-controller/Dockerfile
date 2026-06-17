# Build stage
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest AS builder

WORKDIR /build

# Copy go mod files from subdirectory (context is root)
COPY k8s-update-controller/go.mod k8s-update-controller/go.sum ./
# Note: uid=65532 is the nonroot user in Chainguard images
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    go mod download

# Copy source code from subdirectory
COPY k8s-update-controller/ .

# Build the binary
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    --mount=type=cache,target=/home/nonroot/.cache/go-build,uid=65532,gid=65532 \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.version=${VERSION}" \
    -o k8s-update-controller \
    .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

# Copy the binary from builder
COPY --from=builder /build/k8s-update-controller /usr/local/bin/k8s-update-controller

# Run as non-root (UID 65532 is 'nonroot' user in Chainguard images)
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/k8s-update-controller"]
