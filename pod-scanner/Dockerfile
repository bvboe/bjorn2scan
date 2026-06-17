# Build stage
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest AS builder

ARG TARGETARCH
ARG VERSION=dev

WORKDIR /workspace/pod-scanner

# Copy sbom-generator-shared module (needed for build due to replace directive)
COPY sbom-generator-shared/ ../sbom-generator-shared/

# Copy go.mod and go.sum files first for better layer caching
# This layer will only be invalidated when dependencies change
COPY pod-scanner/go.mod pod-scanner/go.sum* ./

# Download dependencies (cached unless go.mod/go.sum changes)
# Note: uid=65532 is the nonroot user in Chainguard images
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    go mod download

# Now copy source code (after dependency layers are cached)
COPY pod-scanner/main.go ./
COPY pod-scanner/runtime/ ./runtime/
COPY pod-scanner/handlers/ ./handlers/

# Build the binary
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    --mount=type=cache,target=/home/nonroot/.cache/go-build,uid=65532,gid=65532 \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-X main.version=${VERSION} -w -s" -o pod-scanner .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /workspace/pod-scanner/pod-scanner /pod-scanner

EXPOSE 8081

ENTRYPOINT ["/pod-scanner"]
