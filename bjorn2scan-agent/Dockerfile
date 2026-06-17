# Build stage
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest AS builder

ARG TARGETARCH
ARG VERSION=dev

WORKDIR /workspace

# Copy go.mod and go.sum files first for better layer caching
# This layer will only be invalidated when dependencies change
COPY scanner-core/go.mod scanner-core/go.sum ./scanner-core/
COPY bjorn2scan-agent/go.mod bjorn2scan-agent/go.sum* ./bjorn2scan-agent/

# Download dependencies (cached unless go.mod/go.sum changes)
# Note: uid=65532 is the nonroot user in Chainguard images
WORKDIR /workspace/scanner-core
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    go mod download

WORKDIR /workspace/bjorn2scan-agent
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    go mod download

# Now copy source code (after dependency layers are cached)
WORKDIR /workspace
COPY scanner-core/ ./scanner-core/

WORKDIR /workspace/bjorn2scan-agent
COPY bjorn2scan-agent/main.go ./
COPY bjorn2scan-agent/docker/ ./docker/
COPY bjorn2scan-agent/syft/ ./syft/
COPY bjorn2scan-agent/updater/ ./updater/

# Build the binary
RUN --mount=type=cache,target=/go/pkg/mod,uid=65532,gid=65532 \
    --mount=type=cache,target=/home/nonroot/.cache/go-build,uid=65532,gid=65532 \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-X main.version=${VERSION} -w -s" -o bjorn2scan-agent .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /workspace/bjorn2scan-agent/bjorn2scan-agent /bjorn2scan-agent

EXPOSE 9999

ENTRYPOINT ["/bjorn2scan-agent"]
