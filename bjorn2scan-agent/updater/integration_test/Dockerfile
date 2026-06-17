FROM cgr.dev/chainguard/go:latest-dev AS builder

# Set working directory
WORKDIR /build

# Copy all source code (needed for replace directives in go.mod)
COPY . .

# Download dependencies from bjorn2scan-agent directory
WORKDIR /build/bjorn2scan-agent
RUN go mod download

# Build mock server (static binary)
RUN cd updater/integration_test && CGO_ENABLED=0 go build -tags integration -o /mock-server mock-server.go

# Build test driver (static binary)
RUN cd updater/integration_test && CGO_ENABLED=0 go build -tags integration -o /test-driver test-driver.go

# Build health check helper (static binary)
RUN cd updater/integration_test && CGO_ENABLED=0 go build -tags integration -o /health-check health-check.go

# Build test agent (static binary)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bjorn2scan-agent-test

FROM cgr.dev/chainguard/wolfi-base:latest

# Install runtime dependencies
# Wolfi-base includes busybox (with tar) and basic tools
# Add bash, curl, and python for the tests
RUN apk update && apk add --no-cache bash curl python3

# Copy binaries
COPY --from=builder /mock-server /usr/local/bin/mock-server
COPY --from=builder /test-driver /usr/local/bin/test-driver
COPY --from=builder /health-check /usr/local/bin/health-check
COPY --from=builder /bjorn2scan-agent-test /usr/local/bin/bjorn2scan-agent

# Create required directories
RUN mkdir -p /var/lib/bjorn2scan/bin \
             /var/lib/bjorn2scan/data \
             /var/lib/bjorn2scan/cache \
             /var/log/bjorn2scan \
             /etc/bjorn2scan

# Set working directory
WORKDIR /test

# Copy test scripts
COPY bjorn2scan-agent/updater/integration_test/test-scenarios.sh /test/test-scenarios.sh
RUN chmod +x /test/test-scenarios.sh

# Default command runs tests
CMD ["/bin/bash"]
