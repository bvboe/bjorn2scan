#!/bin/bash
set -e

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

section() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

wait_for_server() {
    local url=$1
    local max_attempts=30
    local attempt=0

    info "Waiting for server at $url..."
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            pass "Server is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    fail "Server did not start within $max_attempts seconds"
    return 1
}

cleanup() {
    info "Cleaning up..."
    pkill -f mock-server || true
    pkill -f bjorn2scan-agent || true
    rm -rf /tmp/mock-assets
    rm -rf /var/lib/bjorn2scan/data/*.db
    rm -f /tmp/bjorn2scan-update-rollback
    rm -f /var/lib/bjorn2scan/bin/bjorn2scan-agent.backup
}

# =========================================================================
# TEST 1: Successful Upgrade
# =========================================================================
test_successful_upgrade() {
    section "TEST 1: Successful Upgrade (v0.1.0 → v0.1.1)"

    # Start mock server (only v0.1.1 and v0.1.0 for successful upgrade test)
    info "Starting mock server..."
    MOCK_PORT=8080 MOCK_ASSETS_DIR=/tmp/mock-assets MOCK_RELEASES="v0.1.1,v0.1.0" mock-server > /tmp/mock-server.log 2>&1 &
    MOCK_PID=$!

    # Wait for server
    wait_for_server "http://localhost:8080/releases.atom" || return 1

    # Verify feed is accessible
    info "Checking Atom feed..."
    if curl -sf http://localhost:8080/releases.atom | grep -q "v0.1.1"; then
        pass "Atom feed contains v0.1.1"
    else
        fail "Atom feed does not contain v0.1.1"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Install initial v0.1.0 binary
    info "Installing initial v0.1.0 binary..."
    mkdir -p /tmp/initial-setup
    cd /tmp/initial-setup

    # Download and extract v0.1.0
    if ! curl -sf http://localhost:8080/download/v0.1.0/bjorn2scan-agent-linux-${ARCH}.tar.gz -o agent.tar.gz; then
        fail "Failed to download v0.1.0"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    tar -xzf agent.tar.gz
    cp bjorn2scan-agent /var/lib/bjorn2scan/bin/bjorn2scan-agent
    chmod +x /var/lib/bjorn2scan/bin/bjorn2scan-agent

    # Verify initial version
    if /var/lib/bjorn2scan/bin/bjorn2scan-agent 2>&1 | grep -q "Mock agent v0.1.0"; then
        pass "Initial v0.1.0 binary installed"
    else
        fail "Initial binary not installed correctly"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Run update check (this will install and exit)
    info "Running update check..."
    if test-driver "http://localhost:8080/releases.atom" "http://localhost:8080/download" "0.1.0" > /tmp/update.log 2>&1; then
        pass "Update installed (process exited for restart)"
    else
        fail "Update installation failed"
        cat /tmp/update.log
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Verify binary was upgraded
    info "Verifying binary was upgraded..."
    if /var/lib/bjorn2scan/bin/bjorn2scan-agent 2>&1 | grep -q "Mock agent v0.1.1"; then
        pass "Binary upgraded to v0.1.1"
    else
        fail "Binary was not upgraded"
        /var/lib/bjorn2scan/bin/bjorn2scan-agent 2>&1 || true
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Verify rollback marker exists
    if [ -f /tmp/bjorn2scan-update-rollback ]; then
        pass "Rollback marker created"
    else
        fail "Rollback marker not found"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Start a mock health endpoint (simulates the new agent providing health status)
    info "Starting mock health endpoint..."
    # Create a simple Python HTTP server that responds to /health
    cat > /tmp/health_server.py <<'EOF'
import http.server
import socketserver

class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logging

with socketserver.TCPServer(("", 9999), HealthHandler) as httpd:
    httpd.serve_forever()
EOF
    python3 /tmp/health_server.py > /dev/null 2>&1 &
    HEALTH_PID=$!
    sleep 2  # Give server a moment to start

    # Run health check (simulates restart)
    info "Running post-update health check..."
    if health-check > /tmp/health-check.log 2>&1; then
        pass "Health check passed and update committed"
    else
        fail "Health check failed"
        cat /tmp/health-check.log
        kill $HEALTH_PID 2>/dev/null || true
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Stop health endpoint
    kill $HEALTH_PID 2>/dev/null || true

    # Verify backup was cleaned up
    if [ ! -f /var/lib/bjorn2scan/bin/bjorn2scan-agent.backup ]; then
        pass "Backup file cleaned up"
    else
        fail "Backup file still exists"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Verify rollback marker was cleaned up
    if [ ! -f /tmp/bjorn2scan-update-rollback ]; then
        pass "Rollback marker cleaned up"
    else
        fail "Rollback marker still exists"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Cleanup
    kill $MOCK_PID 2>/dev/null || true
}

# =========================================================================
# TEST 2: Failed Health Check (Rollback)
# =========================================================================
test_failed_health_check() {
    section "TEST 2: Failed Health Check Rollback (v0.1.0 → v0.1.2)"

    # Start mock server (include v0.1.2 which will fail health check)
    info "Starting mock server..."
    MOCK_PORT=8080 MOCK_ASSETS_DIR=/tmp/mock-assets MOCK_RELEASES="v0.1.2,v0.1.1,v0.1.0" mock-server > /tmp/mock-server.log 2>&1 &
    MOCK_PID=$!

    # Wait for server
    wait_for_server "http://localhost:8080/releases.atom" || return 1

    # Verify feed contains failing version
    info "Checking Atom feed for v0.1.2..."
    if curl -sf http://localhost:8080/releases.atom | grep -q "v0.1.2"; then
        pass "Atom feed contains v0.1.2 (failing version)"
    else
        fail "Atom feed does not contain v0.1.2"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Install initial v0.1.0 binary
    info "Installing initial v0.1.0 binary..."
    mkdir -p /tmp/rollback-test
    cd /tmp/rollback-test

    # Download and extract v0.1.0
    if ! curl -sf http://localhost:8080/download/v0.1.0/bjorn2scan-agent-linux-${ARCH}.tar.gz -o agent.tar.gz; then
        fail "Failed to download v0.1.0"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    tar -xzf agent.tar.gz
    cp bjorn2scan-agent /var/lib/bjorn2scan/bin/bjorn2scan-agent
    chmod +x /var/lib/bjorn2scan/bin/bjorn2scan-agent

    # Verify initial version
    if /var/lib/bjorn2scan/bin/bjorn2scan-agent 2>&1 | grep -q "Mock agent v0.1.0"; then
        pass "Initial v0.1.0 binary installed"
    else
        fail "Initial binary not installed correctly"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Run update check (will install v0.1.2 which has failing health check)
    info "Running update check (will install v0.1.2)..."
    if test-driver "http://localhost:8080/releases.atom" "http://localhost:8080/download" "0.1.0" > /tmp/update-rollback.log 2>&1; then
        pass "Update to v0.1.2 installed"
    else
        fail "Update installation failed"
        cat /tmp/update-rollback.log
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Verify binary was upgraded to v0.1.2
    info "Verifying binary was upgraded to v0.1.2..."
    if /var/lib/bjorn2scan/bin/bjorn2scan-agent 2>&1 | grep -q "Mock agent v0.1.2"; then
        pass "Binary upgraded to v0.1.2"
    else
        fail "Binary was not upgraded"
        /var/lib/bjorn2scan/bin/bjorn2scan-agent 2>&1 || true
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Verify backup exists
    if [ -f /var/lib/bjorn2scan/bin/bjorn2scan-agent.backup ]; then
        pass "Backup file created"
    else
        fail "Backup file not found"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Run health check (should fail and trigger rollback)
    # Note: We do NOT start a health endpoint, so the health check will timeout and fail
    info "Running post-update health check (expected to fail)..."
    if health-check > /tmp/health-check-rollback.log 2>&1; then
        fail "Health check should have failed (but it passed)"
        cat /tmp/health-check-rollback.log
        kill $MOCK_PID 2>/dev/null || true
        return 1
    else
        pass "Health check failed and rollback initiated"
    fi

    # Verify binary was rolled back to v0.1.0
    info "Verifying rollback to v0.1.0..."
    if /var/lib/bjorn2scan/bin/bjorn2scan-agent 2>&1 | grep -q "Mock agent v0.1.0"; then
        pass "Binary rolled back to v0.1.0"
    else
        fail "Binary was not rolled back"
        /var/lib/bjorn2scan/bin/bjorn2scan-agent 2>&1 || true
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Verify rollback marker was removed
    if [ ! -f /tmp/bjorn2scan-update-rollback ]; then
        pass "Rollback marker cleaned up"
    else
        fail "Rollback marker still exists"
        kill $MOCK_PID 2>/dev/null || true
        return 1
    fi

    # Cleanup
    kill $MOCK_PID 2>/dev/null || true
}

# =========================================================================
# Main Test Execution
# =========================================================================

echo ""
info "Starting integration tests..."
info "Test environment: Docker container"
echo ""

# Cleanup before tests
cleanup

# Run tests
test_successful_upgrade
cleanup

test_failed_health_check
cleanup

# Summary
section "Test Summary"
echo ""
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
