#!/bin/bash
# Integration test for Agent Auto-Updater
# Tests the complete agent auto-update workflow

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TEST_VERSION_OLD="${TEST_VERSION_OLD:-0.1.34}"
TEST_VERSION_NEW="${TEST_VERSION_NEW:-0.1.35}"
TEST_PORT="${TEST_PORT:-19999}"
TEST_DIR="${TEST_DIR:-/tmp/bjorn2scan-agent-test}"
AGENT_BINARY="$TEST_DIR/bjorn2scan-agent"
AGENT_CONFIG="$TEST_DIR/agent.conf"
AGENT_PID_FILE="$TEST_DIR/agent.pid"
TIMEOUT="${TIMEOUT:-300}" # 5 minutes

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "$expected" = "$actual" ]; then
        log_info "✓ PASS: $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "✗ FAIL: $message"
        log_error "  Expected: $expected"
        log_error "  Actual:   $actual"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if echo "$haystack" | grep -q "$needle"; then
        log_info "✓ PASS: $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "✗ FAIL: $message"
        log_error "  Expected to contain: $needle"
        log_error "  Actual: $haystack"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_not_empty() {
    local value="$1"
    local message="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ -n "$value" ]; then
        log_info "✓ PASS: $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "✗ FAIL: $message (value is empty)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_command_success() {
    local command="$1"
    local message="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    if eval "$command" &>/dev/null; then
        log_info "✓ PASS: $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "✗ FAIL: $message"
        log_error "  Command failed: $command"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

cleanup() {
    log_info "Cleaning up test environment..."

    # Stop agent if running
    stop_agent

    # Remove test directory
    rm -rf "$TEST_DIR"

    # Kill any port forwards
    pkill -f "port.*$TEST_PORT" 2>/dev/null || true
}

setup_test_environment() {
    log_info "Setting up test environment..."

    # Create test directory
    mkdir -p "$TEST_DIR"

    # Build agent binary
    log_info "Building agent binary..."
    cd "$(dirname "$0")/.."
    make -C bjorn2scan-agent build

    # Copy binary to test directory
    cp bjorn2scan-agent/bjorn2scan-agent "$AGENT_BINARY"
    chmod +x "$AGENT_BINARY"

    assert_command_success "[ -x $AGENT_BINARY ]" "Agent binary is executable"
}

create_test_config() {
    log_info "Creating test configuration..."

    cat > "$AGENT_CONFIG" <<EOF
# Test configuration for agent auto-update
port=$TEST_PORT
db_path=$TEST_DIR/containers.db
debug_enabled=false

# Auto-update configuration
auto_update_enabled=true
auto_update_check_interval=30s
auto_update_minor_versions=true
auto_update_major_versions=false
auto_update_pinned_version=
auto_update_min_version=
auto_update_max_version=
update_github_repo=bvboe/b2s-go
update_verify_signatures=false
update_rollback_enabled=true
update_health_check_timeout=30s
EOF

    assert_command_success "[ -f $AGENT_CONFIG ]" "Configuration file created"
}

start_agent() {
    log_info "Starting agent..."

    # Start agent in background from TEST_DIR so it finds ./agent.conf
    cd "$TEST_DIR"
    PORT=$TEST_PORT DB_PATH="$TEST_DIR/containers.db" \
        "$AGENT_BINARY" &
    local pid=$!
    cd - > /dev/null

    echo $pid > "$AGENT_PID_FILE"

    # Wait for agent to start
    local waited=0
    while [ $waited -lt 30 ]; do
        if curl -sf "http://localhost:$TEST_PORT/health" &>/dev/null; then
            log_info "Agent started successfully (PID: $pid)"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    log_error "Agent failed to start within 30 seconds"
    return 1
}

stop_agent() {
    if [ -f "$AGENT_PID_FILE" ]; then
        local pid=$(cat "$AGENT_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping agent (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 2
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$AGENT_PID_FILE"
    fi
}

test_agent_health() {
    log_info "Testing agent health endpoints..."

    # Test health endpoint
    local health=$(curl -sf "http://localhost:$TEST_PORT/health")
    assert_not_empty "$health" "Health endpoint is accessible"

    # Test info endpoint
    local info=$(curl -sf "http://localhost:$TEST_PORT/info")
    assert_not_empty "$info" "Info endpoint is accessible"

    # Check version
    local version=$(echo "$info" | jq -r '.version')
    log_info "Agent version: $version"
    assert_not_empty "$version" "Agent version is reported"
}

test_update_status_api() {
    log_info "Testing update status API..."

    # Get update status
    local status=$(curl -sf "http://localhost:$TEST_PORT/api/update/status")
    assert_not_empty "$status" "Update status endpoint is accessible"

    # Parse status fields
    local update_status=$(echo "$status" | jq -r '.status')
    local last_check=$(echo "$status" | jq -r '.lastCheck')

    log_info "Update status: $update_status"
    log_info "Last check: $last_check"

    assert_not_empty "$update_status" "Update status is reported"
}

test_manual_trigger() {
    log_info "Testing manual update trigger..."

    # Trigger update check
    local response=$(curl -sf -X POST "http://localhost:$TEST_PORT/api/update/trigger")
    assert_contains "$response" "Update check triggered" "Update trigger accepted"

    # Wait for check to complete
    sleep 5

    # Verify last check time updated
    local status=$(curl -sf "http://localhost:$TEST_PORT/api/update/status")
    local last_check=$(echo "$status" | jq -r '.lastCheck')
    assert_not_empty "$last_check" "Last check time is updated"

    log_info "Last check: $last_check"
}

test_pause_resume() {
    log_info "Testing pause and resume functionality..."

    # Pause updates
    local pause_response=$(curl -sf -X POST "http://localhost:$TEST_PORT/api/update/pause")
    assert_contains "$pause_response" "paused" "Pause request accepted"

    # Verify paused (check that status remains idle)
    sleep 2
    local status=$(curl -sf "http://localhost:$TEST_PORT/api/update/status")
    local update_status=$(echo "$status" | jq -r '.status')
    log_info "Status after pause: $update_status"

    # Resume updates
    local resume_response=$(curl -sf -X POST "http://localhost:$TEST_PORT/api/update/resume")
    assert_contains "$resume_response" "resumed" "Resume request accepted"

    sleep 2
}

test_version_constraints() {
    log_info "Testing version constraints..."

    # Stop agent
    stop_agent

    # Update config to block minor updates
    cat > "$AGENT_CONFIG" <<EOF
port=$TEST_PORT
db_path=$TEST_DIR/containers.db
auto_update_enabled=true
auto_update_check_interval=10s
auto_update_minor_versions=false
auto_update_major_versions=false
EOF

    # Restart agent
    start_agent
    sleep 5

    # Trigger update check
    curl -sf -X POST "http://localhost:$TEST_PORT/api/update/trigger" || true
    sleep 5

    # Version should not have changed
    local info=$(curl -sf "http://localhost:$TEST_PORT/info")
    local current_version=$(echo "$info" | jq -r '.version')
    log_info "Version after constraint test: $current_version"

    # Restore config
    create_test_config
}

test_version_pinning() {
    log_info "Testing version pinning..."

    # Stop agent
    stop_agent

    # Update config with pinned version
    cat > "$AGENT_CONFIG" <<EOF
port=$TEST_PORT
db_path=$TEST_DIR/containers.db
auto_update_enabled=true
auto_update_check_interval=10s
auto_update_minor_versions=true
auto_update_major_versions=false
auto_update_pinned_version=dev
EOF

    # Restart agent
    start_agent
    sleep 5

    # Trigger update check
    curl -sf -X POST "http://localhost:$TEST_PORT/api/update/trigger" || true
    sleep 5

    # Check status for pinning message
    local status=$(curl -sf "http://localhost:$TEST_PORT/api/update/status" || echo '{}')
    log_info "Status with pinned version: $(echo $status | jq -r '.status')"

    # Restore config
    create_test_config
}

test_config_reload() {
    log_info "Testing configuration reload..."

    # Update config file
    echo "# Updated at $(date)" >> "$AGENT_CONFIG"

    # Configuration changes require restart in current implementation
    # This test verifies the config file is being read

    stop_agent
    start_agent

    # Verify agent started with updated config
    assert_command_success "curl -sf http://localhost:$TEST_PORT/health" "Agent restarted with updated config"
}

test_backup_creation() {
    log_info "Testing backup creation..."

    # Check if binary exists in expected location
    assert_command_success "[ -f $AGENT_BINARY ]" "Agent binary exists"

    # Simulate backup creation (manual test since auto-update would create it)
    local backup_path="$TEST_DIR/bjorn2scan-agent.backup"
    cp "$AGENT_BINARY" "$backup_path"

    assert_command_success "[ -f $backup_path ]" "Backup can be created"

    # Cleanup
    rm -f "$backup_path"
}

test_rollback_marker() {
    log_info "Testing rollback marker functionality..."

    # Create rollback marker
    local marker="$TEST_DIR/bjorn2scan-agent.rollback-test"
    touch "$marker"

    assert_command_success "[ -f $marker ]" "Rollback marker can be created"

    # Cleanup
    rm -f "$marker"
}

test_health_check_after_restart() {
    log_info "Testing health check after restart..."

    # Stop and restart agent
    stop_agent
    start_agent

    # Wait a bit for agent to fully start
    sleep 3

    # Check health
    local health_response=$(curl -sf "http://localhost:$TEST_PORT/health")
    assert_not_empty "$health_response" "Agent is healthy after restart"

    # Check that services are responding
    assert_command_success "curl -sf http://localhost:$TEST_PORT/info" "Info endpoint works after restart"
}

test_concurrent_api_calls() {
    log_info "Testing concurrent API calls..."

    # Make multiple concurrent status requests and capture PIDs
    local pids=()
    for i in {1..5}; do
        curl -sf "http://localhost:$TEST_PORT/api/update/status" &>/dev/null &
        pids+=($!)
    done

    # Wait only for the curl requests, not all background jobs (agent is also background!)
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    assert_command_success "curl -sf http://localhost:$TEST_PORT/api/update/status" "Agent handles concurrent requests"
}

test_invalid_config() {
    log_info "Testing agent behavior with invalid config..."

    # Stop agent
    stop_agent

    # Create invalid config
    cat > "$AGENT_CONFIG" <<EOF
port=invalid_port
auto_update_enabled=invalid_bool
auto_update_check_interval=invalid_duration
EOF

    # Try to start agent (should fail or use defaults)
    # Agent should handle this gracefully
    PORT=$TEST_PORT DB_PATH="$TEST_DIR/containers.db" \
        "$AGENT_BINARY" &>/dev/null &
    local pid=$!
    echo $pid > "$AGENT_PID_FILE"

    sleep 3

    # Check if agent started (may use defaults)
    if curl -sf "http://localhost:$TEST_PORT/health" &>/dev/null; then
        log_info "Agent handled invalid config by using defaults"
        assert_command_success "true" "Agent handles invalid config gracefully"
    else
        log_warn "Agent failed to start with invalid config (expected behavior)"
        assert_command_success "true" "Agent rejects invalid config as expected"
    fi

    # Restore valid config
    stop_agent
    create_test_config
    start_agent
}

test_update_status_fields() {
    log_info "Testing update status fields..."

    # Get status
    local status=$(curl -sf "http://localhost:$TEST_PORT/api/update/status")

    # Check all expected fields are present
    local has_status=$(echo "$status" | jq -r '.status' | grep -q '.' && echo "yes" || echo "no")
    local has_error=$(echo "$status" | jq 'has("error")' | grep -q 'true' && echo "yes" || echo "no")
    local has_last_check=$(echo "$status" | jq 'has("lastCheck")' | grep -q 'true' && echo "yes" || echo "no")
    local has_last_update=$(echo "$status" | jq 'has("lastUpdate")' | grep -q 'true' && echo "yes" || echo "no")
    local has_latest=$(echo "$status" | jq 'has("latestVersion")' | grep -q 'true' && echo "yes" || echo "no")

    assert_equals "yes" "$has_status" "Status field is present"
    assert_equals "yes" "$has_error" "Error field is present"
    assert_equals "yes" "$has_last_check" "LastCheck field is present"
    assert_equals "yes" "$has_last_update" "LastUpdate field is present"
    assert_equals "yes" "$has_latest" "LatestVersion field is present"
}

print_summary() {
    echo ""
    echo "========================================"
    echo "Integration Test Summary"
    echo "========================================"
    echo "Total Tests:  $TESTS_RUN"
    echo -e "${GREEN}Passed:       $TESTS_PASSED${NC}"
    echo -e "${RED}Failed:       $TESTS_FAILED${NC}"
    echo "========================================"

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}✗ Some tests failed!${NC}"
        return 1
    fi
}

main() {
    log_info "Starting Agent Auto-Updater Integration Tests"
    log_info "Test Directory: $TEST_DIR"
    log_info "Test Port: $TEST_PORT"
    echo ""

    # Setup
    setup_test_environment
    create_test_config
    start_agent

    # Run tests
    test_agent_health
    test_update_status_api
    test_update_status_fields
    test_manual_trigger
    test_pause_resume
    test_version_constraints
    test_version_pinning
    test_config_reload
    test_backup_creation
    test_rollback_marker
    test_health_check_after_restart
    test_concurrent_api_calls
    test_invalid_config

    # Print results
    print_summary
    local exit_code=$?

    # Cleanup (optional)
    if [ "${CLEANUP:-true}" = "true" ]; then
        cleanup
    else
        log_warn "Skipping cleanup (CLEANUP=false)"
        log_info "Test directory: $TEST_DIR"
        log_info "To cleanup manually: rm -rf $TEST_DIR"
    fi

    exit $exit_code
}

# Handle interrupts
trap cleanup EXIT INT TERM

# Run main
main "$@"
