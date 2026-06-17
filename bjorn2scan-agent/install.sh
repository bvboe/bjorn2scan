#!/bin/sh
set -e

# Ensure standard system paths are available
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
export PATH

# Version - injected during release build (or set to "latest" for development)
VERSION="__VERSION__"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Constants
BINARY_NAME="bjorn2scan-agent"
SERVICE_NAME="bjorn2scan-agent.service"
INSTALL_DIR="/var/lib/bjorn2scan/bin"
SERVICE_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/bjorn2scan"
CONFIG_FILE="${CONFIG_DIR}/agent.conf"
CONFIG_EXAMPLE="${CONFIG_DIR}/agent.conf.example"
USER_NAME="bjorn2scan"
GROUP_NAME="bjorn2scan"
GITHUB_REPO="bvboe/b2s-go"

# Helper functions
log_info() { printf "${BLUE}[INFO]${NC} %s\n" "$1" >&2; }
log_success() { printf "${GREEN}[SUCCESS]${NC} %s\n" "$1" >&2; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }
log_warning() { printf "${YELLOW}[WARNING]${NC} %s\n" "$1" >&2; }

# Show help
show_help() {
    cat << EOF
bjorn2scan-agent installer

DESCRIPTION:
    Installs bjorn2scan-agent, a lightweight host-level security scanning agent
    for the Bjorn2Scan v2 platform.

USAGE:
    # Install latest version
    curl -sSfL https://github.com/${GITHUB_REPO}/releases/latest/download/install.sh | sudo sh

    # Install specific version
    curl -sSfL https://github.com/${GITHUB_REPO}/releases/download/v0.1.54/install.sh | sudo sh

    # Install from local binary (for testing)
    LOCAL_BINARY_PATH=/path/to/bjorn2scan-agent-linux-amd64.tar.gz sudo -E sh install.sh

    # Uninstall
    curl -sSfL https://github.com/${GITHUB_REPO}/releases/latest/download/install.sh | sudo sh -s uninstall

    # Show help (download first)
    curl -sSfL https://github.com/${GITHUB_REPO}/releases/latest/download/install.sh -o install.sh
    sh install.sh --help

WHAT IT DOES:
    - Detects your OS and architecture (Linux amd64/arm64 only)
    - Downloads the latest release binary from GitHub
    - Verifies checksum for security
    - Installs binary to ${INSTALL_DIR}
    - Creates systemd service for auto-start
    - Starts the agent on port 9999

DIRECTORIES USED:
    ${INSTALL_DIR}             - Binary installation location
    /etc/systemd/system        - Systemd service file
    /etc/bjorn2scan            - Configuration files
    /var/lib/bjorn2scan        - Data directory (database)
    /var/log/bjorn2scan        - Log files
    /etc/logrotate.d           - Logrotate configuration
    /tmp/bjorn2scan-*          - Temporary download directory (auto-cleaned)

REQUIREMENTS:
    - Linux operating system (Ubuntu, Debian, RHEL, etc.)
    - systemd (for service management)
    - curl or wget
    - Root/sudo access

ENDPOINTS:
    Once installed, the agent exposes:
    - http://localhost:9999/health  - Health check
    - http://localhost:9999/info    - System information

USEFUL COMMANDS:
    systemctl status ${SERVICE_NAME}   - Check status
    systemctl restart ${SERVICE_NAME}  - Restart service
    journalctl -u ${SERVICE_NAME} -f   - View logs

MORE INFO:
    https://github.com/${GITHUB_REPO}

EOF
    exit 0
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        log_info "Try: curl -sSfL https://github.com/${GITHUB_REPO}/releases/latest/download/install.sh | sudo sh"
        exit 1
    fi
}

# Detect OS
detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        linux) OS="linux" ;;
        *) log_error "Unsupported OS: $OS (only Linux is supported)"; exit 1 ;;
    esac
    log_info "Detected OS: $OS"
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    log_info "Detected architecture: $ARCH"
}

# Detect Linux distribution (for systemd check)
detect_distro() {
    if [ -f /etc/os-release ]; then
        # Save VERSION before sourcing (os-release may contain a VERSION variable)
        _SAVED_VERSION="$VERSION"
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
        # Restore our VERSION variable
        VERSION="$_SAVED_VERSION"
        log_info "Detected distribution: $DISTRO $DISTRO_VERSION"
    else
        log_warning "Could not detect Linux distribution"
    fi
}

# Check for systemd
check_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        log_warning "Systemd not found - service will not be installed"
        return 1
    fi
    return 0
}

# Download binary (or use local if specified)
download_binary() {
    log_info "Installing version: ${VERSION}"

    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"

    # Use local binary if specified
    if [ -n "$LOCAL_BINARY_PATH" ]; then
        if [ ! -f "$LOCAL_BINARY_PATH" ]; then
            log_error "Local binary not found: $LOCAL_BINARY_PATH"
            exit 1
        fi

        log_info "Using local binary: $LOCAL_BINARY_PATH"
        cp "$LOCAL_BINARY_PATH" "${BINARY_NAME}-${OS}-${ARCH}.tar.gz"

        # Also copy checksum if it exists
        if [ -f "${LOCAL_BINARY_PATH}.sha256" ]; then
            cp "${LOCAL_BINARY_PATH}.sha256" "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
        fi

        log_success "Local binary copied"
        return 0
    fi

    # Download from GitHub
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

    log_info "Downloading from: $DOWNLOAD_URL"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$DOWNLOAD_URL" -o "${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
        curl -sSfL "$CHECKSUM_URL" -o "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
    else
        wget -q "$DOWNLOAD_URL" -O "${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
        wget -q "$CHECKSUM_URL" -O "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
    fi

    log_success "Download complete"
}

# Verify checksum
verify_checksum() {
    log_info "Verifying checksum..."

    # Skip if checksum file doesn't exist (e.g., when using local binary for testing)
    if [ ! -f "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256" ]; then
        log_warning "Checksum file not found, skipping verification (local binary mode)"
        return
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
    else
        log_warning "No checksum tool found, skipping verification"
        return
    fi

    log_success "Checksum verified"
}

# Extract binary
extract_binary() {
    log_info "Extracting binary..."
    tar -xzf "${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    log_success "Extraction complete"
}

# Stop existing service
stop_service() {
    if check_systemd && systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Stopping existing service..."
        systemctl stop "$SERVICE_NAME"
        log_success "Service stopped"
    fi
}

# Check if group exists (portable across distros)
group_exists() {
    if command -v getent >/dev/null 2>&1; then
        getent group "$1" >/dev/null 2>&1
    else
        grep -q "^${1}:" /etc/group 2>/dev/null
    fi
}

# Check if user exists (portable across distros)
user_exists() {
    if command -v getent >/dev/null 2>&1; then
        getent passwd "$1" >/dev/null 2>&1
    else
        grep -q "^${1}:" /etc/passwd 2>/dev/null
    fi
}

# Create user and group (supports both GNU and BusyBox tools)
create_user() {
    # Detect if we're on Alpine/BusyBox
    IS_ALPINE=false
    if [ "$DISTRO" = "alpine" ] || ! command -v groupadd >/dev/null 2>&1; then
        IS_ALPINE=true
    fi

    # Create group
    if ! group_exists "$GROUP_NAME"; then
        log_info "Creating group: $GROUP_NAME"
        if [ "$IS_ALPINE" = true ]; then
            addgroup -S "$GROUP_NAME"
        else
            groupadd --system "$GROUP_NAME"
        fi
    fi

    # Create user
    if ! user_exists "$USER_NAME"; then
        log_info "Creating user: $USER_NAME"
        if [ "$IS_ALPINE" = true ]; then
            adduser -S -D -H -G "$GROUP_NAME" -s /bin/false "$USER_NAME"
        else
            useradd --system --gid "$GROUP_NAME" --no-create-home --shell /bin/false "$USER_NAME"
        fi
    fi
}

# Install binary
install_binary() {
    log_info "Installing binary to $INSTALL_DIR..."

    # Create binary directory
    mkdir -p "$INSTALL_DIR"

    # After extraction, the binary is named generically (without platform suffix)
    install -m 755 "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

    log_success "Binary installed"
}

# Install configuration file
install_config() {
    log_info "Installing configuration file..."

    # Create config directory
    mkdir -p "$CONFIG_DIR"

    # Always install/update the example config
    CONFIG_EXAMPLE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/agent.conf.example"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$CONFIG_EXAMPLE_URL" -o "$CONFIG_EXAMPLE" 2>/dev/null || \
            log_warning "Could not download example config (will use defaults)"
    else
        wget -q "$CONFIG_EXAMPLE_URL" -O "$CONFIG_EXAMPLE" 2>/dev/null || \
            log_warning "Could not download example config (will use defaults)"
    fi

    # Check if user config already exists
    if [ -f "$CONFIG_FILE" ]; then
        log_warning "Configuration file exists at $CONFIG_FILE"
        log_info "Preserving existing configuration"
        log_info "See $CONFIG_EXAMPLE for new configuration options"

        # Show what's different (if diff exists)
        if command -v diff >/dev/null 2>&1 && [ -f "$CONFIG_EXAMPLE" ]; then
            echo ""
            log_info "Configuration changes in this version:"
            if diff -u "$CONFIG_FILE" "$CONFIG_EXAMPLE" 2>/dev/null | grep '^[+-]' | grep -v '^[+-][+-][+-]' | head -20; then
                :
            else
                log_info "No new configuration options detected"
            fi
            echo ""
        fi
    else
        # Fresh install - copy example to active config
        if [ -f "$CONFIG_EXAMPLE" ]; then
            cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
            log_success "Configuration file created at $CONFIG_FILE"
            log_info "Edit this file to customize settings (port, paths, debug mode, etc.)"
        else
            log_warning "Using built-in defaults (no config file created)"
        fi
    fi

    # Set permissions
    if [ -f "$CONFIG_FILE" ]; then
        chmod 644 "$CONFIG_FILE"
    fi
    if [ -f "$CONFIG_EXAMPLE" ]; then
        chmod 644 "$CONFIG_EXAMPLE"
    fi
}

# Get systemd version
get_systemd_version() {
    systemctl --version | head -n 1 | awk '{print $2}'
}

# Install systemd service
install_service() {
    if ! check_systemd; then
        log_warning "Skipping service installation"
        return
    fi

    log_info "Installing systemd service..."

    # Check systemd version and choose appropriate service file
    SYSTEMD_VERSION=$(get_systemd_version)
    SERVICE_FILE="bjorn2scan-agent.service"

    if [ "$SYSTEMD_VERSION" -lt 232 ]; then
        log_warning "Old systemd detected (v$SYSTEMD_VERSION), using compatibility mode"
        SERVICE_FILE="bjorn2scan-agent-compat.service"
    fi

    # Download service file
    SERVICE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/${SERVICE_FILE}"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$SERVICE_URL" -o "${SERVICE_DIR}/${SERVICE_NAME}"
    else
        wget -q "$SERVICE_URL" -O "${SERVICE_DIR}/${SERVICE_NAME}"
    fi

    # Create required directories for the service
    # Note: Service runs as root, but these directories need to exist for systemd mount namespacing
    mkdir -p /var/lib/bjorn2scan/bin
    mkdir -p /var/lib/bjorn2scan/data
    mkdir -p /var/lib/bjorn2scan/cache
    mkdir -p /var/log/bjorn2scan
    mkdir -p /etc/bjorn2scan

    # Create symlinks for convenience (config and logs accessible from /var/lib/bjorn2scan)
    ln -sf /etc/bjorn2scan /var/lib/bjorn2scan/config
    ln -sf /var/log/bjorn2scan /var/lib/bjorn2scan/log

    chmod 755 /var/lib/bjorn2scan /var/log/bjorn2scan /etc/bjorn2scan

    # Install logrotate configuration
    LOGROTATE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/logrotate.conf"
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$LOGROTATE_URL" -o /etc/logrotate.d/bjorn2scan-agent 2>/dev/null || log_warning "Could not install logrotate config"
    else
        wget -q "$LOGROTATE_URL" -O /etc/logrotate.d/bjorn2scan-agent 2>/dev/null || log_warning "Could not install logrotate config"
    fi

    # Reload systemd
    systemctl daemon-reload

    log_success "Service installed"
}

# Enable and start service
enable_service() {
    if ! check_systemd; then
        return
    fi

    log_info "Enabling service..."
    systemctl enable "$SERVICE_NAME"

    log_info "Starting service..."
    systemctl start "$SERVICE_NAME"

    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "Service is running"
    else
        log_error "Service failed to start"
        log_info "Check logs: journalctl -u $SERVICE_NAME"
        exit 1
    fi
}

# Show installation summary
show_summary() {
    echo ""
    echo "======================================"
    echo "Installation Summary"
    echo "======================================"
    log_success "bjorn2scan-agent v${VERSION} installed successfully!"
    echo ""
    echo "Installed files and directories:"
    echo "  Binary:    ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  Config:    ${CONFIG_FILE}"
    echo "  Example:   ${CONFIG_EXAMPLE}"
    echo "  Data:      /var/lib/bjorn2scan"
    echo "  Logs:      /var/log/bjorn2scan"

    if check_systemd; then
        echo "  Service:   ${SERVICE_DIR}/${SERVICE_NAME}"
        echo "  Logrotate: /etc/logrotate.d/bjorn2scan-agent"
        echo ""
        echo "Useful commands:"
        echo "  Status:  systemctl status $SERVICE_NAME"
        echo "  Logs:    journalctl -u $SERVICE_NAME -f"
        echo "  Stop:    systemctl stop $SERVICE_NAME"
        echo "  Start:   systemctl start $SERVICE_NAME"
        echo "  Restart: systemctl restart $SERVICE_NAME"
    else
        echo ""
        echo "Run manually: ${BINARY_NAME}"
    fi

    echo ""
    echo "Test endpoints:"
    echo "  curl http://localhost:9999/health"
    echo "  curl http://localhost:9999/info"
    echo "======================================"
}

# Show directories that will be used
show_directories() {
    log_info "Directories that will be used:"
    echo "  Binary:         ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  Config:         ${CONFIG_FILE}"
    echo "  Config example: ${CONFIG_EXAMPLE}"
    echo "  Systemd:        ${SERVICE_DIR}/${SERVICE_NAME}"
    echo "  Data:           /var/lib/bjorn2scan"
    echo "  Logs:           /var/log/bjorn2scan"
    echo "  Logrotate:      /etc/logrotate.d/bjorn2scan-agent"
    echo "  Temp download:  \$TMPDIR (auto-cleaned)"
    echo ""
}

# Main installation flow
main() {
    log_info "Starting bjorn2scan-agent installation..."
    echo ""

    check_root
    detect_os
    detect_arch
    detect_distro
    show_directories
    download_binary
    verify_checksum
    extract_binary
    stop_service
    create_user
    install_binary
    install_config
    install_service
    enable_service

    # Cleanup
    cd /
    rm -rf "$TMP_DIR"

    show_summary
}

# Handle uninstall
uninstall() {
    log_info "Uninstalling bjorn2scan-agent..."

    check_root

    if check_systemd && systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
        systemctl disable "$SERVICE_NAME"
        rm -f "${SERVICE_DIR}/${SERVICE_NAME}"
        systemctl daemon-reload
    fi

    # Remove binary and directories
    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -rf /var/lib/bjorn2scan
    rm -rf /var/log/bjorn2scan
    rm -rf /etc/bjorn2scan
    rm -f /etc/logrotate.d/bjorn2scan-agent

    log_success "Uninstall complete"
}

# Parse arguments
case "$1" in
    --help|-h|help)
        show_help
        ;;
    uninstall)
        uninstall
        ;;
    *)
        main
        ;;
esac
