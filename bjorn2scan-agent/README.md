# bjorn2scan-agent

Host-level security scanning agent for the Bjorn2Scan v2 platform.

## Overview

The bjorn2scan-agent runs directly on Linux hosts (not in Kubernetes) and provides HTTP endpoints for health checks and system information.

## Features

- Lightweight binary with no external dependencies
- HTTP server on port 9999
- `/health` and `/info` endpoints
- Systemd integration for auto-start on boot
- Graceful shutdown support
- Multi-architecture support (linux-amd64, linux-arm64)

## Installation

### One-liner Installation (Linux)

#### Latest Version (Recommended)

Install the latest release:

```bash
curl -sSfL https://github.com/bvboe/bjorn2scan/releases/latest/download/install.sh | sudo sh
```

#### Specific Version (Pinned)

For reproducible installations or to match a specific release, download the version-stamped install script from a GitHub release:

```bash
# Install version 0.1.35 specifically
curl -sSfL https://github.com/bvboe/bjorn2scan/releases/download/v0.1.35/install.sh | sudo sh
```

Replace `v0.1.35` with your desired version. Each release includes a version-stamped `install.sh` that defaults to installing that specific version.

#### Verifying the installer (recommended)

Piping a script straight into `sudo sh` runs unreviewed code as root. To inspect it
first, download, read, then execute:

```bash
curl -sSfL https://github.com/bvboe/bjorn2scan/releases/download/v0.1.35/install.sh -o install.sh
less install.sh                 # review what it does
sudo sh install.sh              # run once you're satisfied
```

The installer verifies the downloaded binary's SHA256 checksum. The release binaries
are additionally cosign-signed (see the release notes for `cosign verify-blob`
instructions), and the agent's auto-updater cosign-verifies every subsequent update.

**What the installer does:**
- Download the release binary for your platform (amd64 or arm64)
- Verify SHA256 checksums
- Install the binary to `/var/lib/bjorn2scan/bin/bjorn2scan-agent`
- Create systemd service
- Start the service automatically

### Manual Installation

1. Download the tarball for your platform from [releases](https://github.com/bvboe/bjorn2scan/releases) and verify its checksum:

```bash
curl -sSfLO https://github.com/bvboe/bjorn2scan/releases/latest/download/bjorn2scan-agent-linux-amd64.tar.gz
curl -sSfLO https://github.com/bvboe/bjorn2scan/releases/latest/download/bjorn2scan-agent-linux-amd64.tar.gz.sha256
sha256sum -c bjorn2scan-agent-linux-amd64.tar.gz.sha256
```

2. Extract it — the tarball contains the binary plus the systemd unit, config template, and logrotate config:

```bash
tar -xzf bjorn2scan-agent-linux-amd64.tar.gz
```

3. Install the binary and create the directories the service expects (`ProtectSystem=strict` confines writes to these):

```bash
sudo mkdir -p /var/lib/bjorn2scan/bin /var/lib/bjorn2scan/data /var/lib/bjorn2scan/cache /var/log/bjorn2scan /etc/bjorn2scan
sudo install -m 755 bjorn2scan-agent /var/lib/bjorn2scan/bin/bjorn2scan-agent
sudo chmod 750 /var/log/bjorn2scan
```

4. (Optional) Install the systemd service, config, and logrotate from the extracted files:

```bash
sudo install -m 644 bjorn2scan-agent.service /etc/systemd/system/bjorn2scan-agent.service
sudo install -m 640 agent.conf.example /etc/bjorn2scan/agent.conf   # then edit to taste
sudo install -m 644 logrotate.conf /etc/logrotate.d/bjorn2scan-agent
sudo systemctl daemon-reload
sudo systemctl enable --now bjorn2scan-agent
```

> On systemd older than v232, install `bjorn2scan-agent-compat.service` (also in the tarball) as the unit file instead.

## Usage

### Systemd Commands

```bash
# Check status
systemctl status bjorn2scan-agent

# View logs
journalctl -u bjorn2scan-agent -f

# Restart service
systemctl restart bjorn2scan-agent
```

### API Endpoints

**Health Check:**
```bash
curl http://localhost:9999/health
# Output: OK
```

**System Info:**
```bash
curl http://localhost:9999/info
# Output: {"component":"bjorn2scan-agent","version":"0.1.0","hostname":"server01","os":"linux","arch":"amd64"}
```

### Configuration

The agent reads `/etc/bjorn2scan/agent.conf` (or `./agent.conf`); environment
variables override the file. See [`agent.conf.example`](agent.conf.example) for the
full list. Common options:

- `port` / `PORT`: HTTP server port (default: 9999)
- `listen_address` / `LISTEN_ADDRESS`: listener bind address (default: `0.0.0.0` — all interfaces)
- `debug_enabled` / `DEBUG_ENABLED`: enable debug endpoints and the mutating `/api/update/{trigger,pause,resume}` controls (default: false)
- `web_ui_enabled` / `WEB_UI_ENABLED`: serve the dashboard + API (default: true)

> **Security:** the dashboard and read-only `/api/*` endpoints are unauthenticated and
> bind all interfaces by default, so the host's scan data is reachable on the local
> network. Metrics are pushed to Prometheus, so direct API access is optional. To
> harden, set `listen_address=127.0.0.1` (loopback only) or `web_ui_enabled=false` to
> disable the API entirely. The mutating update controls are already gated behind
> `debug_enabled` (off by default).

## Development

### Prerequisites

- Go 1.25 or later
- Docker (for testing)
- Make

### Build

```bash
# Build for current platform
make build

# Build for all platforms (Linux amd64, arm64)
make build-all

# Test in Docker
make docker-test
```

### Local Development

```bash
# Build and run
make build
./bjorn2scan-agent

# In another terminal
curl http://localhost:9999/health
```

### Testing

```bash
# Run tests
make test

# Test in Docker container
make docker-test
```

## Uninstall

```bash
curl -sSfL https://github.com/bvboe/bjorn2scan/releases/latest/download/install.sh | sudo sh -s uninstall
```

This will completely remove:
- The agent binary and service
- All data, cache, and configuration files
- All log files
- The systemd service configuration

**Warning:** Uninstall removes all data and logs. Back up any data you need before uninstalling.

## Architecture

The agent is designed to run on Linux hosts and provides basic HTTP endpoints for monitoring. It's built as a static binary with no external dependencies, making it easy to deploy across different Linux distributions.

### Version Information

The binary version is embedded at build time using ldflags. You can check the version via:
```bash
curl http://localhost:9999/info | jq .version
```

## License

[Your license here]
