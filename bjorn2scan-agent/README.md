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
curl -sSfL https://github.com/bvboe/b2s-go/releases/latest/download/install.sh | sudo sh
```

#### Specific Version (Pinned)

For reproducible installations or to match a specific release, download the version-stamped install script from a GitHub release:

```bash
# Install version 0.1.35 specifically
curl -sSfL https://github.com/bvboe/b2s-go/releases/download/v0.1.35/install.sh | sudo sh
```

Replace `v0.1.35` with your desired version. Each release includes a version-stamped `install.sh` that defaults to installing that specific version.

**What the installer does:**
- Download the release binary for your platform (amd64 or arm64)
- Verify SHA256 checksums
- Install the binary to `/usr/local/bin/bjorn2scan-agent`
- Create systemd service
- Start the service automatically

### Manual Installation

1. Download the binary for your platform from [releases](https://github.com/bvboe/b2s-go/releases)
2. Extract and install:

```bash
tar -xzf bjorn2scan-agent-linux-amd64.tar.gz
sudo install -m 755 bjorn2scan-agent-linux-amd64 /usr/local/bin/bjorn2scan-agent
```

3. (Optional) Install systemd service:

```bash
sudo curl -sSfL https://raw.githubusercontent.com/bvboe/b2s-go/main/bjorn2scan-agent/bjorn2scan-agent.service \
  -o /etc/systemd/system/bjorn2scan-agent.service
sudo systemctl daemon-reload
sudo systemctl enable bjorn2scan-agent
sudo systemctl start bjorn2scan-agent
```

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

Environment variables:
- `PORT`: HTTP server port (default: 9999)

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
curl -sSfL https://github.com/bvboe/b2s-go/releases/latest/download/install.sh | sudo sh -s uninstall
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
