# Test Container for bjorn2scan-agent

This directory contains a test container setup that provides a realistic environment for testing the bjorn2scan-agent with:
- ✅ **systemd** for service management
- ✅ **Docker daemon** running inside the container
- ✅ **Agent installed** using the actual install.sh script
- ✅ **Local binary** support for testing unreleased versions

## Quick Start

```bash
# Build and run the test container
./test-container.sh run

# Test the agent
curl http://localhost:9999/health
curl http://localhost:9999/info

# View logs
./test-container.sh logs

# Open a shell in the container
./test-container.sh shell

# Stop and clean up
./test-container.sh clean
```

## Architecture

The test container uses a **two-stage build**:

### Stage 1: Build (Chainguard Go)
- Uses `cgr.dev/chainguard/go:latest-dev` for secure, minimal build environment
- Builds the agent binary from source
- Creates a tarball matching the format expected by install.sh

### Stage 2: Runtime (Ubuntu 22.04)
- Uses Ubuntu 22.04 for full systemd support
- Installs Docker daemon
- Runs the actual install.sh script with `LOCAL_BINARY_PATH`
- Starts both systemd and Docker on container startup

> **Note**: We use Ubuntu instead of Chainguard's wolfi-base because systemd and Docker-in-Docker require full system capabilities that minimal distros don't provide.

## Container Features

### Systemd Service Management
The agent runs as a proper systemd service, just like in production:

```bash
# Check service status
docker exec bjorn2scan-test systemctl status bjorn2scan-agent

# View service logs
docker exec bjorn2scan-test journalctl -u bjorn2scan-agent -f

# Restart the service
docker exec bjorn2scan-test systemctl restart bjorn2scan-agent
```

### Docker-in-Docker
The container has a working Docker daemon for testing container scanning:

```bash
# Run a test container inside
docker exec bjorn2scan-test docker run -d nginx:latest

# List containers
docker exec bjorn2scan-test docker ps

# The agent should detect and scan it
curl http://localhost:9999/api/images
```

### Local Binary Installation
The install.sh script supports `LOCAL_BINARY_PATH` environment variable for testing:

```bash
# Inside the container, the agent was installed with:
LOCAL_BINARY_PATH=/tmp/agent-binary.tar.gz /tmp/install.sh
```

This allows testing unreleased versions without needing GitHub releases.

## Usage

### Build the Image

```bash
./test-container.sh build
```

This:
1. Builds the agent binary using Chainguard Go
2. Creates the runtime image with systemd + Docker
3. Tags it as `bjorn2scan-agent:test-local`

### Run the Container

```bash
./test-container.sh run
```

This:
1. Builds the image (if needed)
2. Stops any existing test container
3. Starts a new container with `--privileged` mode
4. Waits for health check to pass
5. Displays access information

The container runs with:
- **Name**: `bjorn2scan-test`
- **Port**: `9999` mapped to host
- **Privileges**: `--privileged` (required for systemd + Docker)

### Access the Container

```bash
# Open a bash shell
./test-container.sh shell

# Once inside, you can:
systemctl status bjorn2scan-agent
journalctl -u bjorn2scan-agent -f
docker ps
curl http://localhost:9999/health
```

### View Logs

```bash
# Container logs (systemd output)
./test-container.sh logs

# Agent service logs (inside container)
docker exec bjorn2scan-test journalctl -u bjorn2scan-agent -f
```

### Restart Agent

```bash
./test-container.sh restart
```

Restarts the bjorn2scan-agent service and shows its status.

### Clean Up

```bash
# Stop and remove container
./test-container.sh clean

# Remove the image too
docker rmi bjorn2scan-agent:test-local
```

## Testing Scenarios

### Test Agent Installation

The agent is automatically installed on container startup. Verify:

```bash
# Check service is running
docker exec bjorn2scan-test systemctl status bjorn2scan-agent

# Check endpoints
curl http://localhost:9999/health
curl http://localhost:9999/info

# Check logs
docker exec bjorn2scan-test journalctl -u bjorn2scan-agent -n 50
```

### Test Container Scanning

```bash
# Enter the container
./test-container.sh shell

# Run some test containers
docker run -d --name test-nginx nginx:latest
docker run -d --name test-alpine alpine:latest sleep 3600

# Check if agent detected them
curl http://localhost:9999/api/images
```

### Test Service Management

```bash
# Restart service
docker exec bjorn2scan-test systemctl restart bjorn2scan-agent

# Stop service
docker exec bjorn2scan-test systemctl stop bjorn2scan-agent

# Check status
docker exec bjorn2scan-test systemctl status bjorn2scan-agent

# Start again
docker exec bjorn2scan-test systemctl start bjorn2scan-agent
```

### Test Configuration Changes

```bash
./test-container.sh shell

# Edit config
vi /etc/bjorn2scan/agent.conf

# Restart to apply changes
systemctl restart bjorn2scan-agent

# Verify
journalctl -u bjorn2scan-agent -f
```

## Limitations

This container is **for testing only**, not production:

- ⚠️ Runs with `--privileged` (security risk)
- ⚠️ Docker-in-Docker has performance overhead
- ⚠️ systemd in containers requires special handling
- ⚠️ No persistent storage (data lost on container removal)

## Future Enhancements

For upgrade testing (planned):

1. **Build multiple versions**: Create tarballs for different agent versions
2. **Mount test binaries**: Volume mount `/test-binaries/` with different versions
3. **Test upgrade flow**:
   - Install v0.1.52
   - Use `LOCAL_BINARY_PATH=/test-binaries/v0.1.53.tar.gz` to trigger upgrade
   - Verify service restarts and health checks work
4. **Test rollback**: Simulate failed upgrades and verify rollback mechanism

## Troubleshooting

### Container won't start

Check if privileged mode is enabled:
```bash
docker inspect bjorn2scan-test | grep Privileged
```

Should show `"Privileged": true`

### Agent not responding

```bash
# Check service status
docker exec bjorn2scan-test systemctl status bjorn2scan-agent

# Check logs
docker exec bjorn2scan-test journalctl -u bjorn2scan-agent -n 100

# Check if port is listening
docker exec bjorn2scan-test netstat -tlnp | grep 9999
```

### Docker daemon not running

```bash
# Check Docker daemon
docker exec bjorn2scan-test ps aux | grep dockerd

# Check Docker logs
docker exec bjorn2scan-test cat /var/log/docker.log

# Restart manually
docker exec bjorn2scan-test pkill dockerd
docker exec bjorn2scan-test dockerd &
```

### Build fails

```bash
# Clean build cache
docker system prune -a

# Rebuild from scratch
./test-container.sh clean
./test-container.sh build
```

## Reference

- **Dockerfile**: `Dockerfile.test`
- **Helper script**: `test-container.sh`
- **Agent source**: Current directory
- **Install script**: `install.sh` (with `LOCAL_BINARY_PATH` support)
