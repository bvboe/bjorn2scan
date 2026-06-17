# Bjorn2Scan Logging Strategy

This document describes the structured logging implementation for bjorn2scan.

## Overview

Bjorn2scan uses Go's `log/slog` package for structured logging. The logging package is located at `scanner-core/logging/` and provides:

- Consistent structured fields across all components
- Component identification for easy log filtering
- Environment-based configuration (no code changes needed)
- JSON or text output formats

## Configuration

Logging is configured via environment variables:

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` | Minimum log level |
| `LOG_FORMAT` | `text`, `json` | `text` | Output format |

### Helm Configuration

```yaml
# values.yaml
env:
  LOG_LEVEL: "info"   # or "debug" for troubleshooting
  LOG_FORMAT: "text"  # or "json" for structured output
```

## Component Names

Each log entry includes a `component` field identifying its source:

| Component | Description | Files |
|-----------|-------------|-------|
| `scheduler` | Job scheduling | `scanner-core/scheduler/` |
| `grype` | Vulnerability scanning | `scanner-core/grype/`, queue vuln scans |
| `scan-queue` | Queue operations | `scanner-core/scanning/queue.go` |
| `database` | Database operations | `scanner-core/database/` |
| `nodes` | Node management | `scanner-core/nodes/`, queue host scans |
| `containers` | Container management | `scanner-core/containers/` |
| `http` | HTTP handlers | `scanner-core/handlers/` |
| `pod-scanner` | Pod scanner operations | `pod-scanner/` |
| `k8s` | Kubernetes operations | `k8s-scan-server/k8s/` |
| `metrics` | Metrics collection | `scanner-core/metrics/` |
| `jobs` | Scheduled jobs | `scanner-core/jobs/` |

## Usage

### In scanner-core modules

```go
import "github.com/bvboe/b2s-go/scanner-core/logging"

// Get a logger for a component
log := logging.For(logging.ComponentQueue)

// Basic logging
log.Info("job enqueued", "image", img.Reference, "digest", img.Digest)
log.Debug("checking status", "digest", digest)
log.Warn("queue full", "depth", depth)
log.Error("failed to store", slog.Any("error", err))

// With additional context
log = log.With("node", nodeName)
log.Info("processing node scan")
```

### In pod-scanner (standalone)

Pod-scanner doesn't import scanner-core, so it uses a standalone slog initialization:

```go
import "log/slog"

// Initialized at startup with LOG_LEVEL and LOG_FORMAT env vars
log := slog.Default().With("component", "pod-scanner")
log.Info("starting scan", "digest", digest)
```

## Log Output Examples

### Text Format (default)

```
time=2024-01-15T10:30:00Z level=INFO msg="processing scan job" component=scan-queue image=nginx:latest digest=sha256:abc123 force_scan=false
time=2024-01-15T10:30:01Z level=INFO msg="successfully scanned and stored SBOM" component=scan-queue image=nginx:latest digest=sha256:abc123
time=2024-01-15T10:30:02Z level=INFO msg="starting vulnerability scan" component=grype image=nginx:latest digest=sha256:abc123
```

### JSON Format

```json
{"time":"2024-01-15T10:30:00Z","level":"INFO","msg":"processing scan job","component":"scan-queue","image":"nginx:latest","digest":"sha256:abc123","force_scan":false}
{"time":"2024-01-15T10:30:01Z","level":"INFO","msg":"successfully scanned and stored SBOM","component":"scan-queue","image":"nginx:latest","digest":"sha256:abc123"}
```

## Filtering Logs

### By Component

```bash
# Filter scan queue logs
kubectl logs deploy/bjorn2scan-scan-server | grep 'component=scan-queue'

# Filter grype/vulnerability logs
kubectl logs deploy/bjorn2scan-scan-server | grep 'component=grype'

# Filter node scan logs
kubectl logs deploy/bjorn2scan-scan-server | grep 'component=nodes'
```

### By Level

```bash
# Show only errors
kubectl logs deploy/bjorn2scan-scan-server | grep 'level=ERROR'

# Show warnings and errors
kubectl logs deploy/bjorn2scan-scan-server | grep -E 'level=(WARN|ERROR)'
```

### With jq (JSON format)

```bash
# Filter by component
kubectl logs deploy/bjorn2scan-scan-server | jq 'select(.component == "scan-queue")'

# Filter by level
kubectl logs deploy/bjorn2scan-scan-server | jq 'select(.level == "ERROR")'

# Filter by image
kubectl logs deploy/bjorn2scan-scan-server | jq 'select(.image == "nginx:latest")'
```

## Migration Status

The following files have been migrated to structured logging:

- [x] `scanner-core/scanning/queue.go` - Core queue operations
- [ ] `scanner-core/handlers/` - HTTP handlers (incremental)
- [ ] `scanner-core/database/` - Database operations (incremental)
- [ ] `k8s-scan-server/k8s/` - K8s operations (incremental)

Files using stdlib `log.Printf()` will continue to work but won't have component tags. Migration is incremental and prioritizes high-impact files.

## Best Practices

1. **Use the right level:**
   - `Debug`: Detailed information for troubleshooting
   - `Info`: Normal operational messages
   - `Warn`: Recoverable issues or unexpected conditions
   - `Error`: Failures requiring attention

2. **Include context:**
   - Always include relevant identifiers (digest, node, image)
   - Use `.With()` for recurring context in a function

3. **Structured over format strings:**
   - Good: `log.Info("scan complete", "image", img, "vulns", count)`
   - Bad: `log.Info(fmt.Sprintf("scan complete: image=%s vulns=%d", img, count))`

4. **Error logging:**
   - Use `slog.Any("error", err)` for error values
   - Include context about what failed, not just the error
