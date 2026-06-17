# Scheduled Jobs Configuration

Bjørn2Scan includes scheduled jobs that run periodically to maintain the system. This document explains how to configure these jobs for both Kubernetes (Helm) and agent deployments.

## Available Jobs

### 1. Refresh Images Job

**Purpose**: Keeps the database synchronized with running workloads

**How it works**:
- Queries all running containers (from Kubernetes or Docker/containerd)
- Compares with database state
- Adds new container instances
- Removes instances no longer running
- Triggers scans for new images

**Default schedule**: Every 6 hours

**Log example**:
```
[refresh-images] Starting periodic reconciliation of running containers
Set container instances: 42 instances, 12 unique images, 3 nodes
Reconciliation complete: added=42, removed=38, new_images=2
Reconciliation summary: 42 instances added, 38 instances removed, 2 new images discovered
```

### 2. Cleanup Job

**Purpose**: Removes orphaned container images and related data

**How it works**:
- Identifies container_images with no associated container_instances
- Deletes orphaned images
- Cascades deletion to packages and vulnerabilities
- Frees up database space

**Default schedule**: Daily (24 hours)

**Log example**:
```
[cleanup] Starting cleanup of orphaned container images
Cleanup complete: removed 5 images, 123 packages, 456 vulnerabilities
[cleanup] Cleanup job completed successfully
```

### 3. Rescan Database Job

**Purpose**: Re-scans images when the Grype vulnerability database updates

**How it works**:
- Checks for Grype database updates
- Identifies images scanned with an older database version
- Re-runs vulnerability scan using existing SBOMs (no SBOM regeneration)
- Also triggers node rescans when host scanning is enabled

**Default schedule**: Every 30 minutes

**Log example**:
```
[rescan-database] Checking for vulnerability database updates...
[rescan-database] Current grype DB: built=2026-01-15T08:20:13Z
[rescan-database] Found 42 images scanned with older grype DB, triggering rescan
[rescan-database] Enqueued 42 images for rescanning
```

### 4. Rescan Nodes Job

**Purpose**: Periodically rescans all nodes with fresh SBOMs to detect package changes

**How it works**:
- Gets all completed nodes
- Enqueues full rescan for each (regenerates SBOM + vulnerability scan)
- Unlike rescan-database, this always retrieves a fresh SBOM because node packages change over time
- Only runs when host scanning is enabled

**Default schedule**: Daily (24 hours)

**Log example**:
```
[rescan-nodes] Starting periodic node rescan with fresh SBOMs...
[rescan-nodes] Found 3 completed nodes, triggering full rescan with fresh SBOMs
[rescan-nodes] Enqueued 3 nodes for full rescan
```

**Key difference from rescan-database**:
| Aspect | rescan-database | rescan-nodes |
|--------|-----------------|--------------|
| Trigger | Grype DB updates | Scheduled interval |
| SBOM | Reuses existing | Always fresh |
| Purpose | New CVE detection | Detect package changes |

## Kubernetes Configuration (Helm)

Jobs are configured in the Helm chart's `values.yaml` under `scanServer.config.jobs`:

```yaml
scanServer:
  config:
    jobs:
      # Refresh Images Job
      refreshImages:
        enabled: true      # Enable/disable the job
        interval: "6h"     # How often to run (Go duration format)
        timeout: "10m"     # Maximum execution time

      # Cleanup Job
      cleanup:
        enabled: true
        interval: "24h"
        timeout: "1h"

      # Rescan Database Job - rescans when Grype DB updates
      rescanDatabase:
        enabled: true
        interval: "30m"    # How often to check for updates
        timeout: "30m"

      # Rescan Nodes Job - periodic full rescan with fresh SBOMs
      # Only runs when hostScanning.enabled is true
      rescanNodes:
        enabled: true
        interval: "24h"    # How often to rescan nodes
        timeout: "2h"      # SBOM generation can be slow
```

### Customizing via Helm Install/Upgrade

```bash
# Change refresh interval to 12 hours
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --set scanServer.config.jobs.refreshImages.interval=12h

# Disable cleanup job
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --set scanServer.config.jobs.cleanup.enabled=false

# Change both jobs
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --set scanServer.config.jobs.refreshImages.interval=3h \
  --set scanServer.config.jobs.cleanup.interval=48h
```

### Using a Custom values.yaml

Create a file `my-values.yaml`:
```yaml
scanServer:
  config:
    jobs:
      refreshImages:
        enabled: true
        interval: "3h"      # More frequent refreshes
        timeout: "10m"
      cleanup:
        enabled: true
        interval: "7d"      # Weekly cleanup instead of daily
        timeout: "2h"       # Longer timeout for large databases
```

Apply it:
```bash
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -f my-values.yaml
```

## Agent Configuration

Jobs are configured in `/etc/bjorn2scan/agent.conf` or `./agent.conf`:

```ini
# ============================================================================
# SCHEDULED JOBS CONFIGURATION
# ============================================================================

# Enable scheduled jobs system (default: true)
jobs_enabled=true

# --- Refresh Images Job ---
jobs_refresh_images_enabled=true
jobs_refresh_images_interval=6h
jobs_refresh_images_timeout=10m

# --- Cleanup Job ---
jobs_cleanup_enabled=true
jobs_cleanup_interval=24h
jobs_cleanup_timeout=1h

# --- Rescan Database Job ---
# Rescans images when Grype vulnerability database updates
jobs_rescan_database_enabled=true
jobs_rescan_database_interval=30m
jobs_rescan_database_timeout=30m

# --- Rescan Nodes Job ---
# Periodic full rescan of nodes with fresh SBOMs
# Only runs when host_scanning_enabled=true
jobs_rescan_nodes_enabled=true
jobs_rescan_nodes_interval=24h
jobs_rescan_nodes_timeout=2h
```

### Configuration via Environment Variables

Environment variables override config file settings:

```bash
# Change refresh interval
export JOBS_REFRESH_IMAGES_INTERVAL=3h

# Disable cleanup
export JOBS_CLEANUP_ENABLED=false

# Change cleanup interval
export JOBS_CLEANUP_INTERVAL=48h

# Rescan database job
export JOBS_RESCAN_DATABASE_ENABLED=true
export JOBS_RESCAN_DATABASE_INTERVAL=1h

# Rescan nodes job (requires HOST_SCANNING_ENABLED=true)
export JOBS_RESCAN_NODES_ENABLED=true
export JOBS_RESCAN_NODES_INTERVAL=12h
export JOBS_RESCAN_NODES_TIMEOUT=3h
```

### Systemd Service

If using systemd, environment variables can be set in the service file:

```ini
[Service]
Environment="JOBS_REFRESH_IMAGES_INTERVAL=3h"
Environment="JOBS_CLEANUP_INTERVAL=48h"
```

Then reload and restart:
```bash
sudo systemctl daemon-reload
sudo systemctl restart bjorn2scan-agent
```

## Duration Format

All interval and timeout values use Go duration format:

| Format | Meaning |
|--------|---------|
| `30s` | 30 seconds |
| `5m` | 5 minutes |
| `1h` | 1 hour |
| `6h` | 6 hours |
| `24h` | 24 hours (1 day) |
| `48h` | 48 hours (2 days) |
| `168h` | 168 hours (7 days) |

You can combine units: `1h30m` = 1 hour 30 minutes

## Monitoring Jobs

### Check Job Status

**Kubernetes**:
```bash
# View scanner-server logs
kubectl logs -n b2sv2 deployment/bjorn2scan-scan-server | grep -E '\[refresh-images\]|\[cleanup\]'
```

**Agent**:
```bash
# View agent logs
sudo journalctl -u bjorn2scan-agent -f | grep -E '\[refresh-images\]|\[cleanup\]'

# Or check log file if not using systemd
tail -f /var/log/bjorn2scan/agent.log | grep -E '\[refresh-images\]|\[cleanup\]'
```

### Expected Log Patterns

**Refresh Job** (every 6h by default):
```
[refresh-images] Starting periodic reconciliation of running containers
Set container instances: 42 instances, 12 unique images, 3 nodes
Reconciliation summary: 42 instances added, 38 instances removed, 2 new images discovered
[refresh-images] Reconciliation triggered successfully
```

**Cleanup Job** (daily by default):
```
[cleanup] Starting cleanup of orphaned container images
Cleanup complete: removed 5 images, 123 packages, 456 vulnerabilities
[cleanup] Cleanup job completed successfully
```

Or when nothing to clean:
```
[cleanup] Starting cleanup of orphaned container images
Cleanup: no orphaned images found
[cleanup] Cleanup job completed successfully
```

## Troubleshooting

### Job Not Running

1. **Check if jobs are enabled**:
   - Kubernetes: `helm get values bjorn2scan -n b2sv2 | grep -A 10 jobs`
   - Agent: `grep jobs_enabled /etc/bjorn2scan/agent.conf`

2. **Check for errors in logs**:
   ```bash
   # Kubernetes
   kubectl logs -n b2sv2 deployment/bjorn2scan-scan-server | grep -E 'error|Error|ERROR'

   # Agent
   sudo journalctl -u bjorn2scan-agent | grep -E 'error|Error|ERROR'
   ```

3. **Verify scheduler started**:
   ```bash
   # Look for scheduler startup message
   # Kubernetes
   kubectl logs -n b2sv2 deployment/bjorn2scan-scan-server | grep scheduler

   # Agent
   sudo journalctl -u bjorn2scan-agent | grep scheduler
   ```

### Job Timing Out

If jobs consistently timeout, increase the timeout:

**Kubernetes**:
```bash
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --set scanServer.config.jobs.refreshImages.timeout=20m
```

**Agent**:
```ini
jobs_refresh_images_timeout=20m
```

### High Resource Usage

If jobs cause resource spikes:

1. **Increase interval** (run less frequently):
   ```yaml
   refreshImages:
     interval: "12h"  # Instead of 6h
   ```

2. **Run during off-peak hours** (future feature):
   Scheduled for future implementation - time-of-day scheduling

## Recommendations

### Small Deployments (< 50 containers)
```yaml
refreshImages:
  interval: "3h"    # More frequent for faster detection
  timeout: "5m"
cleanup:
  interval: "24h"
  timeout: "30m"
```

### Medium Deployments (50-500 containers)
```yaml
refreshImages:
  interval: "6h"    # Default - good balance
  timeout: "10m"
cleanup:
  interval: "24h"
  timeout: "1h"
```

### Large Deployments (> 500 containers)
```yaml
refreshImages:
  interval: "12h"   # Less frequent to reduce load
  timeout: "20m"    # More time for large reconciliation
cleanup:
  interval: "7d"    # Weekly to reduce database churn
  timeout: "2h"
```

## Future Jobs

The following jobs are planned for future releases:

### Telemetry Job
Sends usage metrics and statistics to OpenTelemetry collector.
