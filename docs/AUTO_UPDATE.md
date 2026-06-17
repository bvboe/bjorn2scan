# Auto-Update User Guide

This guide explains how to configure and use the automatic update feature for both Kubernetes deployments and standalone agents.

## Table of Contents

- [Overview](#overview)
- [Kubernetes Auto-Update](#kubernetes-auto-update)
  - [Enabling Auto-Update](#enabling-auto-update)
  - [Configuration Options](#configuration-options)
  - [Manual Control](#manual-control)
  - [Monitoring](#monitoring)
- [Agent Auto-Update](#agent-auto-update)
  - [Configuration File](#configuration-file)
  - [API Endpoints](#api-endpoints)
  - [Systemd Integration](#systemd-integration)
- [Version Policies](#version-policies)
  - [Version Constraints](#version-constraints)
  - [Version Pinning](#version-pinning)
  - [Min/Max Bounds](#minmax-bounds)
- [Signature Verification](#signature-verification)
- [Rollback Protection](#rollback-protection)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

---

## Overview

Bjørn2Scan supports automatic updates for both Kubernetes deployments and standalone agents:

- **Kubernetes**: In-cluster CronJob that checks GHCR for new Helm chart versions and performs automatic upgrades
- **Agent**: Background service integrated into the agent binary that checks GitHub Releases and performs self-updates

Both support:
- ✅ Configurable version constraints (patch, minor, major updates)
- ✅ Version pinning for controlled deployments
- ✅ Signature verification with cosign (Kubernetes ready, Agent planned)
- ✅ Automatic health checks with rollback on failure
- ✅ Manual trigger via API/kubectl
- ✅ Pause/resume functionality

---

## Kubernetes Auto-Update

The Kubernetes update controller runs as a **CronJob** that periodically checks for new Helm chart versions and performs upgrades automatically.

### Configuring Auto-Update

Auto-update is **enabled by default** (`updateController.enabled: true`). Tune the schedule and version policies — or turn it off — via your Helm values:

```yaml
updateController:
  enabled: true          # default; set to false to disable
  schedule: "0 2 * * *"  # Daily at 2am UTC

  config:
    autoUpdateMinor: true
    autoUpdateMajor: false
    pinnedVersion: ""  # Empty = auto-update
```

Apply with `helm upgrade --install` (auto-update is already on; this sets the schedule):

```bash
helm upgrade --install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --namespace bjorn2scan \
  --create-namespace \
  --set updateController.schedule="0 2 * * *"
```

To disable auto-update entirely:

```bash
helm upgrade --install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --namespace bjorn2scan \
  --create-namespace \
  --set updateController.enabled=false
```

### Configuration Options

#### Schedule

The `schedule` field uses standard Kubernetes CronJob syntax:

```yaml
# Examples:
schedule: "0 2 * * *"      # Daily at 2am UTC
schedule: "0 */6 * * *"    # Every 6 hours
schedule: "@daily"         # Daily at midnight
schedule: "@hourly"        # Every hour
schedule: "*/30 * * * *"   # Every 30 minutes
```

#### Version Constraints

```yaml
updateController:
  config:
    # Allow automatic minor version updates (0.1.x → 0.2.x)
    autoUpdateMinor: true

    # Allow automatic major version updates (0.x.x → 1.x.x)
    autoUpdateMajor: false

    # Pin to a specific version (disables auto-update)
    pinnedVersion: ""

    # Set minimum version (won't downgrade below this)
    minVersion: "0.1.30"

    # Set maximum version (won't upgrade above this)
    maxVersion: "1.0.0"
```

#### Rollback Settings

```yaml
updateController:
  config:
    rollback:
      # Enable automatic rollback on failure
      enabled: true

      # Wait time before health check after upgrade
      healthCheckDelay: 5m

      # Automatically rollback if health check fails
      autoRollback: true
```

#### Signature Verification

```yaml
updateController:
  config:
    verification:
      # Enable cosign signature verification
      enabled: true

      # GitHub Actions OIDC identity pattern
      cosignIdentityRegexp: "https://github.com/bvboe/b2s-go/*"

      # OIDC issuer for GitHub Actions
      cosignOIDCIssuer: "https://token.actions.githubusercontent.com"
```

### Manual Control

#### Trigger Update Check Immediately

```bash
# Create a one-time Job from the CronJob
kubectl create job --from=cronjob/bjorn2scan-update-controller \
  manual-update-$(date +%s) \
  -n bjorn2scan
```

#### Pause Auto-Updates

```bash
# Suspend the CronJob
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n bjorn2scan
```

#### Resume Auto-Updates

```bash
# Resume the CronJob
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":false}}' \
  -n bjorn2scan
```

### Monitoring

#### View Recent Update Jobs

```bash
# List all update controller jobs
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan

# Get details of most recent job
kubectl describe job \
  $(kubectl get jobs -l app=bjorn2scan-update-controller \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{.items[-1].metadata.name}' \
    -n bjorn2scan) \
  -n bjorn2scan
```

#### View Update Logs

```bash
# View logs from most recent update job
kubectl logs -l job-name=$(kubectl get jobs \
  -l app=bjorn2scan-update-controller \
  --sort-by=.metadata.creationTimestamp \
  -o jsonpath='{.items[-1].metadata.name}' \
  -n bjorn2scan) \
  -n bjorn2scan

# Follow logs from running job
kubectl logs -f -l app=bjorn2scan-update-controller -n bjorn2scan
```

#### Check CronJob Status

```bash
# View CronJob configuration and status
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan -o yaml

# Check if CronJob is suspended
kubectl get cronjob bjorn2scan-update-controller \
  -n bjorn2scan \
  -o jsonpath='{.spec.suspend}'
```

#### View Helm Release History

```bash
# Show upgrade history
helm history bjorn2scan -n bjorn2scan

# Show detailed information about current release
helm get all bjorn2scan -n bjorn2scan
```

---

## Agent Auto-Update

The agent auto-update feature is integrated into the `bjorn2scan-agent` binary and runs as a background goroutine.

### Configuration File

Create or edit `/etc/bjorn2scan/agent.conf` or `./agent.conf`:

```ini
# ============================================================================
# AUTO-UPDATE CONFIGURATION
# ============================================================================

# Enable automatic updates (default: true)
# When enabled, agent will periodically check for new versions and auto-update
auto_update_enabled=true

# Update check interval (default: 1h)
# Format: Go duration string (e.g., "1h", "6h", "24h")
auto_update_check_interval=1h

# Allow automatic minor version updates (default: true)
# Example: 0.1.x → 0.2.x
auto_update_minor_versions=true

# Allow automatic major version updates (default: false)
# Example: 0.x.x → 1.x.x
auto_update_major_versions=false

# Pin to a specific version (default: empty = auto-update)
# When set, only this version will be installed
# Example: auto_update_pinned_version=0.1.35
auto_update_pinned_version=

# Minimum allowed version (default: empty = no minimum)
# Will not downgrade below this version
auto_update_min_version=

# Maximum allowed version (default: empty = no maximum)
# Will not upgrade above this version
auto_update_max_version=

# GitHub repository for updates (default: bvboe/b2s-go)
# Format: owner/repo
update_github_repo=bvboe/b2s-go

# Verify signatures before installing (default: true)
# Verifies the cosign/Sigstore bundle for each downloaded release before installing
update_verify_signatures=true

# Enable automatic rollback on failure (default: true)
# If health check fails after update, automatically rollback to previous version
update_rollback_enabled=true

# Health check timeout after update (default: 60s)
# Format: Go duration string or integer seconds
update_health_check_timeout=60s

# Cosign identity regexp for signature verification
update_cosign_identity_regexp=https://github.com/bvboe/b2s-go/*

# Cosign OIDC issuer for signature verification
update_cosign_oidc_issuer=https://token.actions.githubusercontent.com
```

### Environment Variable Overrides

Configuration can be overridden via environment variables:

```bash
# Enable auto-update via environment
export AUTO_UPDATE_ENABLED=true

# Set check interval
export AUTO_UPDATE_CHECK_INTERVAL=12h

# Pin to specific version
export AUTO_UPDATE_PINNED_VERSION=0.1.35
```

### API Endpoints

The agent exposes HTTP API endpoints for manual control:

#### Get Update Status

```bash
curl http://localhost:9999/api/update/status
```

Response:
```json
{
  "status": "idle",
  "error": "",
  "lastCheck": "2025-12-23T10:30:00Z",
  "lastUpdate": "2025-12-22T02:15:00Z",
  "latestVersion": "0.1.35"
}
```

Status values:
- `idle` - No update in progress
- `checking` - Checking for updates
- `downloading` - Downloading new version
- `verifying` - Verifying signature
- `installing` - Installing new version
- `restarting` - Restarting service
- `failed` - Update failed (check error field)

#### Trigger Update Check

```bash
curl -X POST http://localhost:9999/api/update/trigger
```

Response:
```json
{
  "message": "Update check triggered"
}
```

#### Pause Auto-Updates

```bash
curl -X POST http://localhost:9999/api/update/pause
```

Response:
```json
{
  "message": "Auto-updates paused"
}
```

#### Resume Auto-Updates

```bash
curl -X POST http://localhost:9999/api/update/resume
```

Response:
```json
{
  "message": "Auto-updates resumed"
}
```

### Systemd Integration

The agent integrates with systemd for automatic restart after updates.

#### Check Service Status

```bash
# View agent service status
sudo systemctl status bjorn2scan-agent

# Check if auto-update is enabled
curl http://localhost:9999/api/update/status | jq .
```

#### View Update Logs

```bash
# View agent logs (includes update activity)
sudo journalctl -u bjorn2scan-agent -f

# View logs for specific update
sudo journalctl -u bjorn2scan-agent --since "1 hour ago" | grep -i update

# View agent log file
sudo tail -f /var/log/bjorn2scan/agent.log
```

#### Manual Restart After Failed Update

```bash
# If automatic rollback fails, manually restart with previous version
sudo systemctl restart bjorn2scan-agent
```

---

## Version Policies

### Version Constraints

Version constraints control which updates are automatically applied:

| Policy | Allows | Example | Use Case |
|--------|--------|---------|----------|
| **Patch only** | x.y.z → x.y.z+1 | 0.1.34 → 0.1.35 | Maximum stability |
| **Minor + Patch** | x.y.z → x.y+1.0 | 0.1.34 → 0.2.0 | Recommended default |
| **Major + Minor + Patch** | x.y.z → x+1.0.0 | 0.9.9 → 1.0.0 | Bleeding edge |

#### Examples

**Conservative (patch updates only):**
```yaml
autoUpdateMinor: false
autoUpdateMajor: false
```
- ✅ 0.1.34 → 0.1.35
- ❌ 0.1.34 → 0.2.0
- ❌ 0.9.9 → 1.0.0

**Recommended (minor + patch updates):**
```yaml
autoUpdateMinor: true
autoUpdateMajor: false
```
- ✅ 0.1.34 → 0.1.35
- ✅ 0.1.34 → 0.2.0
- ❌ 0.9.9 → 1.0.0

**Aggressive (all updates):**
```yaml
autoUpdateMinor: true
autoUpdateMajor: true
```
- ✅ 0.1.34 → 0.1.35
- ✅ 0.1.34 → 0.2.0
- ✅ 0.9.9 → 1.0.0

### Version Pinning

Pin to a specific version to disable auto-update or control exact version:

**Kubernetes:**
```yaml
updateController:
  config:
    pinnedVersion: "0.1.35"
```

**Agent:**
```ini
auto_update_pinned_version=0.1.35
```

**Behavior:**
- Current version < pinned version → **Upgrade** to pinned version
- Current version = pinned version → **No update** (stay at pinned version)
- Current version > pinned version → **No downgrade** (stay at current)

**Use cases:**
- Test a specific version in staging before production
- Maintain consistent versions across environments
- Temporarily freeze updates during critical operations

### Min/Max Bounds

Set version boundaries to control update range:

**Kubernetes:**
```yaml
updateController:
  config:
    minVersion: "0.1.30"
    maxVersion: "0.2.0"
```

**Agent:**
```ini
auto_update_min_version=0.1.30
auto_update_max_version=0.2.0
```

**Behavior:**
- Won't downgrade below `minVersion`
- Won't upgrade above `maxVersion`
- Useful for gradual rollout strategies

**Example scenarios:**

1. **Gradual rollout:**
   - Production: `maxVersion: "0.1.50"` (stay on 0.1.x)
   - Staging: `maxVersion: "0.2.0"` (test 0.2.x)
   - Dev: No max (latest always)

2. **Prevent downgrades:**
   - Set `minVersion` to current version
   - Ensures only upgrades, never downgrades

---

## Signature Verification

All release artifacts are signed with [cosign](https://github.com/sigstore/cosign) using GitHub Actions OIDC.

### Kubernetes (Ready)

Signature verification is **ready and available** for Kubernetes deployments:

```yaml
updateController:
  config:
    verification:
      enabled: true
      cosignIdentityRegexp: "https://github.com/bvboe/b2s-go/*"
      cosignOIDCIssuer: "https://token.actions.githubusercontent.com"
```

The update controller will:
1. Download the Helm chart OCI artifact
2. Verify the signature using cosign
3. Reject installation if signature verification fails

### Agent (Planned)

Signature verification is **implemented but not yet enabled** for agent updates:

```ini
# TODO: Enable when cosign verification is fully tested
update_verify_signatures=false
```

Once enabled, the agent will:
1. Download binary, signature (.sig), and certificate (.cert)
2. Verify SHA256 checksum
3. Verify cosign signature
4. Reject installation if verification fails

### Manual Verification

You can manually verify signatures for any release:

**Helm Chart:**
```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/bvboe/b2s-go/bjorn2scan:0.1.35
```

**Agent Binary:**
```bash
# Download binary, signature, and certificate from GitHub Release
# Then verify:
cosign verify-blob bjorn2scan-agent-linux-amd64.tar.gz \
  --certificate bjorn2scan-agent-linux-amd64.tar.gz.cert \
  --signature bjorn2scan-agent-linux-amd64.tar.gz.sig \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

---

## Rollback Protection

Both Kubernetes and Agent update mechanisms include automatic rollback:

### How It Works

1. **Pre-Update Backup**
   - Kubernetes: Helm stores release history automatically
   - Agent: Creates backup of current binary at `/tmp/bjorn2scan-agent.backup`

2. **Update Application**
   - Kubernetes: `helm upgrade` with new chart version
   - Agent: Atomic binary replacement using `os.Rename()`

3. **Health Check**
   - Kubernetes: Waits 5 minutes, checks pod readiness and health endpoint
   - Agent: Restarts service, waits 60s, checks `/health` endpoint

4. **Automatic Rollback**
   - If health check fails: automatically rollback and restart
   - Kubernetes: `helm rollback` to previous revision
   - Agent: Restore backup binary and restart service

### Configuration

**Kubernetes:**
```yaml
updateController:
  config:
    rollback:
      enabled: true
      healthCheckDelay: 5m
      autoRollback: true
```

**Agent:**
```ini
update_rollback_enabled=true
update_health_check_timeout=60s
```

### Manual Rollback

If automatic rollback fails or you need to rollback manually:

**Kubernetes:**
```bash
# View release history
helm history bjorn2scan -n bjorn2scan

# Rollback to previous version
helm rollback bjorn2scan -n bjorn2scan

# Rollback to specific revision
helm rollback bjorn2scan 3 -n bjorn2scan
```

**Agent:**
```bash
# Check if backup exists
ls -la /tmp/bjorn2scan-agent.backup

# Manually restore backup
sudo cp /tmp/bjorn2scan-agent.backup /usr/local/bin/bjorn2scan-agent
sudo chmod +x /usr/local/bin/bjorn2scan-agent
sudo systemctl restart bjorn2scan-agent

# Verify health
curl http://localhost:9999/health
```

---

## Troubleshooting

### Kubernetes

#### Update Job Keeps Failing

**Check job logs:**
```bash
kubectl logs -l app=bjorn2scan-update-controller -n bjorn2scan --tail=100
```

**Common issues:**
- RBAC permissions: Ensure ClusterRole has necessary permissions
- Network issues: Check if cluster can reach GHCR
- Signature verification failure: Check cosign configuration
- Helm upgrade conflicts: Check for manual changes to release

**Solution:**
```bash
# Check ClusterRole
kubectl get clusterrole bjorn2scan-update-controller -o yaml

# Test GHCR connectivity
kubectl run test --rm -it --image=alpine -- \
  wget -O- https://ghcr.io/v2/

# View detailed job events
kubectl describe job <job-name> -n bjorn2scan
```

#### CronJob Not Running

**Check schedule syntax:**
```bash
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan \
  -o jsonpath='{.spec.schedule}'
```

**Check if suspended:**
```bash
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan \
  -o jsonpath='{.spec.suspend}'
```

**Solution:**
```bash
# Fix schedule (if invalid)
kubectl patch cronjob bjorn2scan-update-controller -n bjorn2scan \
  -p '{"spec":{"schedule":"0 2 * * *"}}'

# Resume if suspended
kubectl patch cronjob bjorn2scan-update-controller -n bjorn2scan \
  -p '{"spec":{"suspend":false}}'
```

#### Update Applied But Pods Still Old Version

**Check Helm release vs running pods:**
```bash
# Check Helm chart version
helm list -n bjorn2scan

# Check pod image versions
kubectl get pods -n bjorn2scan \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'
```

**Solution:**
```bash
# Force pod rollout
kubectl rollout restart deployment/bjorn2scan-scan-server -n bjorn2scan
kubectl rollout restart daemonset/bjorn2scan-pod-scanner -n bjorn2scan
```

### Agent

#### Auto-Update Not Working

**Check configuration:**
```bash
# Verify auto-update is enabled
grep auto_update_enabled /etc/bjorn2scan/agent.conf

# Check status via API
curl http://localhost:9999/api/update/status
```

**Check logs:**
```bash
# View update activity
sudo journalctl -u bjorn2scan-agent -f | grep -i update

# Check for errors
sudo grep -i "update\|error" /var/log/bjorn2scan/agent.log | tail -20
```

**Common issues:**
- Config file not loaded: Check path `/etc/bjorn2scan/agent.conf`
- Network issues: Agent can't reach GitHub API
- Version constraints: Current version doesn't match update policy
- Paused: Updates were manually paused

**Solution:**
```bash
# Manually trigger update
curl -X POST http://localhost:9999/api/update/trigger

# Check if paused and resume
curl -X POST http://localhost:9999/api/update/resume

# Verify network connectivity
curl -I https://api.github.com/repos/bvboe/b2s-go/releases/latest
```

#### Update Downloaded But Not Applied

**Check rollback marker:**
```bash
# If rollback marker exists, update failed health check
ls -la /tmp/bjorn2scan-agent.rollback-*
```

**Check permissions:**
```bash
# Verify agent can write to binary location
ls -la /usr/local/bin/bjorn2scan-agent
```

**Solution:**
```bash
# Remove old rollback markers
sudo rm /tmp/bjorn2scan-agent.rollback-*

# Ensure correct permissions
sudo chown root:root /usr/local/bin/bjorn2scan-agent
sudo chmod 755 /usr/local/bin/bjorn2scan-agent

# Trigger update again
curl -X POST http://localhost:9999/api/update/trigger
```

#### Agent Won't Restart After Update

**Check systemd service:**
```bash
# View service status
sudo systemctl status bjorn2scan-agent

# Check for errors
sudo journalctl -u bjorn2scan-agent -n 50
```

**Solution:**
```bash
# Manually restore backup if exists
if [ -f /tmp/bjorn2scan-agent.backup ]; then
  sudo cp /tmp/bjorn2scan-agent.backup /usr/local/bin/bjorn2scan-agent
  sudo chmod +x /usr/local/bin/bjorn2scan-agent
fi

# Restart service
sudo systemctl restart bjorn2scan-agent

# Check health
curl http://localhost:9999/health
```

---

## Best Practices

### Production Deployments

1. **Test in Staging First**
   - Enable auto-update in staging before production
   - Monitor for 1-2 weeks to catch issues
   - Use version pinning to control promotion

2. **Use Conservative Version Policies**
   - Start with `autoUpdateMinor: true, autoUpdateMajor: false`
   - Only enable major updates after testing
   - Consider pinning for critical production systems

3. **Schedule Updates During Low Traffic**
   - Kubernetes: Schedule CronJob during maintenance window
   - Agent: Set check interval to run during off-peak hours

4. **Monitor Update Activity**
   - Set up alerts for failed update jobs/services
   - Review logs regularly
   - Track version drift across environments

5. **Enable Signature Verification**
   - Always enable for production
   - Protects against supply chain attacks
   - Ensures authenticity of updates

### Multi-Environment Strategy

```yaml
# Development
autoUpdateMinor: true
autoUpdateMajor: true
schedule: "@hourly"  # Get updates quickly

# Staging
autoUpdateMinor: true
autoUpdateMajor: false
schedule: "0 2 * * *"  # Daily at 2am

# Production
pinnedVersion: "0.1.35"  # Manual control
# OR
autoUpdateMinor: true
autoUpdateMajor: false
schedule: "0 2 * * 0"  # Weekly on Sunday
maxVersion: "0.2.0"  # Cap at tested version
```

### Disaster Recovery

1. **Always Keep Backups**
   - Helm: Automatic release history
   - Agent: Backup created automatically at `/tmp/bjorn2scan-agent.backup`

2. **Document Rollback Procedures**
   - Include in runbooks
   - Test rollback process regularly
   - Ensure team knows how to perform manual rollback

3. **Set Version Bounds**
   - Use `minVersion` to prevent accidental downgrades
   - Use `maxVersion` to limit blast radius

4. **Gradual Rollout**
   - Update a small percentage of agents first
   - Use version pinning to control rollout speed
   - Monitor metrics before updating remaining agents

### Security Considerations

1. **Signature Verification**
   - Enable for all production deployments
   - Verify cosign configuration is correct
   - Test verification with known good/bad artifacts

2. **Network Security**
   - Ensure agents/cluster can reach GHCR and GitHub
   - Use private registries if required
   - Configure firewall rules appropriately

3. **RBAC (Kubernetes)**
   - Review ClusterRole permissions
   - Use least-privilege principle
   - Audit update controller access regularly

4. **Audit Logging**
   - Enable audit logs for all updates
   - Monitor for unexpected updates
   - Alert on update failures

### Monitoring and Alerting

Set up monitoring for:

- ✅ Update job/service failures
- ✅ Version drift between environments
- ✅ Failed health checks after updates
- ✅ Rollback events
- ✅ Signature verification failures

Example Prometheus alert:

```yaml
- alert: Bjorn2ScanUpdateFailed
  expr: kube_job_status_failed{job_name=~"bjorn2scan-update-controller.*"} > 0
  for: 5m
  annotations:
    summary: "Bjørn2Scan auto-update failed"
    description: "Update job {{ $labels.job_name }} failed"
```

---

## Support

For issues or questions:

- **GitHub Issues**: https://github.com/bvboe/b2s-go/issues
- **Documentation**: https://github.com/bvboe/b2s-go/tree/main/docs
- **Runbooks**: See [RUNBOOKS.md](./RUNBOOKS.md) for operational procedures

