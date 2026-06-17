# Bjørn2Scan Auto-Update Operational Runbooks

This document provides step-by-step operational procedures for managing the Bjørn2Scan auto-update feature in production environments.

## Table of Contents

- [Emergency Procedures](#emergency-procedures)
  - [Disable Auto-Updates Immediately](#disable-auto-updates-immediately)
  - [Emergency Rollback](#emergency-rollback)
  - [Stop In-Progress Update](#stop-in-progress-update)
- [Routine Operations](#routine-operations)
  - [Enable Auto-Updates](#enable-auto-updates)
  - [Update Version Constraints](#update-version-constraints)
  - [Pin to Specific Version](#pin-to-specific-version)
  - [Schedule Maintenance Window Update](#schedule-maintenance-window-update)
- [Monitoring and Health Checks](#monitoring-and-health-checks)
  - [Check Update Status](#check-update-status)
  - [Verify Version Consistency](#verify-version-consistency)
  - [Monitor Update History](#monitor-update-history)
- [Incident Response](#incident-response)
  - [Failed Update Recovery](#failed-update-recovery)
  - [Version Mismatch Resolution](#version-mismatch-resolution)
  - [Update Loop Prevention](#update-loop-prevention)
- [Planned Maintenance](#planned-maintenance)
  - [Controlled Version Upgrade](#controlled-version-upgrade)
  - [Multi-Environment Rollout](#multi-environment-rollout)
  - [Testing New Versions](#testing-new-versions)
- [Disaster Recovery](#disaster-recovery)
  - [Complete System Rollback](#complete-system-rollback)
  - [Restore from Backup](#restore-from-backup)
  - [Rebuild After Failure](#rebuild-after-failure)
- [Advanced Procedures](#advanced-procedures)
  - [Manual Chart/Binary Installation](#manual-chartbinary-installation)
  - [Signature Verification Troubleshooting](#signature-verification-troubleshooting)
  - [Custom Update Schedule](#custom-update-schedule)

---

## Emergency Procedures

### Disable Auto-Updates Immediately

**When to use:** Production issue detected, need to freeze versions immediately.

**Time to complete:** < 2 minutes

#### Kubernetes

```bash
# Step 1: Suspend the CronJob immediately
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n bjorn2scan

# Step 2: Verify suspension
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan \
  -o jsonpath='{.spec.suspend}'
# Expected output: true

# Step 3: Kill any running update jobs
kubectl delete jobs -l app=bjorn2scan-update-controller -n bjorn2scan

# Step 4: Verify no jobs are running
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan
# Expected output: No resources found
```

**Verification:**
```bash
# Ensure CronJob shows as suspended
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan
# STATUS should show: Suspended
```

#### Agent

```bash
# Step 1: Pause auto-updates via API on all agents
for host in agent1 agent2 agent3; do
  curl -X POST http://$host:9999/api/update/pause
done

# Step 2: Verify pause status
for host in agent1 agent2 agent3; do
  echo "=== $host ==="
  curl -s http://$host:9999/api/update/status | jq -r '.status'
done

# Step 3: If API unavailable, disable via config
# On each agent:
sudo sed -i 's/auto_update_enabled=true/auto_update_enabled=false/' \
  /etc/bjorn2scan/agent.conf

sudo systemctl restart bjorn2scan-agent
```

**Verification:**
```bash
# Check each agent status
curl http://agent1:9999/api/update/status | jq .
# status should be "idle" with no recent activity
```

---

### Emergency Rollback

**When to use:** Bad update detected in production, immediate rollback required.

**Time to complete:** 5-10 minutes

#### Kubernetes

```bash
# Step 1: Disable auto-updates
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n bjorn2scan

# Step 2: View release history
helm history bjorn2scan -n bjorn2scan
# Note the REVISION number of the last good version

# Step 3: Rollback to previous version
helm rollback bjorn2scan -n bjorn2scan

# OR rollback to specific revision:
helm rollback bjorn2scan <REVISION> -n bjorn2scan

# Step 4: Wait for rollout to complete
kubectl rollout status deployment/bjorn2scan-scan-server -n bjorn2scan
kubectl rollout status daemonset/bjorn2scan-pod-scanner -n bjorn2scan

# Step 5: Verify health
kubectl get pods -n bjorn2scan
curl http://<scan-server-url>/health
```

**Verification:**
```bash
# Check current version
helm list -n bjorn2scan

# Verify all pods are running
kubectl get pods -n bjorn2scan -o wide

# Check application health
kubectl get pods -n bjorn2scan \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\n"}{end}'
# All should show: Running
```

#### Agent

```bash
# Step 1: Check if backup exists
ssh agent1 'ls -la /tmp/bjorn2scan-agent.backup'

# Step 2: Restore backup on all agents
for host in agent1 agent2 agent3; do
  echo "=== Rolling back $host ==="
  ssh $host 'sudo cp /tmp/bjorn2scan-agent.backup /usr/local/bin/bjorn2scan-agent'
  ssh $host 'sudo chmod +x /usr/local/bin/bjorn2scan-agent'
  ssh $host 'sudo systemctl restart bjorn2scan-agent'
done

# Step 3: Wait for services to start (30 seconds)
sleep 30

# Step 4: Verify health on all agents
for host in agent1 agent2 agent3; do
  echo "=== $host ==="
  curl -s http://$host:9999/health | jq .
  curl -s http://$host:9999/info | jq -r '.version'
done
```

**Verification:**
```bash
# Ensure all agents are healthy and running previous version
for host in agent1 agent2 agent3; do
  echo "$host: $(curl -s http://$host:9999/info | jq -r '.version')"
done
```

**Post-Rollback Actions:**
1. Document the issue in incident report
2. Notify development team
3. Pin version to prevent auto-update until issue resolved
4. Schedule post-mortem

---

### Stop In-Progress Update

**When to use:** Update is failing or causing issues during installation.

**Time to complete:** 2-5 minutes

#### Kubernetes

```bash
# Step 1: Identify running update job
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan

# Step 2: Delete the job (stops update)
kubectl delete job <job-name> -n bjorn2scan

# Step 3: Verify Helm release state
helm list -n bjorn2scan
# Check STATUS - should show: deployed (previous version)

# Step 4: If Helm is in pending state, rollback
if [ "$(helm list -n bjorn2scan -o json | jq -r '.[0].status')" = "pending-upgrade" ]; then
  helm rollback bjorn2scan -n bjorn2scan
fi

# Step 5: Suspend CronJob to prevent retry
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n bjorn2scan
```

**Verification:**
```bash
# Ensure Helm release is in deployed state
helm list -n bjorn2scan -o json | jq -r '.[0].status'
# Expected: deployed

# Verify pods are stable
kubectl get pods -n bjorn2scan
```

#### Agent

```bash
# Step 1: Check current update status
curl http://agent1:9999/api/update/status

# Step 2: If update is in progress, restart service to abort
ssh agent1 'sudo systemctl restart bjorn2scan-agent'

# Step 3: Verify service recovered with previous version
curl http://agent1:9999/info | jq -r '.version'

# Step 4: Pause updates to prevent retry
curl -X POST http://agent1:9999/api/update/pause
```

**Verification:**
```bash
# Ensure agent is running and healthy
curl http://agent1:9999/health
curl http://agent1:9999/api/update/status | jq .
# status should be "idle"
```

---

## Routine Operations

### Enable Auto-Updates

**When to use:** Initial setup or re-enabling after maintenance.

**Time to complete:** 5 minutes

#### Kubernetes

```bash
# Step 1: Configure update schedule and policies
cat <<EOF > update-config.yaml
updateController:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2am UTC
  config:
    autoUpdateMinor: true
    autoUpdateMajor: false
    rollback:
      enabled: true
      autoRollback: true
    verification:
      enabled: true
EOF

# Step 2: Apply configuration
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n bjorn2scan \
  -f update-config.yaml

# Step 3: Verify CronJob is created and active
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan

# Step 4: Check next scheduled run
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan \
  -o jsonpath='{.status.lastScheduleTime}{"\n"}'
```

**Verification:**
```bash
# Verify CronJob configuration
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan -o yaml

# Ensure not suspended
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan \
  -o jsonpath='{.spec.suspend}'
# Expected: false or <empty>
```

#### Agent

```bash
# Step 1: Update configuration file on all agents
for host in agent1 agent2 agent3; do
  ssh $host 'sudo tee -a /etc/bjorn2scan/agent.conf > /dev/null <<EOF
auto_update_enabled=true
auto_update_check_interval=6h
auto_update_minor_versions=true
auto_update_major_versions=false
update_rollback_enabled=true
EOF'
done

# Step 2: Restart agents to pick up config
for host in agent1 agent2 agent3; do
  ssh $host 'sudo systemctl restart bjorn2scan-agent'
done

# Step 3: Verify auto-update is enabled
for host in agent1 agent2 agent3; do
  echo "=== $host ==="
  curl -s http://$host:9999/api/update/status | jq -r '.status'
done
```

**Verification:**
```bash
# Check update status on all agents
for host in agent1 agent2 agent3; do
  echo "$host: $(curl -s http://$host:9999/api/update/status | jq -r '.lastCheck')"
done
# Should show recent check times
```

---

### Update Version Constraints

**When to use:** Change update policy (e.g., allow major updates).

**Time to complete:** 5 minutes

#### Kubernetes

```bash
# Step 1: Create values file with new constraints
cat <<EOF > version-constraints.yaml
updateController:
  config:
    autoUpdateMinor: true
    autoUpdateMajor: true  # Now allowing major updates
    minVersion: "0.1.30"
    maxVersion: "2.0.0"
EOF

# Step 2: Apply changes
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n bjorn2scan \
  -f version-constraints.yaml \
  --reuse-values

# Step 3: Verify ConfigMap updated
kubectl get configmap bjorn2scan-update-controller -n bjorn2scan \
  -o yaml | grep -A 5 "autoUpdateMajor"
```

**Verification:**
```bash
# Check ConfigMap contains new values
kubectl get configmap bjorn2scan-update-controller -n bjorn2scan -o yaml
```

#### Agent

```bash
# Step 1: Update configuration on all agents
for host in agent1 agent2 agent3; do
  ssh $host 'sudo sed -i "s/auto_update_major_versions=false/auto_update_major_versions=true/" /etc/bjorn2scan/agent.conf'
done

# Step 2: Restart agents (config reloads automatically, but restart ensures immediate pickup)
for host in agent1 agent2 agent3; do
  ssh $host 'sudo systemctl restart bjorn2scan-agent'
done
```

**Verification:**
```bash
# Verify configuration on agents
for host in agent1 agent2 agent3; do
  echo "=== $host ==="
  ssh $host 'grep auto_update_major /etc/bjorn2scan/agent.conf'
done
```

---

### Pin to Specific Version

**When to use:** Testing specific version, preventing updates during critical period.

**Time to complete:** 5 minutes

#### Kubernetes

```bash
# Step 1: Pin to specific version
cat <<EOF > pinned-version.yaml
updateController:
  config:
    pinnedVersion: "0.1.35"
EOF

# Step 2: Apply configuration
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n bjorn2scan \
  -f pinned-version.yaml \
  --reuse-values

# Step 3: Trigger immediate update check to apply pinned version
kubectl create job --from=cronjob/bjorn2scan-update-controller \
  pin-to-version-$(date +%s) \
  -n bjorn2scan

# Step 4: Monitor job completion
kubectl wait --for=condition=complete --timeout=300s \
  job/pin-to-version-* -n bjorn2scan
```

**Verification:**
```bash
# Verify Helm chart version
helm list -n bjorn2scan

# Check if version matches pinned version
helm list -n bjorn2scan -o json | jq -r '.[0].chart'
# Should show: bjorn2scan-0.1.35
```

#### Agent

```bash
# Step 1: Set pinned version on all agents
for host in agent1 agent2 agent3; do
  ssh $host 'echo "auto_update_pinned_version=0.1.35" | sudo tee -a /etc/bjorn2scan/agent.conf'
done

# Step 2: Trigger update check to apply pinned version
for host in agent1 agent2 agent3; do
  curl -X POST http://$host:9999/api/update/trigger
done

# Step 3: Wait for updates to complete (5 minutes)
sleep 300

# Step 4: Verify versions
for host in agent1 agent2 agent3; do
  echo "$host: $(curl -s http://$host:9999/info | jq -r '.version')"
done
```

**Verification:**
```bash
# All agents should show pinned version
for host in agent1 agent2 agent3; do
  version=$(curl -s http://$host:9999/info | jq -r '.version')
  if [ "$version" = "0.1.35" ]; then
    echo "$host: OK ($version)"
  else
    echo "$host: MISMATCH ($version)"
  fi
done
```

---

### Schedule Maintenance Window Update

**When to use:** Perform controlled update during scheduled maintenance.

**Time to complete:** 30-60 minutes

#### Pre-Maintenance Checklist

```bash
# 1. Document current versions
helm list -n bjorn2scan > pre-update-versions.txt
kubectl get pods -n bjorn2scan -o wide >> pre-update-versions.txt

# 2. Backup current configuration
helm get values bjorn2scan -n bjorn2scan > pre-update-values.yaml

# 3. Verify backups are available
helm history bjorn2scan -n bjorn2scan

# 4. Check cluster health
kubectl get nodes
kubectl get pods --all-namespaces | grep -v Running

# 5. Notify team maintenance is starting
echo "Maintenance window started at $(date)" | tee maintenance.log
```

#### Kubernetes Update Procedure

```bash
# Step 1: Suspend auto-updates during manual process
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n bjorn2scan

# Step 2: Trigger manual update
kubectl create job --from=cronjob/bjorn2scan-update-controller \
  maintenance-update-$(date +%s) \
  -n bjorn2scan

# Step 3: Monitor update progress
kubectl logs -f -l app=bjorn2scan-update-controller -n bjorn2scan

# Step 4: Wait for rollout to complete
kubectl rollout status deployment/bjorn2scan-scan-server -n bjorn2scan
kubectl rollout status daemonset/bjorn2scan-pod-scanner -n bjorn2scan

# Step 5: Verify health
kubectl get pods -n bjorn2scan
for pod in $(kubectl get pods -n bjorn2scan -o name); do
  kubectl exec $pod -n bjorn2scan -- curl -s http://localhost:8080/health
done

# Step 6: Resume auto-updates
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":false}}' \
  -n bjorn2scan
```

#### Post-Maintenance Verification

```bash
# 1. Document new versions
helm list -n bjorn2scan > post-update-versions.txt

# 2. Compare versions
diff pre-update-versions.txt post-update-versions.txt

# 3. Run smoke tests
curl http://<scan-server-url>/health
curl http://<scan-server-url>/info

# 4. Check for errors in logs
kubectl logs --tail=100 -l app.kubernetes.io/name=bjorn2scan -n bjorn2scan | grep -i error

# 5. Verify scanning functionality
# Trigger a test scan and verify results

# 6. Document completion
echo "Maintenance window completed at $(date)" | tee -a maintenance.log
```

---

## Monitoring and Health Checks

### Check Update Status

**Frequency:** Daily or after each update window

#### Kubernetes

```bash
#!/bin/bash
# check-k8s-update-status.sh

echo "=== Bjørn2Scan Update Status ==="
echo "Date: $(date)"
echo ""

# Check CronJob status
echo "--- CronJob Status ---"
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan

# Check recent jobs
echo ""
echo "--- Recent Update Jobs ---"
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan \
  --sort-by=.metadata.creationTimestamp

# Check last successful update
echo ""
echo "--- Last Successful Update ---"
last_job=$(kubectl get jobs -l app=bjorn2scan-update-controller \
  --sort-by=.metadata.creationTimestamp \
  -o jsonpath='{.items[-1].metadata.name}' \
  -n bjorn2scan)

if [ -n "$last_job" ]; then
  kubectl get job $last_job -n bjorn2scan \
    -o jsonpath='Job: {.metadata.name}\nStatus: {.status.succeeded}/{.status.failed}\nStarted: {.status.startTime}\nCompleted: {.status.completionTime}\n'
fi

# Check current Helm release
echo ""
echo "--- Current Release ---"
helm list -n bjorn2scan

# Check for failed jobs
echo ""
echo "--- Failed Jobs (last 7 days) ---"
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan \
  --field-selector status.successful=0 \
  | grep -v "0/1"
```

**Save and run:**
```bash
chmod +x check-k8s-update-status.sh
./check-k8s-update-status.sh
```

#### Agent

```bash
#!/bin/bash
# check-agent-update-status.sh

echo "=== Bjørn2Scan Agent Update Status ==="
echo "Date: $(date)"
echo ""

AGENTS=("agent1:9999" "agent2:9999" "agent3:9999")

for agent in "${AGENTS[@]}"; do
  echo "--- $agent ---"

  # Get version
  version=$(curl -s http://$agent/info | jq -r '.version')
  echo "Version: $version"

  # Get update status
  status=$(curl -s http://$agent/api/update/status)
  echo "Status: $(echo $status | jq -r '.status')"
  echo "Last Check: $(echo $status | jq -r '.lastCheck')"
  echo "Last Update: $(echo $status | jq -r '.lastUpdate')"
  echo "Latest Available: $(echo $status | jq -r '.latestVersion')"

  if [ "$(echo $status | jq -r '.error')" != "" ]; then
    echo "ERROR: $(echo $status | jq -r '.error')"
  fi

  echo ""
done
```

**Save and run:**
```bash
chmod +x check-agent-update-status.sh
./check-agent-update-status.sh
```

---

### Verify Version Consistency

**Frequency:** Daily

```bash
#!/bin/bash
# verify-version-consistency.sh

echo "=== Version Consistency Check ==="
echo "Date: $(date)"
echo ""

# Expected version (from Helm)
k8s_version=$(helm list -n bjorn2scan -o json | jq -r '.[0].chart' | sed 's/bjorn2scan-//')
echo "Kubernetes Chart Version: $k8s_version"

# Check all pod versions
echo ""
echo "--- Pod Versions ---"
kubectl get pods -n bjorn2scan \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' \
  | awk -F: '{print $1"\t"$NF}'

# Check agent versions
echo ""
echo "--- Agent Versions ---"
AGENTS=("agent1:9999" "agent2:9999" "agent3:9999")
for agent in "${AGENTS[@]}"; do
  version=$(curl -s http://$agent/info 2>/dev/null | jq -r '.version // "UNREACHABLE"')
  echo "$agent: $version"
done

# Summary
echo ""
echo "--- Version Drift Detection ---"
# Add logic to detect version mismatches
```

---

### Monitor Update History

**Frequency:** Weekly

```bash
#!/bin/bash
# update-history-report.sh

echo "=== Update History Report ==="
echo "Period: Last 7 days"
echo "Date: $(date)"
echo ""

# Kubernetes update history
echo "--- Kubernetes Updates ---"
helm history bjorn2scan -n bjorn2scan --max 10

echo ""
echo "--- Update Jobs (last 7 days) ---"
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan \
  --sort-by=.status.startTime \
  | awk 'NR==1 || $3>0'  # Show header and successful jobs

# Failed updates
echo ""
echo "--- Failed Updates ---"
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan \
  --field-selector status.successful=0

# Agent update history (from logs)
echo ""
echo "--- Agent Update Activity ---"
for host in agent1 agent2 agent3; do
  echo "=== $host ==="
  ssh $host 'sudo journalctl -u bjorn2scan-agent --since "7 days ago" | grep -i "update\|upgrade" | tail -10'
  echo ""
done
```

---

## Incident Response

### Failed Update Recovery

**Severity:** High
**Response Time:** 15 minutes

#### Symptoms
- Update job shows failed status
- Pods in CrashLoopBackOff
- Health checks failing
- Version mismatch after update

#### Investigation Steps

```bash
# Step 1: Check update job logs
kubectl logs -l app=bjorn2scan-update-controller -n bjorn2scan --tail=100

# Step 2: Check Helm release status
helm list -n bjorn2scan -o json | jq -r '.[0].status'

# Step 3: Check pod status and events
kubectl get pods -n bjorn2scan
kubectl describe pods -n bjorn2scan | grep -A 5 "Events:"

# Step 4: Check recent Helm releases
helm history bjorn2scan -n bjorn2scan
```

#### Recovery Procedure

```bash
# If Helm release is in failed state:

# Option A: Rollback to previous version
helm rollback bjorn2scan -n bjorn2scan
kubectl rollout status deployment/bjorn2scan-scan-server -n bjorn2scan

# Option B: If rollback fails, force delete and reinstall
helm uninstall bjorn2scan -n bjorn2scan
helm install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n bjorn2scan \
  --version <last-known-good-version> \
  -f saved-values.yaml

# Disable auto-updates until issue resolved
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n bjorn2scan
```

#### Post-Incident

```bash
# 1. Document the incident
cat <<EOF > incident-report.md
## Update Failure Incident

**Date:** $(date)
**Affected Version:** <version>
**Root Cause:** <describe>
**Resolution:** <describe>
**Action Items:**
- [ ] Review update logs
- [ ] Update version constraints
- [ ] Test in staging first
- [ ] Create ticket for dev team
EOF

# 2. Collect logs for analysis
kubectl logs -l app=bjorn2scan-update-controller -n bjorn2scan > update-failure-logs.txt
helm history bjorn2scan -n bjorn2scan >> update-failure-logs.txt

# 3. Re-enable updates with pinned version
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":false}}' \
  -n bjorn2scan
```

---

### Version Mismatch Resolution

**Severity:** Medium
**Response Time:** 30 minutes

#### Symptoms
- Different versions across pods/agents
- Some components updated, others not
- Helm chart version doesn't match pod images

#### Investigation

```bash
# Check Helm chart version
helm list -n bjorn2scan

# Check actual pod images
kubectl get pods -n bjorn2scan \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'

# Check agent versions
for host in agent1 agent2 agent3; do
  echo "$host: $(curl -s http://$host:9999/info | jq -r '.version')"
done
```

#### Resolution

```bash
# Step 1: Force pod recreation to pick up correct images
kubectl rollout restart deployment/bjorn2scan-scan-server -n bjorn2scan
kubectl rollout restart daemonset/bjorn2scan-pod-scanner -n bjorn2scan

# Step 2: Wait for rollout
kubectl rollout status deployment/bjorn2scan-scan-server -n bjorn2scan
kubectl rollout status daemonset/bjorn2scan-pod-scanner -n bjorn2scan

# Step 3: If agents have wrong version, trigger update
for host in agent1 agent2 agent3; do
  curl -X POST http://$host:9999/api/update/trigger
done

# Step 4: Verify consistency
./verify-version-consistency.sh
```

---

### Update Loop Prevention

**Severity:** Low
**Response Time:** As soon as detected

#### Symptoms
- Update controller runs continuously
- Same version being installed repeatedly
- Job history shows many recent runs

#### Investigation

```bash
# Check job frequency
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan \
  --sort-by=.status.startTime

# Check CronJob schedule
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan \
  -o jsonpath='{.spec.schedule}'

# Check ConfigMap for version constraints
kubectl get configmap bjorn2scan-update-controller -n bjorn2scan -o yaml
```

#### Resolution

```bash
# Step 1: Suspend CronJob
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n bjorn2scan

# Step 2: Delete recent jobs
kubectl delete jobs -l app=bjorn2scan-update-controller -n bjorn2scan

# Step 3: Fix version constraints (example: pin current version)
current_version=$(helm list -n bjorn2scan -o json | jq -r '.[0].chart' | sed 's/bjorn2scan-//')

cat <<EOF > fix-loop.yaml
updateController:
  config:
    pinnedVersion: "$current_version"
EOF

helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n bjorn2scan \
  -f fix-loop.yaml \
  --reuse-values

# Step 4: Resume CronJob
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":false}}' \
  -n bjorn2scan
```

---

## Planned Maintenance

### Controlled Version Upgrade

**Use case:** Upgrade to specific version in controlled manner

```bash
#!/bin/bash
# controlled-upgrade.sh

TARGET_VERSION="0.1.36"
NAMESPACE="bjorn2scan"

echo "=== Controlled Upgrade to $TARGET_VERSION ==="

# Pre-upgrade
echo "Step 1: Backing up current configuration..."
helm get values bjorn2scan -n $NAMESPACE > backup-values-$(date +%Y%m%d-%H%M%S).yaml

echo "Step 2: Current version:"
helm list -n $NAMESPACE

# Upgrade
echo "Step 3: Suspending auto-updates..."
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n $NAMESPACE

echo "Step 4: Upgrading to $TARGET_VERSION..."
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --version $TARGET_VERSION \
  -n $NAMESPACE \
  --reuse-values \
  --wait \
  --timeout 10m

# Verification
echo "Step 5: Verifying upgrade..."
helm list -n $NAMESPACE

echo "Step 6: Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=bjorn2scan \
  -n $NAMESPACE \
  --timeout=300s

echo "Step 7: Health check..."
# Add your health check commands here

echo "Step 8: Pinning to $TARGET_VERSION..."
cat <<EOF > pin-version.yaml
updateController:
  config:
    pinnedVersion: "$TARGET_VERSION"
EOF

helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n $NAMESPACE \
  -f pin-version.yaml \
  --reuse-values

echo "Step 9: Resuming auto-updates..."
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":false}}' \
  -n $NAMESPACE

echo "=== Upgrade Complete ==="
```

---

### Multi-Environment Rollout

**Use case:** Controlled rollout across dev → staging → production

```bash
#!/bin/bash
# multi-env-rollout.sh

VERSION="0.1.36"

# Stage 1: Development
echo "=== Stage 1: Development Environment ==="
kubectl config use-context dev-cluster
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --version $VERSION \
  -n bjorn2scan \
  --reuse-values

echo "Waiting 5 minutes for smoke testing..."
sleep 300

echo "Running dev smoke tests..."
# Add smoke test commands

read -p "Dev tests passed? Proceed to staging? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Rollout aborted"
  exit 1
fi

# Stage 2: Staging
echo "=== Stage 2: Staging Environment ==="
kubectl config use-context staging-cluster
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --version $VERSION \
  -n bjorn2scan \
  --reuse-values

echo "Waiting 1 hour for comprehensive testing..."
sleep 3600

echo "Running staging tests..."
# Add comprehensive test commands

read -p "Staging tests passed? Proceed to production? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Rollout aborted"
  exit 1
fi

# Stage 3: Production
echo "=== Stage 3: Production Environment ==="
kubectl config use-context prod-cluster

echo "Creating backup..."
helm get values bjorn2scan -n bjorn2scan > prod-backup-$(date +%Y%m%d).yaml

helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --version $VERSION \
  -n bjorn2scan \
  --reuse-values \
  --wait

echo "Monitoring for 15 minutes..."
for i in {1..15}; do
  echo "Minute $i/15..."
  kubectl get pods -n bjorn2scan
  sleep 60
done

echo "=== Multi-Environment Rollout Complete ==="
```

---

### Testing New Versions

**Use case:** Test new version before enabling auto-update

```bash
#!/bin/bash
# test-new-version.sh

NEW_VERSION="0.1.37"
TEST_NAMESPACE="bjorn2scan-test"

echo "=== Testing New Version $NEW_VERSION ==="

# Create test namespace
echo "Step 1: Creating test namespace..."
kubectl create namespace $TEST_NAMESPACE

# Install test release
echo "Step 2: Installing test release..."
helm install bjorn2scan-test oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --version $NEW_VERSION \
  -n $TEST_NAMESPACE \
  --set updateController.enabled=false

# Wait for pods
echo "Step 3: Waiting for pods..."
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=bjorn2scan \
  -n $TEST_NAMESPACE \
  --timeout=300s

# Run tests
echo "Step 4: Running functional tests..."
# Add test commands here

# Cleanup
echo "Step 5: Cleaning up test environment..."
read -p "Delete test namespace? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  helm uninstall bjorn2scan-test -n $TEST_NAMESPACE
  kubectl delete namespace $TEST_NAMESPACE
fi

echo "=== Testing Complete ==="
```

---

## Disaster Recovery

### Complete System Rollback

**Severity:** Critical
**Response Time:** Immediate

```bash
#!/bin/bash
# disaster-rollback.sh

echo "=== DISASTER RECOVERY: Complete System Rollback ==="

NAMESPACE="bjorn2scan"

# Step 1: Disable all auto-updates
echo "Disabling all auto-updates..."
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' \
  -n $NAMESPACE

# Step 2: View Helm history
echo "Release history:"
helm history bjorn2scan -n $NAMESPACE

# Step 3: Identify last good version
read -p "Enter revision number to rollback to: " REVISION

# Step 4: Perform rollback
echo "Rolling back to revision $REVISION..."
helm rollback bjorn2scan $REVISION -n $NAMESPACE

# Step 5: Force pod recreation
echo "Forcing pod recreation..."
kubectl delete pods --all -n $NAMESPACE

# Step 6: Wait for recovery
echo "Waiting for system recovery..."
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=bjorn2scan \
  -n $NAMESPACE \
  --timeout=600s

# Step 7: Verify health
echo "Verifying system health..."
kubectl get pods -n $NAMESPACE

# Step 8: Document incident
cat <<EOF > disaster-recovery-$(date +%Y%m%d-%H%M%S).log
Disaster Recovery Performed
Date: $(date)
Rolled back to revision: $REVISION
Status: $(helm list -n $NAMESPACE -o json | jq -r '.[0].status')
EOF

echo "=== Recovery Complete ==="
echo "IMPORTANT: Investigate root cause before re-enabling auto-updates"
```

---

### Restore from Backup

**Use case:** Complete reinstall from saved configuration

```bash
#!/bin/bash
# restore-from-backup.sh

BACKUP_FILE=$1
NAMESPACE="bjorn2scan"

if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup-values.yaml>"
  exit 1
fi

echo "=== Restoring from Backup ==="

# Step 1: Uninstall current release
echo "Uninstalling current release..."
helm uninstall bjorn2scan -n $NAMESPACE

# Step 2: Wait for cleanup
echo "Waiting for cleanup..."
sleep 30

# Step 3: Reinstall from backup
echo "Reinstalling from backup..."
helm install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n $NAMESPACE \
  -f $BACKUP_FILE \
  --wait

# Step 4: Verify
echo "Verifying installation..."
helm list -n $NAMESPACE
kubectl get pods -n $NAMESPACE

echo "=== Restore Complete ==="
```

---

## Advanced Procedures

### Manual Chart/Binary Installation

**Kubernetes - Manual Chart Installation:**

```bash
# Download specific chart version
helm pull oci://ghcr.io/bvboe/b2s-go/bjorn2scan --version 0.1.35

# Extract chart
tar -xzf bjorn2scan-0.1.35.tgz

# Inspect and modify if needed
cd bjorn2scan
cat values.yaml

# Install from local chart
helm install bjorn2scan . -n bjorn2scan -f custom-values.yaml
```

**Agent - Manual Binary Installation:**

```bash
# Download specific version
VERSION="0.1.35"
curl -LO https://github.com/bvboe/b2s-go/releases/download/v${VERSION}/bjorn2scan-agent-linux-amd64.tar.gz

# Verify checksum
curl -LO https://github.com/bvboe/b2s-go/releases/download/v${VERSION}/bjorn2scan-agent-linux-amd64.tar.gz.sha256
sha256sum -c bjorn2scan-agent-linux-amd64.tar.gz.sha256

# Extract and install
tar -xzf bjorn2scan-agent-linux-amd64.tar.gz
sudo install -m 755 bjorn2scan-agent-linux-amd64 /usr/local/bin/bjorn2scan-agent

# Restart service
sudo systemctl restart bjorn2scan-agent
```

---

### Signature Verification Troubleshooting

**Issue:** Signature verification failing

```bash
# Step 1: Verify cosign is installed
cosign version

# Step 2: Test signature verification manually
cosign verify \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/bvboe/b2s-go/bjorn2scan:0.1.35

# Step 3: If verification fails, check configuration
kubectl get configmap bjorn2scan-update-controller -n bjorn2scan -o yaml \
  | grep -A 3 "verification"

# Step 4: Temporarily disable verification for testing
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n bjorn2scan \
  --set updateController.config.verification.enabled=false \
  --reuse-values

# Step 5: Re-enable after fixing
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  -n bjorn2scan \
  --set updateController.config.verification.enabled=true \
  --reuse-values
```

---

### Custom Update Schedule

**Use case:** Change update schedule for specific requirements

```bash
# Daily at 3:30 AM UTC
kubectl patch cronjob bjorn2scan-update-controller -n bjorn2scan \
  -p '{"spec":{"schedule":"30 3 * * *"}}'

# Every Sunday at 2 AM
kubectl patch cronjob bjorn2scan-update-controller -n bjorn2scan \
  -p '{"spec":{"schedule":"0 2 * * 0"}}'

# First day of month at midnight
kubectl patch cronjob bjorn2scan-update-controller -n bjorn2scan \
  -p '{"spec":{"schedule":"0 0 1 * *"}}'

# Every 12 hours
kubectl patch cronjob bjorn2scan-update-controller -n bjorn2scan \
  -p '{"spec":{"schedule":"0 */12 * * *"}}'

# Verify new schedule
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan \
  -o jsonpath='{.spec.schedule}'
```

---

## Quick Reference

### Emergency Commands

```bash
# DISABLE UPDATES IMMEDIATELY
kubectl patch cronjob bjorn2scan-update-controller -p '{"spec":{"suspend":true}}' -n bjorn2scan

# EMERGENCY ROLLBACK
helm rollback bjorn2scan -n bjorn2scan

# STOP IN-PROGRESS UPDATE
kubectl delete jobs -l app=bjorn2scan-update-controller -n bjorn2scan
```

### Health Check Commands

```bash
# Kubernetes
helm list -n bjorn2scan
kubectl get pods -n bjorn2scan
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan

# Agent
curl http://localhost:9999/health
curl http://localhost:9999/api/update/status
```

### Log Commands

```bash
# Kubernetes
kubectl logs -l app=bjorn2scan-update-controller -n bjorn2scan --tail=100
helm history bjorn2scan -n bjorn2scan

# Agent
sudo journalctl -u bjorn2scan-agent -f
sudo tail -f /var/log/bjorn2scan/agent.log
```

---

## Escalation Path

**Level 1: Operator**
- Basic health checks
- Routine operations
- Following documented procedures

**Level 2: Platform Team**
- Failed update recovery
- Version mismatch resolution
- Performance issues

**Level 3: Development Team**
- Update mechanism bugs
- Signature verification issues
- Design changes needed

**Emergency Contact:** [Add your team's contact information]

---

## Document Maintenance

- **Last Updated:** 2025-12-23
- **Review Frequency:** Quarterly
- **Owner:** DevOps/Platform Team
- **Related Documents:**
  - [AUTO_UPDATE.md](./AUTO_UPDATE.md) - User guide
  - [README.md](../README.md) - General documentation
