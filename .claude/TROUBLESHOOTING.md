# Bjorn2Scan Troubleshooting Guide

This document provides troubleshooting guidance for common issues with bjorn2scan deployments.

## Debug API Endpoints

Debug endpoints require `DEBUG_ENABLED=true` environment variable.

### Queue Visibility

```bash
# View current queue state with all pending jobs
curl http://HOST/api/debug/queue | jq .
```

Response:
```json
{
  "current_depth": 5,
  "peak_depth": 12,
  "total_enqueued": 1547,
  "total_dropped": 3,
  "total_processed": 1539,
  "jobs": [
    {"type": "image", "image": "nginx:latest", "digest": "sha256:...", "node_name": "worker-1", "force_scan": false},
    {"type": "host", "node_name": "worker-1", "force_scan": true, "full_rescan": false}
  ]
}
```

### Manual Rescans

```bash
# Rescan a specific node
curl -X POST http://HOST/api/debug/rescan/node/worker-1

# Rescan with full SBOM regeneration
curl -X POST http://HOST/api/debug/rescan/node/worker-1 -d '{"full_rescan": true}'

# Rescan a specific image by digest
curl -X POST http://HOST/api/debug/rescan/image/sha256:abc123...

# Rescan ALL nodes (like grype DB update triggers)
curl -X POST http://HOST/api/debug/rescan/all-nodes

# Rescan ALL images
curl -X POST http://HOST/api/debug/rescan/all-images
```

### SQL Queries

```bash
# Execute arbitrary SQL (read-only recommended)
curl -X POST http://HOST/api/debug/sql \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM images LIMIT 10"}'
```

### Performance Metrics

```bash
# View request metrics and queue depth
curl http://HOST/api/debug/metrics | jq .
```

### Scheduled Jobs

```bash
# List all scheduled jobs
curl http://HOST/api/debug/jobs | jq .

# Trigger a job manually
curl -X POST http://HOST/api/debug/jobs/rescan-database/trigger
```

## Common Issues

### Stuck Images (not being scanned)

**Symptoms:**
- Images remain in `pending` or `generating_sbom` status indefinitely
- Queue depth shows 0 but images aren't scanned

**Diagnosis:**
```bash
# Check queue state
curl http://HOST/api/debug/queue | jq .

# Check image statuses
curl http://HOST/api/debug/sql -d '{"query": "SELECT digest, status, status_error FROM images WHERE status != '\''completed'\'' LIMIT 20"}' | jq .

# Check pod-scanner health on each node
kubectl get pods -n b2sv2 -l app=bjorn2scan-pod-scanner
```

**Resolution:**
1. If pod-scanner is not running on the node, check DaemonSet
2. Force rescan specific images: `curl -X POST http://HOST/api/debug/rescan/image/sha256:...`
3. Check pod-scanner logs: `kubectl logs -n b2sv2 -l app=bjorn2scan-pod-scanner`

### Stuck Nodes (SBOM generation failing)

**Symptoms:**
- Nodes stuck in `sbom_failed` or `generating_sbom` status
- `status_error` shows error messages

**Diagnosis:**
```bash
# Check node statuses
curl http://HOST/api/nodes | jq '.[] | {name: .name, status: .status, error: .status_error}'

# Check specific node
curl http://HOST/api/debug/sql -d '{"query": "SELECT name, status, status_error FROM nodes WHERE status != '\''completed'\''"}' | jq .
```

**Common errors:**
- `pod-scanner returned status 500` - pod-scanner cannot access host filesystem
- `context deadline exceeded` - SBOM generation timed out (15 minute timeout)

**Resolution:**
1. Check pod-scanner has hostPID and proper volume mounts
2. Check node has sufficient resources (SBOM generation is memory-intensive)
3. Force rescan: `curl -X POST http://HOST/api/debug/rescan/node/NODE_NAME`

### Queue Backlog (jobs accumulating)

**Symptoms:**
- `queue_depth` metric growing
- Scans taking a long time to complete

**Diagnosis:**
```bash
# Check current queue depth and jobs
curl http://HOST/api/debug/queue | jq '{depth: .current_depth, peak: .peak_depth, dropped: .total_dropped}'

# Check what's in the queue
curl http://HOST/api/debug/queue | jq '.jobs[:10]'
```

**Resolution:**
1. Queue processes one job at a time - large backlogs are normal after cluster changes
2. Check if grype DB is ready: `curl http://HOST/api/db/status`
3. If DB isn't ready, scans will queue until it is
4. Check scan-server logs for errors: `kubectl logs -n b2sv2 deploy/bjorn2scan-scan-server --tail=100`

### Grype Database Issues

**Symptoms:**
- Scans failing with "vulnerability database not ready"
- `/api/db/status` shows errors

**Diagnosis:**
```bash
# Check DB status
curl http://HOST/api/db/status | jq .

# Check scan-server logs for DB initialization
kubectl logs -n b2sv2 deploy/bjorn2scan-scan-server | grep -i "grype\|database"
```

**Resolution:**
1. Wait for initial download (can take 2+ minutes on first run)
2. Check disk space on grype DB volume
3. Check network connectivity for DB downloads
4. Reinitialize DB: `curl -X POST http://HOST/api/debug/db/reinit`

### Stale Scans (outdated vulnerability data)

**Symptoms:**
- `grype_db_built` on nodes/images doesn't match current DB version
- Missing recently disclosed vulnerabilities

**Diagnosis:**
```bash
# Check current grype DB version
curl http://HOST/api/db/status | jq .built

# Check node grype_db versions
curl http://HOST/api/nodes | jq '.[] | {name: .name, grype_db: .grype_db_built}'

# Compare to current
CURRENT=$(curl -s http://HOST/api/db/status | jq -r .built)
curl http://HOST/api/nodes | jq --arg c "$CURRENT" '.[] | select(.grype_db_built < $c) | .name'
```

**Resolution:**
1. Trigger rescan-database job: `curl -X POST http://HOST/api/debug/jobs/rescan-database/trigger`
2. Or manually rescan all: `curl -X POST http://HOST/api/debug/rescan/all-nodes`

## Useful SQL Queries

### Image Status Counts

```sql
SELECT status, COUNT(*) as count
FROM images
GROUP BY status
ORDER BY count DESC;
```

### Images with Errors

```sql
SELECT digest, status, status_error, updated_at
FROM images
WHERE status LIKE '%failed%'
ORDER BY updated_at DESC
LIMIT 20;
```

### Node Status Counts

```sql
SELECT status, COUNT(*) as count
FROM nodes
GROUP BY status
ORDER BY count DESC;
```

### Nodes with Errors

```sql
SELECT name, status, status_error, updated_at
FROM nodes
WHERE status LIKE '%failed%'
ORDER BY updated_at DESC;
```

### Recently Updated Images

```sql
SELECT digest, status, updated_at
FROM images
ORDER BY updated_at DESC
LIMIT 20;
```

### Vulnerability Counts by Severity

```sql
SELECT severity, COUNT(*) as count
FROM vulnerabilities
GROUP BY severity
ORDER BY
  CASE severity
    WHEN 'Critical' THEN 1
    WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3
    WHEN 'Low' THEN 4
    ELSE 5
  END;
```

### Node Vulnerability Counts by Severity

```sql
SELECT severity, COUNT(*) as count
FROM node_vulnerabilities
GROUP BY severity
ORDER BY
  CASE severity
    WHEN 'Critical' THEN 1
    WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3
    WHEN 'Low' THEN 4
    ELSE 5
  END;
```

### Images Scanned with Old Grype DB

```sql
SELECT digest, grype_db_built, vulns_scanned_at
FROM images
WHERE grype_db_built < (SELECT MAX(grype_db_built) FROM images)
AND status = 'completed'
LIMIT 20;
```

## Queue Architecture

Understanding the queue helps with troubleshooting:

- **Single queue** with two internal slices: `jobs` (images) and `hostJobs` (nodes)
- **Single worker** processes jobs serially (one at a time)
- **Image jobs are prioritized** over host jobs
- **No concurrent scanning** - prevents resource exhaustion

When the queue is full (if max depth is configured):
- Default behavior: drops new jobs
- Jobs already in queue are preserved

## Log Filtering

Once structured logging is enabled, filter by component:

```bash
# Filter by component in logs
kubectl logs -n b2sv2 deploy/bjorn2scan-scan-server | grep '"component":"queue"'
kubectl logs -n b2sv2 deploy/bjorn2scan-scan-server | grep '"component":"grype"'
kubectl logs -n b2sv2 deploy/bjorn2scan-scan-server | grep '"component":"scheduler"'
```

Component names:
- `scheduler` - Job scheduling
- `grype` - Vulnerability scanning
- `scan-queue` - Queue operations
- `database` - Database operations
- `nodes` - Node management
- `containers` - Container management
- `http` - HTTP handlers
- `pod-scanner` - Pod scanner operations
