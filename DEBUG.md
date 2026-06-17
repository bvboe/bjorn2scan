# Debug Mode Documentation

Bjørn2Scan includes a debug mode that provides SQL query capabilities, performance metrics, and verbose logging for development and troubleshooting.

**⚠️ WARNING: Debug mode should ONLY be enabled in development/testing environments. Do NOT enable in production.**

## Features

- **SQL Query Endpoint**: Execute read-only SELECT queries on the database
- **Performance Metrics**: View request statistics, response times, and queue depth
- **Verbose Logging**: Detailed request/response logging with timing information

## Configuration

### Kubernetes Deployment

Enable debug mode via Helm values:

```yaml
# values.yaml
scanServer:
  config:
    debugEnabled: true
```

Then upgrade your deployment:

```bash
helm upgrade bjorn2scan ./helm/bjorn2scan \
  --set scanServer.config.debugEnabled=true
```

Or use environment variable override:

```bash
kubectl set env deployment/bjorn2scan-scan-server DEBUG_ENABLED=true
```

### Agent Deployment

#### Option 1: Configuration File

Create `/etc/bjorn2scan/agent.conf`:

```ini
# Bjørn2Scan Agent Configuration
port=9999
db_path=/var/lib/bjorn2scan/containers.db
debug_enabled=true
```

#### Option 2: Environment Variable

```bash
DEBUG_ENABLED=true ./bjorn2scan-agent
```

Or in systemd service file:

```ini
[Service]
Environment="DEBUG_ENABLED=true"
ExecStart=/usr/local/bin/bjorn2scan-agent
```

## Debug Endpoints

### POST /debug/sql

Execute read-only SQL queries on the database.

**Security**:
- Only SELECT queries allowed
- No semicolons (prevents multiple statements)
- Dangerous keywords blocked (INSERT, UPDATE, DELETE, DROP, etc.)

**Example Request**:

```bash
curl -X POST http://localhost:8080/debug/sql \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM container_images LIMIT 10"}'
```

**Example Response**:

```json
{
  "rows": [
    {
      "id": 1,
      "digest": "sha256:abc123...",
      "repository": "nginx",
      "tag": "latest",
      "scan_status": "scanned"
    }
  ],
  "row_count": 1
}
```

**Useful Queries**:

```sql
-- List all images
SELECT digest, repository, tag, scan_status FROM container_images;

-- Count images by scan status
SELECT scan_status, COUNT(*) as count FROM container_images GROUP BY scan_status;

-- Find images with vulnerabilities
SELECT DISTINCT i.digest, i.repository, i.tag, COUNT(v.id) as vuln_count
FROM container_images i
JOIN vulnerabilities v ON i.id = v.image_id
GROUP BY i.id, i.digest, i.repository, i.tag
ORDER BY vuln_count DESC;

-- View recent scans
SELECT digest, repository, tag, scanned_at
FROM container_images
WHERE scan_status = 'scanned'
ORDER BY scanned_at DESC
LIMIT 10;

-- Check package counts
SELECT name, COUNT(DISTINCT image_id) as image_count, SUM(number_of_instances) as total_instances
FROM packages
GROUP BY name
ORDER BY image_count DESC
LIMIT 20;
```

### GET /debug/metrics

Retrieve performance metrics and statistics.

**Example Request**:

```bash
curl http://localhost:8080/debug/metrics
```

**Example Response**:

```json
{
  "request_count": 145,
  "total_duration_ms": 12500,
  "queue_depth": 3,
  "last_updated": "2025-12-18T10:30:45Z",
  "endpoints": {
    "/api/images": {
      "count": 50,
      "total_duration_ms": 2500,
      "avg_duration_ms": 50,
      "last_access": "2025-12-18T10:30:40Z"
    },
    "/api/images/sha256:abc123/vulnerabilities": {
      "count": 25,
      "total_duration_ms": 5000,
      "avg_duration_ms": 200,
      "last_access": "2025-12-18T10:30:45Z"
    }
  }
}
```

## Verbose Logging

When debug mode is enabled, all HTTP requests and responses are logged with detailed information:

```
[DEBUG] Request: method=GET path=/api/images remote=127.0.0.1:54321
[DEBUG] Response: method=GET path=/api/images status=200 size=1234 duration=45.2ms
```

This helps identify:
- Slow endpoints
- Large responses
- Request patterns
- Performance bottlenecks

## Database Schema Reference

Useful tables for queries:

- **container_images**: Image metadata and scan status
- **container_instances**: Running container instances
- **packages**: Software packages found in images
- **vulnerabilities**: CVEs and security issues
- **image_summary**: Aggregated package and OS information

See `scanner-core/database/migrations.go` for complete schema.

## Security Considerations

1. **Read-Only Queries**: Only SELECT statements are allowed
2. **No Data Modification**: INSERT/UPDATE/DELETE blocked
3. **No Multiple Statements**: Semicolons rejected
4. **Keyword Filtering**: Dangerous SQL keywords blocked
5. **Return 403**: Debug endpoints return Forbidden when debug mode disabled

## Troubleshooting

### Debug endpoints return 403

Check that debug mode is enabled:
- K8s: `kubectl get deployment bjorn2scan-scan-server -o yaml | grep DEBUG_ENABLED`
- Agent: Check config file or environment variable

### SQL query rejected

- Ensure query starts with SELECT
- Remove semicolons
- Avoid dangerous keywords (UPDATE, DELETE, etc.)
- Check for syntax errors

### No metrics showing

- Metrics are only collected when debug mode is enabled
- Make some requests first to populate metrics
- Check that the service has been running long enough

## Disabling Debug Mode

### Kubernetes

```bash
helm upgrade bjorn2scan ./helm/bjorn2scan \
  --set scanServer.config.debugEnabled=false
```

Or:

```bash
kubectl set env deployment/bjorn2scan-scan-server DEBUG_ENABLED=false
```

### Agent

Remove `debug_enabled=true` from config file or unset DEBUG_ENABLED environment variable, then restart the agent.

## Performance Impact

- **When Disabled**: Zero overhead - debug handlers not registered, middleware passes through immediately
- **When Enabled**: Minimal overhead - ~1-2ms per request for logging and metrics collection
