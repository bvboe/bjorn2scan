# Prometheus Metrics Implementation

## Overview

This document describes the Prometheus metrics endpoint implementation for bjorn2scan, enabling monitoring and alerting on vulnerability data.

## Metrics Endpoint

- **Path**: `/metrics`
- **Format**: Prometheus text exposition format
- **Access**: Public (no authentication required by default)

## Metrics Exposed

### 1. Container Instance Metrics

#### `bjorn2scan_scanned_instances`
Gauge metric indicating scanned container instances (value always 1 per instance).

**Labels**:
- `cluster_name`: Cluster identifier (hostname for agent, cluster name for k8s)
- `namespace`: Kubernetes namespace (or "default" for Docker containers)
- `pod_name`: Pod name (or "standalone" for Docker containers)
- `container_name`: Container name
- `image`: Full image reference (repository:tag)
- `image_id`: Image digest (SHA256)
- `distro_name`: Operating system distribution (e.g., "ubuntu", "alpine")
- `distro_version`: OS version (e.g., "22.04", "3.18")
- `node_name`: Node where container runs
- `container_runtime`: Runtime type (e.g., "docker", "containerd")

**Example**:
```
bjorn2scan_scanned_instances{cluster_name="prod-cluster",namespace="frontend",pod_name="web-app-xyz",container_name="nginx",image="nginx:1.25",image_id="sha256:abc123...",distro_name="debian",distro_version="12",node_name="node-1",container_runtime="containerd"} 1
```

### 2. Deployment Metrics

#### `bjorn2scan_deployment`
Gauge metric providing deployment information (value always 1).

**Labels**:
- `deployment_uuid`: Unique deployment identifier
- `deployment_name`: Deployment name (hostname for agent, cluster name for k8s)
- `deployment_type`: Type of deployment ("agent" or "kubernetes")
- `bjorn2scan_version`: Version of bjorn2scan
- `deployment_ip`: IP address where scanner runs (primary outbound IP for agent, node IP for k8s). Omitted if unavailable.
- `deployment_console`: URL of the web UI console (e.g., http://192.168.1.10:9999/). Omitted if web UI is disabled or URL cannot be determined.
- `grype_db_built`: Build timestamp of the Grype vulnerability database in RFC3339 format (e.g., "2025-12-27T10:30:00Z"). Omitted if database status is unavailable.

**Example**:
```
# Agent deployment with web UI enabled and grype database status
bjorn2scan_deployment{deployment_uuid="abc-123",deployment_name="my-server",deployment_type="agent",bjorn2scan_version="0.1.54",deployment_ip="192.168.1.10",deployment_console="http://192.168.1.10:9999/",grype_db_built="2025-12-27T10:30:00Z"} 1

# Kubernetes deployment with ClusterIP service
bjorn2scan_deployment{deployment_uuid="def-456",deployment_name="prod-cluster",deployment_type="kubernetes",bjorn2scan_version="0.1.54",deployment_ip="10.0.1.5",deployment_console="http://bjorn2scan.default.svc.cluster.local:80/",grype_db_built="2025-12-27T10:30:00Z"} 1
```

**Use Case for grype_db_built**: This label allows monitoring the age of the vulnerability database across all deployments. You can create alerts when the database is too old or track how often it's being updated.

**Configuration**:
- Web UI: Enable/disable via `web_ui_enabled` (agent config) or `scanServer.config.webUIEnabled` (Helm)
- Custom Console URL: Set via `CONSOLE_URL` environment variable or `scanServer.config.consoleURL` (Helm) to override auto-detection

### 3. Container Instance Metrics

#### `bjorn2scan_scanned_instance`
Gauge metric for each container instance (value always 1 per instance). Includes all container instances regardless of scan status.

**Labels**:
- `deployment_uuid`: Unique deployment identifier
- `deployment_uuid_host_name`: Hierarchical label combining deployment UUID and host name
- `deployment_uuid_namespace`: Hierarchical label combining deployment UUID and namespace
- `deployment_uuid_namespace_image`: Hierarchical label for deployment, namespace, and image
- `deployment_uuid_namespace_image_digest`: Hierarchical label for deployment, namespace, and image digest
- `deployment_uuid_namespace_pod`: Hierarchical label for deployment, namespace, and pod
- `deployment_uuid_namespace_pod_container`: Full hierarchical label for container instance
- `host_name`: Node where container runs
- `namespace`: Kubernetes namespace (or "default" for Docker containers)
- `pod`: Pod name (or "standalone" for Docker containers)
- `container`: Container name
- `distro`: Operating system distribution
- `image_repo`: Image repository
- `image_tag`: Image tag
- `image_digest`: Image digest (SHA256)
- `instance_type`: Type of instance ("CONTAINER")
- `scan_status`: Current scan status (e.g., "pending", "generating_sbom", "completed", "sbom_failed", "vuln_scan_failed")

**Example**:
```
bjorn2scan_scanned_instance{deployment_uuid="abc-123",host_name="node-1",namespace="frontend",pod="web-app-xyz",container="nginx",distro="debian",image_repo="nginx",image_tag="1.25",image_digest="sha256:abc123...",scan_status="completed"} 1
```

**Use Case for scan_status**: This label allows monitoring scan progress and identifying containers with failed or pending scans. You can create alerts when too many containers have failed scans or track scan completion rates.

### 4. Vulnerability Metrics

#### `bjorn2scan_image_vulnerability`
Gauge metric reporting all vulnerabilities found in running container images. Value represents the number of vulnerability instances.

**Labels**:
- All labels from `bjorn2scan_scanned_instance` plus:
- `severity`: Vulnerability severity (Critical, High, Medium, Low, Negligible, Unknown)
- `vulnerability`: CVE ID (e.g., "CVE-2024-1234")
- `vulnerability_id`: Unique vulnerability identifier combining deployment UUID and vulnerability DB ID
- `package_name`: Affected package name
- `package_version`: Affected package version
- `fix_status`: Fix availability ("fixed", "not-fixed", "wont-fix", "unknown")
- `fixed_version`: Version with fix (if available)

**Example**:
```
bjorn2scan_image_vulnerability{deployment_uuid="abc-123",namespace="frontend",pod="web-app",container="nginx",severity="Critical",vulnerability="CVE-2024-1234",package_name="openssl",package_version="3.0.0",fix_status="fixed",fixed_version="3.0.13"} 2
```

**Configuration**:
- Helm: `scanServer.config.metrics.vulnerabilitiesEnabled: true`
- Agent config: `metrics_vulnerabilities_enabled=true`
- Environment: `METRICS_VULNERABILITIES_ENABLED=true`

#### `bjorn2scan_image_vulnerability_exploited`
Gauge metric reporting known exploited vulnerabilities (CISA KEV catalog) in running container images. Only includes vulnerabilities with known exploits. Value is always 1 (presence indicates exploitation).

**Labels**: Same as `bjorn2scan_image_vulnerability`

**Example**:
```
bjorn2scan_image_vulnerability_exploited{deployment_uuid="abc-123",namespace="frontend",pod="web-app",container="nginx",severity="Critical",vulnerability="CVE-2024-1234",package_name="openssl",package_version="3.0.0",fix_status="fixed",fixed_version="3.0.13"} 1
```

**Use Case**: This metric helps prioritize remediation by highlighting vulnerabilities that are actively being exploited in the wild according to CISA's Known Exploited Vulnerabilities catalog.

**Configuration**:
- Helm: `scanServer.config.metrics.vulnerabilityExploitedEnabled: true`
- Agent config: `metrics_vulnerability_exploited_enabled=true`
- Environment: `METRICS_VULNERABILITY_EXPLOITED_ENABLED=true`

#### `bjorn2scan_image_vulnerability_risk`
Gauge metric reporting vulnerability risk scores for running container images. Value represents the risk score (float) for each vulnerability. Includes all vulnerabilities regardless of risk value.

**Labels**: Same as `bjorn2scan_image_vulnerability`

**Example**:
```
bjorn2scan_image_vulnerability_risk{deployment_uuid="abc-123",namespace="frontend",pod="web-app",container="nginx",severity="Critical",vulnerability="CVE-2024-1234",package_name="openssl",package_version="3.0.0",fix_status="fixed",fixed_version="3.0.13"} 7.5
```

**Use Case**: This metric provides granular risk assessment based on multiple factors (CVSS, EPSS, exploitability). The risk score helps prioritize remediation efforts with more nuance than severity alone.

**Configuration**:
- Helm: `scanServer.config.metrics.vulnerabilityRiskEnabled: true`
- Agent config: `metrics_vulnerability_risk_enabled=true`
- Environment: `METRICS_VULNERABILITY_RISK_ENABLED=true`

### 5. Node Metrics

Node metrics are enabled when host scanning is enabled. They mirror the structure of image metrics but report vulnerabilities found in node/host packages.

#### `bjorn2scan_node_scanned`
Gauge metric for each scanned node (value always 1 per node). Only includes nodes with completed scans.

**Labels**:
- `deployment_uuid`: Unique deployment identifier
- `deployment_name`: Deployment name
- `node`: Kubernetes node name
- `hostname`: Node hostname
- `os_release`: OS version (e.g., "Ubuntu 22.04.3 LTS")
- `kernel_version`: Kernel version
- `architecture`: CPU architecture (amd64, arm64)
- `instance_type`: Type of instance ("NODE")

**Example**:
```
bjorn2scan_node_scanned{deployment_uuid="abc-123",deployment_name="prod-cluster",node="node-1",hostname="node-1.local",os_release="Ubuntu 22.04.3 LTS",kernel_version="5.15.0-91-generic",architecture="amd64",instance_type="NODE"} 1
```

**Configuration**:
- Helm: `scanServer.config.metrics.nodeScannedEnabled: true`
- Agent config: `metrics_node_scanned_enabled=true`
- Environment: `METRICS_NODE_SCANNED_ENABLED=true`

#### `bjorn2scan_node_vulnerability`
Gauge metric reporting vulnerabilities found in node packages. Value represents the count of vulnerability instances.

**Labels**: All labels from `bjorn2scan_node_scanned` plus:
- `severity`: Vulnerability severity (Critical, High, Medium, Low, Negligible, Unknown)
- `vulnerability`: CVE ID (e.g., "CVE-2024-1234")
- `vulnerability_id`: Unique identifier combining deployment UUID and vulnerability DB ID
- `package_name`: Affected package name
- `package_version`: Affected package version
- `package_type`: Package type (deb, rpm, apk, etc.)
- `fix_status`: Fix availability ("fixed", "not-fixed", "unknown")
- `fixed_version`: Version with fix (if available)

**Example**:
```
bjorn2scan_node_vulnerability{deployment_uuid="abc-123",deployment_name="prod-cluster",node="node-1",hostname="node-1.local",os_release="Ubuntu 22.04.3 LTS",kernel_version="5.15.0-91-generic",architecture="amd64",instance_type="NODE",severity="Critical",vulnerability="CVE-2024-1234",vulnerability_id="abc-123.42",package_name="openssl",package_version="3.0.2",package_type="deb",fix_status="fixed",fixed_version="3.0.13"} 1
```

**Configuration**:
- Helm: `scanServer.config.metrics.nodeVulnerabilitiesEnabled: true`
- Agent config: `metrics_node_vulnerabilities_enabled=true`
- Environment: `METRICS_NODE_VULNERABILITIES_ENABLED=true`

#### `bjorn2scan_node_vulnerability_risk`
Gauge metric reporting vulnerability risk scores for node packages. Value represents the risk score (float) multiplied by count.

**Labels**: Same as `bjorn2scan_node_vulnerability`

**Example**:
```
bjorn2scan_node_vulnerability_risk{deployment_uuid="abc-123",deployment_name="prod-cluster",node="node-1",...,severity="Critical",vulnerability="CVE-2024-1234",package_name="openssl",...} 9.8
```

**Configuration**:
- Helm: `scanServer.config.metrics.nodeVulnerabilityRiskEnabled: true`
- Agent config: `metrics_node_vulnerability_risk_enabled=true`
- Environment: `METRICS_NODE_VULNERABILITY_RISK_ENABLED=true`

#### `bjorn2scan_node_vulnerability_exploited`
Gauge metric reporting known exploited vulnerabilities (CISA KEV catalog) on nodes. Only includes vulnerabilities with known exploits.

**Labels**: Same as `bjorn2scan_node_vulnerability`

**Example**:
```
bjorn2scan_node_vulnerability_exploited{deployment_uuid="abc-123",deployment_name="prod-cluster",node="node-1",...,severity="Critical",vulnerability="CVE-2024-1234",package_name="openssl",...} 1
```

**Configuration**:
- Helm: `scanServer.config.metrics.nodeVulnerabilityExploitedEnabled: true`
- Agent config: `metrics_node_vulnerability_exploited_enabled=true`
- Environment: `METRICS_NODE_VULNERABILITY_EXPLOITED_ENABLED=true`

### 6. Aggregated Queries

While there are no dedicated total metrics, you can derive counts using PromQL:

#### Count Total Instances
```promql
count(bjorn2scan_scanned_instance)
```

#### Count Unique Images
```promql
count(count by (image_digest) (bjorn2scan_scanned_instance))
```

#### Count Instances by Namespace
```promql
count by (namespace) (bjorn2scan_scanned_instance)
```

#### Count Instances by Scan Status
```promql
count by (scan_status) (bjorn2scan_scanned_instance)
```

#### Count Failed Scans
```promql
count(bjorn2scan_scanned_instance{scan_status=~"sbom_failed|vuln_scan_failed"})
```

#### Count Pending Scans
```promql
count(bjorn2scan_scanned_instance{scan_status="pending"})
```

## Implementation Architecture

### Package Structure
```
scanner-core/
  metrics/
    collector.go      # Prometheus collector implementation
    metrics.go        # Metric definitions and registration
    handler.go        # HTTP handler for /metrics endpoint
    metrics_test.go   # Unit tests
```

### Data Flow
1. HTTP request to `/metrics`
2. Handler calls collector's `Collect()` method
3. Collector queries database for current state
4. Metrics are generated with appropriate labels
5. Prometheus text format is written to response

### Performance Considerations
- **Caching**: Metrics are computed on each scrape (no caching by default)
- **Query Optimization**: Uses efficient SQL queries with proper indexes
- **Scrape Interval**: Recommended 30-60 seconds
- **Timeout**: Database queries have 10-second timeout

## Configuration

No additional configuration required. The `/metrics` endpoint is automatically registered when the HTTP server starts.

## Example Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'bjorn2scan-agent'
    static_configs:
      - targets: ['agent-host:9999']
    scrape_interval: 30s
    scrape_timeout: 10s

  - job_name: 'bjorn2scan-k8s'
    kubernetes_sd_configs:
      - role: service
    relabel_configs:
      - source_labels: [__meta_kubernetes_service_label_app]
        regex: bjorn2scan
        action: keep
```

## Example Prometheus Queries

### Count vulnerabilities by severity
```promql
sum by (severity) (bjorn2scan_image_vulnerability)
```

### Count containers with critical vulnerabilities
```promql
count(bjorn2scan_image_vulnerability{severity="Critical"})
```

### Container instances by namespace
```promql
count by (namespace) (bjorn2scan_scanned_instance)
```

### Known exploited vulnerabilities (CISA KEV) by severity
```promql
sum by (severity) (bjorn2scan_image_vulnerability_exploited > 0)
```

### Containers with actively exploited CVEs
```promql
count by (namespace, pod, container) (bjorn2scan_image_vulnerability_exploited > 0)
```

### Top 10 most critical exploited vulnerabilities
```promql
topk(10, sum by (vulnerability, severity) (bjorn2scan_image_vulnerability_exploited{severity="Critical"}))
```

### Average risk score by severity
```promql
avg by (severity) (bjorn2scan_image_vulnerability_risk)
```

### Highest risk vulnerabilities across all containers
```promql
topk(10, max by (vulnerability, severity) (bjorn2scan_image_vulnerability_risk))
```

### Containers with high-risk vulnerabilities (risk > 7.0)
```promql
count by (namespace, pod, container) (bjorn2scan_image_vulnerability_risk > 7.0)
```

### Total risk exposure by namespace
```promql
sum by (namespace) (bjorn2scan_image_vulnerability_risk)
```

### Deployment info
```promql
bjorn2scan_deployment
```

### Grype database age monitoring
```promql
# Get the grype database build timestamp for all deployments
bjorn2scan_deployment{grype_db_built!=""}

# Extract the grype_db_built label for alerting (use with alertmanager)
# Example alert: Database older than 7 days
# This requires parsing the RFC3339 timestamp in your alerting rules
```

### Node vulnerability queries

```promql
# Count total scanned nodes
count(bjorn2scan_node_scanned)

# Count node vulnerabilities by severity
sum by (severity) (bjorn2scan_node_vulnerability)

# Critical node vulnerabilities
count(bjorn2scan_node_vulnerability{severity="Critical"})

# Known exploited vulnerabilities on nodes (CISA KEV)
sum by (node) (bjorn2scan_node_vulnerability_exploited)

# Total risk exposure by node
sum by (node) (bjorn2scan_node_vulnerability_risk)

# Nodes with high-risk vulnerabilities (risk > 7.0)
count by (node) (bjorn2scan_node_vulnerability_risk > 7.0)
```

## Grafana Dashboards

Two dashboards are available:

- `docs/grafana-container-dashboard.json` — container/image vulnerabilities, grouped by namespace, image, and running container.
- `docs/grafana-node-dashboard.json` — host/node vulnerabilities, grouped by OS and node (uses the `bjorn2scan_node_*` metrics).

Both share a `staleness_window` interval variable: panel queries wrap metrics in `last_over_time(...[$staleness_window])` so deployments that push infrequently (agents push every 15m vs. 5m for Kubernetes) stay visible between pushes.

The container dashboard's features:

### Dashboard Features

- **Overview Row**: Total instances, unique images, known exploited vulns, critical/high/total vuln counts
- **Vulnerability Distribution**: Pie charts for severity, fix status, and instances by namespace
- **Risk Analysis**: Top 10 highest risk vulnerabilities, total risk by namespace
- **Known Exploited Vulnerabilities**: Table of all CISA KEV matches with severity highlighting
- **Namespace Details**: Stacked bar chart of vulnerabilities by namespace and severity
- **Deployment Info**: Table of all bjorn2scan deployments with version and console URL

### Import Instructions

1. In Grafana, go to **Dashboards** > **Import**
2. Upload `grafana-container-dashboard.json` or paste its contents
3. Select your Prometheus data source
4. Click **Import**

The dashboard auto-refreshes every 30 seconds and includes a data source selector variable.

## Security Considerations

- Metrics endpoint is unauthenticated by default
- Consider using network policies to restrict access
- Image digests are exposed (consider if this is sensitive in your environment)
- No PII or secrets are exposed in metrics
