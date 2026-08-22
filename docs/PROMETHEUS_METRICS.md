# Prometheus Metrics Implementation

## Overview

This document describes the metrics bjorn2scan exports, over both the `/metrics`
scrape endpoint and the OTLP push. The vulnerability and inventory metrics are the
same logical model in two encodings — see [OTLP export](#otlp-export).

Two groups are **scrape-only** and never travel over OTLP: the
`bjorn2scan_db_*` histograms and the `go_*` runtime metrics. Both are diagnostics
about the process rather than vulnerability data, so they are exposed on
`/metrics` and deliberately kept out of the push. Verified 2026-08-20 — the
`bjorn2scan_db_*` series show zero in Prometheus over six hours despite being
present on every scrape.

Label lists and metric names here were verified against a live scrape
(kubeadm, 2026-08-20). If you change a metric, update this file in the same
commit: it drifted badly once and dashboards were written against metrics that
had stopped existing.

### Metric inventory

| Metric | Type | Cardinality driver |
|---|---|---|
| `bjorn2scan_deployment` | gauge | one per deployment |
| `bjorn2scan_image_scanned` | gauge | one per running container |
| `bjorn2scan_image_scan_status` | gauge | one per scan status |
| `bjorn2scan_image_vulnerability` | gauge | image × CVE × package |
| `bjorn2scan_image_vulnerability_risk` | gauge | image × CVE × package |
| `bjorn2scan_image_vulnerability_exploited` | gauge | KEV matches only |
| `bjorn2scan_node_scanned` | gauge | one per node |
| `bjorn2scan_node_scan_status` | gauge | one per scan status |
| `bjorn2scan_node_vulnerability` | gauge | node × CVE × package |
| `bjorn2scan_node_vulnerability_risk` | gauge | node × CVE × package |
| `bjorn2scan_node_vulnerability_exploited` | gauge | KEV matches only |
| `bjorn2scan_db_read_seconds` | histogram | one per DB operation (scrape-only) |
| `bjorn2scan_db_write_wait_seconds` | histogram | one per DB operation (scrape-only) |
| `bjorn2scan_db_write_exec_seconds` | histogram | one per DB operation (scrape-only) |
| `go_memstats_*`, `go_gc_*`, `go_goroutines` | gauge/counter | 14 fixed series (scrape-only) |

The `× package` families dominate the payload: on a 6-node cluster they were
290,656 of ~625,000 series and 91% of a 293 MB scrape.

### Removed metrics (2026-08-20) — breaking

`bjorn2scan_scanned_instances` and `bjorn2scan_scanned_instance` are **no longer
exported**. Both were documented here long after they stopped being emitted.

- `bjorn2scan_scanned_instance` → use **`bjorn2scan_image_scanned`**. Labels
  changed too: `image_repo` + `image_tag` are now the single `image_reference`,
  and `scan_status` moved out to its own `bjorn2scan_image_scan_status` metric
  rather than being a label on every instance.
- `bjorn2scan_scanned_instances` (plural) was the pre-2.0 label scheme
  (`cluster_name`, `pod_name`, `container_name`, `image_id`, …) and has no direct
  successor; `bjorn2scan_image_scanned` covers the same ground.

### Removed labels (2026-08-20) — breaking

`kernel_version`, `architecture` and `instance_type` are no longer exported on
`bjorn2scan_node_vulnerability`, `_risk` or `_exploited`. They are per-node
invariants, so repeating them on every finding cost ~46 MB on a large deployment
while telling you nothing the node itself didn't.

They are still on **`bjorn2scan_node_scanned`**, one series per node. Join when
you need them:

```promql
sum by (kernel_version) (
  bjorn2scan_node_vulnerability
    * on (deployment_uuid, node) group_left(kernel_version)
  bjorn2scan_node_scanned)
```

`os_release` was deliberately kept on the vulnerability metrics, since filtering
findings by distro is common enough to be worth the bytes.

### Removed labels (2026-08-19) — breaking

The six pre-joined "hierarchical" labels are **no longer exported**:

```
deployment_uuid_host_name                deployment_uuid_namespace_image_digest
deployment_uuid_namespace                deployment_uuid_namespace_pod
deployment_uuid_namespace_image          deployment_uuid_namespace_pod_container
```

They were synthetic join keys for Grafana's `joinByField` transform (which can
only join on a single field), and cost ~22 MB — 6.1% — of a large deployment's
scrape while carrying no information not already present in the atomic labels.

**Migration:** derive them at query time with `label_join`, writing to the same
label name so nothing else in a dashboard needs to change:

```promql
sum by(deployment_uuid_namespace_pod_container) (
  label_join(<your original inner expression>,
    "deployment_uuid_namespace_pod_container", ".",
    "deployment_uuid", "namespace", "pod", "container"))
```

The separator is `.` and the component order matches the old label name, so the
generated values are byte-identical to what was previously exported. Build any of
the six the same way from `deployment_uuid`, `namespace`, `pod`, `container`,
`host_name`, `image_reference`, and `image_digest`.

## Metrics Endpoint

- **Path**: `/metrics`
- **Format**: Prometheus text exposition format
- **Access**: Public (no authentication required by default)

## OTLP export

The vulnerability and inventory metrics are pushed directly over OTLP, without an
OpenTelemetry Collector in between. Push and scrape are two encodings of one model
and are required to carry the same logical data — if you add a metric to one, add
it to the other.

**Not everything is pushed.** The `bjorn2scan_db_*` histograms and the `go_*`
runtime metrics are exposed on `/metrics` only. If you rely on them for alerting,
scrape the endpoint directly; they will never appear in a backend fed solely by
the push.

**Transport**
- `METRICS_ENDPOINT` — collector/backend address (e.g. `192.168.2.56:9090`)
- `METRICS_PROTOCOL` — `http` or `grpc`
- `METRICS_INSECURE` — disable TLS
- `METRICS_PUSH_INTERVAL` — how often to push (Helm sets `5m`; agents default `15m`)
- `METRICS_COMPRESSION` — `gzip` (default) or `none`. Turning it off is useful
  when inspecting payloads on the wire during debugging.
- `METRICS_STALENESS_WINDOW` — how long a data point stays valid before it is
  considered stale (default `60m`)

**Resource attributes.** Every push sets resource attributes once per batch
rather than repeating them as labels on each data point. Be aware of how the
Prometheus OTLP receiver treats them: it promotes only `service.name` → `job`
and `service.instance.id` → `instance`. Everything else lands in `target_info`
unless you configure `promote_resource_attributes` on the receiver. This is why
deployment identity travels as ordinary labels (`deployment_uuid`,
`deployment_name`) instead of resource attributes — moving them was evaluated and
rejected, see `docs/OTEL-DATA-ARCHITECTURE.md`.

**Querying pushed data.** Because agents push on a long interval, Prometheus's
5-minute staleness window can make a metric read as absent between pushes. Wrap
queries accordingly:

```promql
last_over_time(bjorn2scan_deployment[20m]) > 0
```

**Push diagnostics.** Each export logs `duration_ms`, `staleness_ms`,
`collect_ms`, `send_ms` and its breakdown into `marshal_ms`, `compress_ms` and
`http_ms`, plus `batches`, `data_points`, `bytes_uncompressed`,
`bytes_compressed` and `compression_ratio`. `marshal` and `compress` are CPU on
the scanner pod; `http` is the wire plus however long the receiver takes to accept
the batch. These are logged rather than exported as metrics, to avoid the exporter
measuring itself.

## Metrics Exposed

### 1. Deployment Metrics

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

### 2. Container Instance Metrics

#### `bjorn2scan_image_scanned`
Gauge metric for each running container instance (value always 1). Emitted for
every container regardless of scan status.

**Labels**:
- `deployment_uuid`: Unique deployment identifier
- `deployment_name`: Deployment name
- `host_name`: Node where the container runs
- `namespace`: Kubernetes namespace (or "default" for Docker containers)
- `pod`: Pod name (or "standalone" for Docker containers)
- `container`: Container name
- `distro`: Operating system distribution of the image
- `architecture`: CPU architecture (amd64, arm64)
- `image_reference`: Full image reference as specified (repository:tag or repository@digest)
- `image_digest`: Image digest (SHA256)
- `instance_type`: Type of instance ("CONTAINER")

**Example**:
```
bjorn2scan_image_scanned{deployment_uuid="abc-123",deployment_name="prod-cluster",host_name="node-1",namespace="frontend",pod="web-app-xyz",container="nginx",distro="debian",architecture="amd64",image_reference="nginx:1.25",image_digest="sha256:abc123...",instance_type="CONTAINER"} 1
```

Note there is **no `scan_status` label** here — scan progress is reported
separately by `bjorn2scan_image_scan_status`, which keeps this metric's
cardinality tied to the container count alone.

**Configuration**:
- Helm: `scanServer.config.metrics.scannedInstancesEnabled: true`
- Environment: `METRICS_SCANNED_CONTAINERS_ENABLED=true`

#### `bjorn2scan_image_scan_status`
Gauge metric counting images grouped by scan status. One series per status,
zero-filled, so a status with no images still reports 0 and a drop to zero is
distinguishable from the series disappearing.

**Labels**:
- `deployment_uuid`: Unique deployment identifier
- `scan_status`: One of `completed`, `scanning_vulnerabilities`, `generating_sbom`,
  `pending`, `sbom_failed`, `sbom_unavailable`, `vuln_scan_failed`

**Example**:
```
bjorn2scan_image_scan_status{deployment_uuid="abc-123",scan_status="completed"} 26
bjorn2scan_image_scan_status{deployment_uuid="abc-123",scan_status="pending"} 0
```

**Configuration**:
- Helm: `scanServer.config.metrics.imageScanStatusEnabled: true`
- Environment: `METRICS_IMAGE_SCAN_STATUS_ENABLED=true`

### 3. Vulnerability Metrics

#### `bjorn2scan_image_vulnerability`
Gauge metric reporting all vulnerabilities found in running container images. Value represents the number of vulnerability instances.

**Labels** — all 17, as emitted:
- `deployment_uuid`, `deployment_name`: Deployment identity
- `host_name`, `namespace`, `pod`, `container`: Where the container runs
- `image_reference`, `image_digest`, `distro`, `instance_type`: Which image
- `severity`: Vulnerability severity (Critical, High, Medium, Low, Negligible, Unknown)
- `vulnerability`: CVE ID (e.g., "CVE-2024-1234")
- `vulnerability_id`: Unique vulnerability identifier combining deployment UUID and vulnerability DB ID
- `package_name`: Affected package name
- `package_version`: Affected package version
- `fix_status`: Fix availability ("fixed", "not-fixed", "wont-fix", "unknown")
- `fixed_version`: Version with fix (empty if none)

Unlike the node equivalent, the image metrics carry **no `package_type`** label.

**Example**:
```
bjorn2scan_image_vulnerability{deployment_uuid="abc-123",deployment_name="prod-cluster",host_name="node-1",namespace="frontend",pod="web-app",container="nginx",image_reference="nginx:1.25",image_digest="sha256:abc123...",distro="debian",instance_type="CONTAINER",severity="Critical",vulnerability="CVE-2024-1234",vulnerability_id="abc-123.42",package_name="openssl",package_version="3.0.0",fix_status="fixed",fixed_version="3.0.13"} 2
```

The value is the **instance count** — how many running containers share this
finding — not a boolean. It is frequently greater than 1.

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

### 4. Node Metrics

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

**Labels** — all 13, as emitted. This is a **subset** of `bjorn2scan_node_scanned`
plus the finding fields: `kernel_version`, `architecture` and `instance_type` are
deliberately *not* repeated here (see [Removed labels
(2026-08-20)](#removed-labels-2026-08-20--breaking)).
- `deployment_uuid`, `deployment_name`: Deployment identity
- `node`: Kubernetes node name
- `hostname`: Node hostname
- `os_release`: OS version (e.g., "Ubuntu 24.04.3 LTS")
- `severity`: Vulnerability severity (Critical, High, Medium, Low, Negligible, Unknown)
- `vulnerability`: CVE ID (e.g., "CVE-2024-1234")
- `vulnerability_id`: Unique identifier combining deployment UUID and vulnerability DB ID
- `package_name`: Affected package name
- `package_version`: Affected package version
- `package_type`: Package type (deb, rpm, apk, etc.)
- `fix_status`: Fix availability ("fixed", "not-fixed", "unknown")
- `fixed_version`: Version with fix (empty if none)

**Example**:
```
bjorn2scan_node_vulnerability{deployment_name="Kubeadm",deployment_uuid="abc-123",fix_status="not-fixed",fixed_version="",hostname="kubeadm-controlplane",node="kubeadm-controlplane",os_release="Ubuntu 24.04.3 LTS",package_name="linux-tools-6.8.0-137-generic",package_type="deb",package_version="6.8.0-137.137",severity="Low",vulnerability="CVE-2012-4542",vulnerability_id="abc-123.345690"} 1
```

One CVE typically produces **several series per node**, one per affected package —
a kernel CVE on Ubuntu commonly matches a dozen `linux-*` packages. Deduplicate
before counting:

```promql
count(count by (node, vulnerability) (bjorn2scan_node_vulnerability))
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

#### `bjorn2scan_node_scan_status`
Gauge metric counting nodes grouped by scan status. Mirrors
`bjorn2scan_image_scan_status`, zero-filled across every known status.

**Labels**:
- `deployment_uuid`: Unique deployment identifier
- `scan_status`: One of `completed`, `scanning_vulnerabilities`, `generating_sbom`,
  `pending`, `sbom_failed`, `sbom_unavailable`, `vuln_scan_failed`

**Example**:
```
bjorn2scan_node_scan_status{deployment_uuid="abc-123",scan_status="completed"} 6
```

**Configuration**:
- Environment: `METRICS_NODE_SCAN_STATUS_ENABLED=true` (default true)
- Note: there is currently **no Helm value** for this toggle — the chart does not
  set the environment variable, so it always runs at the built-in default. Add
  `nodeScanStatusEnabled` to `values.yaml` if it needs to be configurable.

### 5. Database Performance Metrics

Histograms measuring time spent in SQLite operations, labelled by `operation`.
Always exported — there is no configuration toggle — but **`/metrics` only**:
these are not carried by the OTLP push. These are what
`docs/RUNBOOKS.md` and the `validate-deployments` workflow use to judge whether a
deployment is healthy.

#### `bjorn2scan_db_write_wait_seconds`
Time spent waiting to acquire the write mutex. All writes are serialized at the Go
level, so a growing wait means a long transaction is holding the lock.

#### `bjorn2scan_db_write_exec_seconds`
Time spent holding the write mutex — i.e. executing the transaction. This is where
slow operations show up: on a large cluster `apply_staleness_diff` has been
measured at ~177 s/call and `store_node_vulnerabilities` at ~57 s/call.

#### `bjorn2scan_db_read_seconds`
Time spent in read operations, notably the streaming reads that back metric
generation.

**Labels**: `operation` (plus `le` on the `_bucket` series)

Observed `operation` values include `add_container`, `apply_staleness_diff`,
`reap_stuck_scans`, `remove_container`, `reset_interrupted_scans`,
`set_containers`, `store_image_packages`, `store_image_vulnerabilities`,
`store_sbom`, `store_sbom_blob`, `store_vulnerabilities`,
`store_vulnerabilities_blob`, `stream_scanned_containers`,
`update_last_scanned_at`, `update_status`. The set grows with the code; treat it
as open.

**Example**:
```
bjorn2scan_db_write_exec_seconds_bucket{operation="store_image_vulnerabilities",le="0.5"} 58
bjorn2scan_db_write_exec_seconds_sum{operation="store_image_vulnerabilities"} 5.266
bjorn2scan_db_write_exec_seconds_count{operation="store_image_vulnerabilities"} 60
```

**Useful queries**:
```promql
# Mean duration per operation
rate(bjorn2scan_db_write_exec_seconds_sum[1h])
  / rate(bjorn2scan_db_write_exec_seconds_count[1h])

# Operations spending the most total time
topk(5, bjorn2scan_db_write_exec_seconds_sum)

# Lock contention
topk(5, bjorn2scan_db_write_wait_seconds_sum)
```

### 6. Go Runtime Metrics

Memory and GC counters for the scanner process, exposed on `/metrics` only.
Names follow the `client_golang` convention so existing dashboards work, but the
exposition is hand-rolled to match the rest of the package and to keep the series
count deliberate: **14 fixed, label-free series** rather than the ~80 the standard
collector emits. Cardinality is the problem this project is about; its own
diagnostics should not contribute to it.

These exist because memory, not latency, is this exporter's binding constraint —
a large deployment sits near 2.6 GiB against a 4 GiB limit while using 2.4% of its
push interval.

| Metric | Type | Use |
|---|---|---|
| `go_memstats_heap_alloc_bytes` | gauge | live heap |
| `go_memstats_heap_inuse_bytes` | gauge | in-use spans; minus heap_alloc is fragmentation |
| `go_memstats_heap_sys_bytes` | gauge | heap obtained from the OS |
| `go_memstats_heap_released_bytes` | gauge | returned to the OS |
| `go_memstats_heap_objects` | gauge | live object count |
| `go_memstats_next_gc_bytes` | gauge | GC target; ~2x the live set at GOGC=100 |
| `go_memstats_alloc_bytes_total` | counter | **cumulative allocation — its rate is the garbage rate** |
| `go_memstats_mallocs_total` / `_frees_total` | counter | object churn |
| `go_memstats_stack_inuse_bytes` | gauge | goroutine stacks |
| `go_memstats_sys_bytes` | gauge | total from the OS; reconciles against RSS |
| `go_gc_cycles_total` | counter | completed GC cycles |
| `go_gc_pause_seconds_total` | counter | cumulative stop-the-world time |
| `go_goroutines` | gauge | goroutine count |
| `go_memlimit_bytes` | gauge | emitted only when GOMEMLIMIT is set |

**Useful queries**:
```promql
# Garbage rate — bytes allocated per second
rate(go_memstats_alloc_bytes_total[15m])

# Headroom against the container limit
go_memstats_sys_bytes / on() group_left() go_memlimit_bytes

# Fragmentation
go_memstats_heap_inuse_bytes - go_memstats_heap_alloc_bytes
```

**Heap profiles**: `/debug/pprof/heap` is registered when `debugEnabled` is set,
alongside the other debug endpoints. `go_memstats_*` shows totals; only a profile
attributes them to call sites. It stays behind the debug flag because profiles can
expose label values held in memory.

### 7. Aggregated Queries

While there are no dedicated total metrics, you can derive counts using PromQL:

#### Count Total Instances
```promql
count(bjorn2scan_image_scanned)
```

#### Count Unique Images
```promql
count(count by (image_digest) (bjorn2scan_image_scanned))
```

#### Count Instances by Namespace
```promql
count by (namespace) (bjorn2scan_image_scanned)
```

#### Count Images by Scan Status
Scan status is its own metric now, so this is a direct read rather than an
aggregation over instances:
```promql
bjorn2scan_image_scan_status
```

#### Count Failed Scans
```promql
sum(bjorn2scan_image_scan_status{scan_status=~"sbom_failed|vuln_scan_failed|sbom_unavailable"})
```

#### Count Pending Scans
```promql
bjorn2scan_image_scan_status{scan_status="pending"}
```

## Implementation Architecture

### Package Structure
```
scanner-core/
  metrics/
    collect.go        # Gathers metric data from the database
    format.go         # Prometheus text exposition rendering
    handler.go        # HTTP handler for /metrics endpoint
    metrics.go        # Metric definitions and label construction
    otel.go           # OTLP push orchestration and per-export logging
    otel_direct.go    # OTLP encoding, compression, transport
    stream.go         # Streaming generation for the large vulnerability families
    tracker.go        # Staleness tracking between pushes
    types.go          # Shared types and the provider interface
  database/
    db_metrics.go     # bjorn2scan_db_* histograms
```

### Data Flow
1. HTTP request to `/metrics`
2. Handler calls collector's `Collect()` method
3. Collector queries database for current state
4. Metrics are generated with appropriate labels
5. Prometheus text format is written to response

### Performance Considerations

- **No caching.** Metrics are computed on every scrape, straight from the
  database. The large vulnerability families are generated by `stream.go`, which
  writes them out incrementally rather than materialising the whole payload in
  memory.
- **Size scales with findings × packages, not with cluster size.** A 6-node
  kubeadm cluster with 29 images produced a **293 MB, 17-second** scrape,
  dominated by `bjorn2scan_node_vulnerability{,_risk}` at 91% of the bytes.
  Measure your own before assuming it is small.
- **Scrape interval and timeout must fit the payload.** A 30s interval against a
  17s scrape leaves almost no headroom, and an over-aggressive scrape has
  previously timed out and knocked the deployment's health checks over. Set
  `scrape_timeout` above your measured scrape time and the interval well above
  that — for large deployments prefer the OTLP push (default 5m for Kubernetes)
  and treat `/metrics` as a debugging endpoint.
- **Check before you tune**: `curl -s -o /dev/null -w '%{size_download} %{time_total}\n' http://<host>/metrics`

## Configuration

No additional configuration required. The `/metrics` endpoint is automatically registered when the HTTP server starts.

## Example Prometheus Configuration

Note the intervals: these are sized for a scrape that can take tens of seconds
and return hundreds of megabytes. The defaults most people reach for (30s / 10s)
will time out on a large deployment and take the target down with them.

```yaml
scrape_configs:
  - job_name: 'bjorn2scan-agent'
    static_configs:
      - targets: ['agent-host:9999']
    scrape_interval: 5m
    scrape_timeout: 2m

  - job_name: 'bjorn2scan-k8s'
    kubernetes_sd_configs:
      - role: service
    scrape_interval: 5m
    scrape_timeout: 2m
    relabel_configs:
      - source_labels: [__meta_kubernetes_service_label_app]
        regex: bjorn2scan
        action: keep
```

For anything beyond a small deployment, prefer the OTLP push over scraping.

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
count by (namespace) (bjorn2scan_image_scanned)
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
