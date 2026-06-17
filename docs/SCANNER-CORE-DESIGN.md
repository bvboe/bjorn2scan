# Scanner-Core Design

> **⚠️ Work in progress.** This is a living redesign document, not a definitive
> spec. Parts may be aspirational or lag behind the current code — verify against
> the source before relying on details here.

This document describes how scanner-core works, the decisions behind its design,
and the constraints that must be respected when making changes.

---

## What scanner-core is

scanner-core is the shared Go library that implements all scanning, storage, and
metrics logic. It is not a standalone binary. Two binaries depend on it:

- **k8s-scan-server** — the Kubernetes deployment; receives container events from
  the pod-scanner DaemonSet and runs node host scans
- **bjorn2scan-agent** — the standalone agent; discovers containers via the local
  container runtime directly

scanner-core owns:
- The SQLite database (schema, migrations, all reads and writes)
- The scan job queue and execution pipeline
- Grype vulnerability database management
- Scheduled background jobs
- All HTTP API handlers
- Prometheus metrics collection and export

The callers (k8s-scan-server, bjorn2scan-agent) provide:
- An SBOM retriever callback — how to generate a container image SBOM (via Syft)
- A host SBOM retriever callback — how to generate a node host SBOM (optional)
- A container refresh trigger callback — how to get the current set of running containers
- Deployment metadata (cluster name, type, console URL)

scanner-core never calls Syft directly.

---

## Design principles

### Relationship to other components
Only k8s-scan-server and bjorn2scan-agent depends on scanner-core. No other components. It 
would be considered a major architectural decision to change that.

### Singleton deployment

scanner-core is designed to run as a single replica only. There is no distributed
coordination, no leader election, and no sharding. All concurrency is internal
(goroutines within one process). This is intentional — it keeps the system simple
and the SQLite database usable as the sole source of truth.

### Scalability within a single instance

The system must handle clusters of 1 node to 100+ nodes and 10 to 1000+ images
without configuration changes. This means:
- All queries must use indexes; no full table scans in hot paths
- No n+1 like query patters
- Metrics must stream from the database rather than load into memory — a large
  cluster can produce hundreds of thousands of vulnerability metric data points
- Write throughput matters less than read latency

### Low-latency reads

The UI and metrics endpoints must return quickly. Scans are long-running and happen
asynchronously in the background. A scan taking 5 minutes is acceptable; an API
response taking 5 seconds is not. Design decisions that trade write throughput for
read latency are correct.

### Grype is single-threaded and asynchronous

Grype loads its vulnerability database into memory and is not safe to call
concurrently. The scan queue enforces a single worker goroutine — only one scan
job (image or node) runs at a time. Grype is never called from an HTTP handler
or from any other concurrent path. Breaking this rule causes memory spikes, race
conditions, and instability.

### Recover from failure without intervention

The system must recover from any failure state on its own. This shapes several
concrete decisions:
- If the SQLite database is corrupt, delete it and restart with a clean slate
- If a scan crashes mid-flight, the interrupted job is reset to `pending` on
  startup and retried
- If the grype DB download fails, the next scheduled run will retry
- External intervention (manual deletion, kubectl exec) should never be required

All data in the database can be regenerated from scratch. SBOMs come from the
container runtime, vulnerability data comes from grype. The only data that cannot
be regenerated is historical scan timestamps.

### Availability is not a hard requirement

Restarts are treated as bugs and investigated, but they are survivable. It is
acceptable in extreme scenarios to reset the database entirely and rescan from
scratch. This allows the system to avoid defensive complexity that would otherwise
be required to maintain state across failures.

---

## Package structure

```
scanner-core/
  config/        Configuration loading (INI file + env var overrides)
  containers/    Container identity and image reference types
  database/      SQLite persistence — all reads and writes
  debug/         Debug HTTP endpoints (/debug/sql, /debug/metrics)
  deployment/    Deployment metadata (name, type, UUID, version)
  grype/         Grype wrapper — vulnerability scanning against an SBOM
  handlers/      HTTP API handlers (/api/images, /api/nodes, /metrics, etc.)
  jobs/          Scheduled job implementations
  logging/       Structured logging (slog-based, component-tagged)
  metrics/       Prometheus metric collection and OTEL export
  nodes/         Node/host scan data types
  scanning/      Scan queue, worker, and job dispatch
  scheduler/     Cron scheduler (wraps jobs with interval and timeout)
  sqlitedriver/  SQLite driver registration (modernc.org/sqlite, pure Go)
  vulndb/        Grype vulnerability database updater
  web/           Web UI (embedded static assets)
```

---

## Database

### Storage

scanner-core uses SQLite with WAL (Write-Ahead Logging) mode. WAL allows
concurrent readers while a write is in progress, which is important because
the `/metrics` endpoint streams vulnerability data while background jobs
are writing scan results.

The database is a single file (`containers.db`) stored at the path configured
via `DB_PATH`. The WAL and SHM sidecar files live alongside it.

Five connections are kept open (`SetMaxOpenConns(5)`). All write transactions
are serialized by an application-level `sync.Mutex` so SQLite's single-writer
constraint is never violated — extra connections only add read parallelism,
which WAL mode handles correctly. This ensures the health check and WAL monitor
always have a free slot even during concurrent streaming reads and writes.

Key pragmas:
```sql
PRAGMA journal_mode = WAL;       -- concurrent reads during writes
PRAGMA busy_timeout = 30000;     -- 30s wait before SQLITE_BUSY error
PRAGMA synchronous = NORMAL;     -- durable without fsync on every write
```

### Startup

On startup, the database goes through:
1. `PRAGMA wal_checkpoint(TRUNCATE)` — merges any leftover WAL from a previous
   crash into the main database file
2. `PRAGMA quick_check` — runs only if the WAL had unmerged frames (indicating
   an unclean shutdown such as an OOM kill). Skipped on clean restarts to avoid
   a multi-minute scan of large databases on slow NFS storage.
3. Schema migration — applies any pending migrations
4. Reset interrupted scans — images and nodes left in transient states
   (`generating_sbom`, `scanning_vulnerabilities`) are reset to `pending`
   so they are retried

### Corruption handling

If `quick_check` detects corruption, or if a write operation fails in a way
that indicates corruption, the process exits. The pod restarts, and on the
next startup the database files are deleted and recreated from scratch. All
data is rebuilt by rescanning.

A background WAL monitor checkpoints every 30 minutes and logs a warning if
the WAL grows beyond 25,000 unmerged frames (~100MB), which can indicate a
stalled write or an NFS rename issue.

### Schema and migrations

The schema is managed by versioned migrations in `database/migrations.go`.
Migrations run in sequence on startup. They are append-only — existing
migrations are never modified.

The schema has two main sides that mirror each other:

**Container image scanning:**
- `images` — one row per unique image digest; stores SBOM and vulnerability
  JSON blobs, scan status, OS info, grype DB timestamp
- `containers` — one row per running container; FK to `images`
- `packages` (→ `image_packages`) — parsed package inventory per image
- `package_details` (→ `image_package_details`) — extended package metadata
- `vulnerabilities` (→ `image_vulnerabilities`) — parsed vulnerabilities per image;
  stores `package_name/version/type` inline (denormalized)
- `vulnerability_details` (→ `image_vulnerability_details`) — extended vuln metadata

**Node/host scanning:**
- `nodes` — one row per cluster node; mirrors `images` in structure
- `node_packages` — package inventory per node
- `node_package_details` — extended package metadata
- `node_vulnerabilities` — vulnerabilities per node; currently uses a FK to
  `node_packages` (being changed to inline `package_name/version/type` to
  match the image side)
- `node_vulnerability_details` — extended vuln metadata

**Infrastructure:**
- `job_executions` — history of scheduled job runs
- `metric_staleness` — per-metric-series staleness tracking (see Metrics section)
- `app_state` — key/value store for persistent process state (e.g. grype DB timestamp)
- `schema_migrations` — applied migration versions

---

## Scan queue

All scanning work flows through a single serial queue in the `scanning` package.
One goroutine processes jobs one at a time. This is intentional: grype cannot
run concurrently, and serializing at the queue level eliminates an entire class
of resource contention.

That means that the majority of all write-intensive operations happens asynchronously.

### System Events

There are a number of events that are either scheduled or happen at certain points in the
lifecycle of the application that are important for the lifecycle of the application.

#### Scanner-core startup
The following steps happens synchronously and need to be completed in order for the application to be considered up and running.
* Initialize Grype Scanner (not including the GrypeDB)
* Database initialization (as described earlier in this document)

In addition to that, the following jobs are triggered asynchronously in this particular order.
* Trigger Update Grype DB job
* Trigger Re-Synchronize Images job
* Trigger Re-Synchronize Nodes job

#### New Container Instance
TBD

#### Remove Container Instance

#### New Node Instance

#### Remove Node Instance

#### Grype DB Update

#### Resynchronize image and node information

#### Purge old scan data


### Asynchronous Jobs

It's important to not that all jobs are idempotent. That means that any job can be executed one or more times, and the end-result will be the same.

#### Update Grype DB - Priority: High
This job's purpose is both to ensure that the Grype Database is up-to-date, and to detect whenever it changes.
If the database changes, or is initialized for the first time, then a rescan of all images and nodes is triggered.

The flow is something as follows:
* Run something similar to a "grype db update"
  * If no update is triggered, do nothing.
  * If the database is updated, either because it's loaded for the first time or there's new feed available, 
    trigger a rescan all images job and rescan all nodes job.

#### Re-Synchronize Images - Priority: High
It's purpose is to ensure that the image and container information in the database accurately reflects what's actually running.

The high-level flow is as follows:
* Load all running container information, either from K8s or wherever the agent gets it, this will require some kind of a call-back to k8s-scan-server and bjorn2scan-agent
* Compare this information with what's already in the database
* For every container not in the database, trigger a New Container Instance job
* For every container in the database that's no longer running, trigger Remove Container Instance job

#### Re-Synchronize Nodes - Priority: High
It's purpose is to ensure that the node information in the database accurately reflects what's actually running.

The high-level flow is as follows:
* Load all running node information, either from K8s or wherever the agent gets it, this will require some kind of a call-back to k8s-scan-server and bjorn2scan-agent
* Compare this information with what's already in the database
* For every node not in the database, trigger a New Node Instance job
* For every node in the database that's no longer running, trigger Remove Node Instance job

#### Trigger the 



#### Scan Image

#### Scan Job

| Job | Trigger | SBOM | Grype |
|-----|---------|------|-------|
| `ScanJob` | New container discovered | Generate new | Run |
| `ForceScanJob` | Grype DB updated | Reuse existing | Run |
| `HostScanJob` | Node added / periodic rescan | Generate new | Run |
| `HostForceScanJob` | Grype DB updated | Reuse existing | Run |
| `HostFullRescanJob` | Periodic full rescan | Generate new | Run |

### Queue depth

The queue is unbounded (`MaxDepth: 0`). Both k8s-scan-server and bjorn2scan-agent
use this default. A bounded mode exists in the code (`QueueFullDrop`,
`QueueFullDropOldest`, `QueueFullBlock`) but is not used in production.

### Image scan pipeline

```
1. Check existing SBOM
   ├─ ForceScan + SBOM exists → skip to step 3
   ├─ SBOM exists, no force  → nothing to do, return
   └─ No SBOM               → continue

2. Generate SBOM
   - Status → "generating_sbom"
   - Call sbomRetriever callback (provided by k8s-scan-server or agent)
   - Store SBOM JSON in images.sbom

3. Scan vulnerabilities
   - Status → "scanning_vulnerabilities"
   - Write SBOM to temp file
   - Call grype.ScanVulnerabilitiesWithConfig()
   - Store vulnerability JSON in images.vulnerabilities
   - Record grype DB timestamp on the image row

4. Status → "completed"
```

Timeout for an image scan: 5 minutes.

### Node/host scan pipeline

Mirrors the image pipeline with two differences:
- Timeout is 15 minutes (host filesystem enumeration is slow)
- Only one host scan job per node is allowed in the queue at a time; duplicate
  enqueues are silently dropped

---

## Grype vulnerability database

Grype's vulnerability database is downloaded and managed by the `vulndb` package.
The `DatabaseUpdater` uses grype's native distribution mechanism to check for
updates and download them.

### Storage location

The grype DB is stored separately from `containers.db`, by default on an `emptyDir`
volume (local container disk). This avoids NFS "silly rename" failures: grype
replaces its database file in-place during updates, which fails on NFS-backed PVCs.
If the DB is on NFS and a download fails mid-replace, the retry logic deletes the
existing DB before retrying — leaving the pod with no vulnerability database at all.

Storing the grype DB on local disk means it is re-downloaded on every pod restart
(~2 minutes). This is acceptable given the daily update cadence.

### Update detection

`CheckForUpdates()` is called every 30 minutes by the rescan-database job. It:

1. Loads the last known grype DB timestamp from `app_state` (persistent across restarts)
2. Calls grype's download/update mechanism
3. Reads the actual build timestamp directly from the SQLite metadata in the DB file
   (bypasses grype's in-memory cache which can return stale values)
4. Compares against the persisted timestamp to detect a real change
5. Saves the new timestamp to `app_state`
6. Returns `(hasChanged bool, error)`

The first run after a fresh download does not trigger a rescan — there is no
previous timestamp to compare against.

---

## Scheduled jobs

Jobs are managed by the `scheduler` package, which wraps each job with a configured
interval and a timeout. Job execution history is recorded in `job_executions`.

### rescan-database (default: every 30 minutes)

Checks whether the grype vulnerability database has been updated. If it has:
- Finds all images whose `grype_db_built` is older than the current DB timestamp
  (only images with running containers — orphaned images are excluded)
- Enqueues a `ForceScan` for each stale image (reuses SBOM, reruns grype only)
- Enqueues a `HostForceScan` for each completed node with a stale grype DB

This is the mechanism that keeps vulnerability data current without regenerating
SBOMs unnecessarily.

### refresh-images (default: every 6 hours)

Calls the container refresh trigger callback. The caller (agent or k8s-scan-server)
responds by pushing the current set of running containers back to scanner-core.
New containers are queued for scanning; containers that no longer exist are removed.

### cleanup (default: every 24 hours)

Removes orphaned images — images that have no associated containers. Also removes
their associated packages and vulnerabilities. This keeps the database from growing
unboundedly as container images are replaced.

---

## Metrics

### Collection model

scanner-core exports metrics in two ways:
- **Pull**: `/metrics` endpoint returns Prometheus-format text on demand
- **Push**: Background OTEL exporter pushes to a configured Prometheus endpoint
  on a configurable interval (default: 15 minutes)

The pull endpoint streams data directly from the database to the HTTP response
writer in chunks, without loading all rows into memory first. This is required
because a large cluster can produce hundreds of thousands of data points across
vulnerability metrics.

### Metrics emitted

| Metric | Description |
|--------|-------------|
| `bjorn2scan_deployment` | Deployment info label-set (version, type, grype DB timestamp, console URL) |
| `bjorn2scan_image_scanned` | One series per container (image reference, digest, namespace, pod, OS, arch) |
| `bjorn2scan_vulnerability` | Vulnerability count per container/image × severity |
| `bjorn2scan_vulnerability_risk` | Risk score × count per container/image × severity |
| `bjorn2scan_vulnerability_exploited` | Known-exploited vulnerability count per container/image |
| `bjorn2scan_image_scan_status` | Count of images per scan status |
| `bjorn2scan_node_scanned` | One series per node (hostname, OS, kernel, arch) |
| `bjorn2scan_node_vulnerability` | Vulnerability count per node × severity |
| `bjorn2scan_node_vulnerability_risk` | Risk score × count per node × severity |
| `bjorn2scan_node_vulnerability_exploited` | Known-exploited count per node |

### Staleness tracking

Prometheus has no built-in way to expire a time series when the underlying
entity disappears (a container is removed, a node is drained). Without handling
this, old series accumulate in Prometheus forever.

scanner-core tracks every emitted metric series in the `metric_staleness` table,
keyed by the family name and sorted label set. The lifecycle:

1. **Active series**: row exists with `expires_at_unix = NULL`
2. **Series disappears**: row updated to `expires_at_unix = now + staleness_window`
   (default 60 minutes)
3. **During grace period**: series still emitted as `NaN` so Prometheus marks it
   stale
4. **After expiry**: row deleted; series no longer emitted

When a series reappears (container rescheduled), its expiry is cleared. Stable
clusters with no churn produce zero database writes during metric collection.

### OTEL direct export

For large clusters, the standard OTEL SDK buffers all data points in memory before
exporting, which causes OOM on deployments with many nodes and high vulnerability
counts. The direct export mode bypasses SDK buffering by writing metric batches
directly to the Prometheus OTLP endpoint in configurable batch sizes (default:
5,000 data points per request).

---

## Configuration

Configuration is loaded from an INI file (`/etc/bjorn2scan/agent.conf` or
`./agent.conf`) with environment variable overrides. All settings have defaults
that work out of the box.

Key configuration areas:
- **Server**: port, DB path, debug endpoints, web UI
- **Jobs**: enable/disable each job, intervals, timeouts
- **Host scanning**: enable/disable, filesystem exclusion patterns, NFS auto-detection
- **Metrics**: OTEL endpoint, push interval, per-metric-family toggles,
  staleness window
- **Grype DB**: separate storage path override
