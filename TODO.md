# bjorn2scan TODO List

## Active Tasks
- [ ] None currently

## In Progress
- [ ] None currently

## Backlog

### Code Quality
- [x] **[BUG] `sbom-generator-shared` appears with unknown version in SBOM output**
  - [x] Investigate how version is embedded at build time for this module
  - [x] Fix so the correct version is reported in generated SBOMs

### Research Topics
- [ ] **[RESEARCH] Batched SBOM processing through Grype**
  - [ ] **Goal**: Reduce memory usage for large node SBOMs (52MB+) by batching
  - [ ] **Approach**: Split SBOM into chunks of ~1000 packages, run each through Grype separately, merge results
  - [ ] **Questions to answer**:
    - [ ] Can Grype handle partial SBOMs? (Does it need full SBOM context?)
    - [ ] How to split SBOM JSON correctly? (Preserve relationships, metadata)
    - [ ] Will merged results be identical to single-pass results?
    - [ ] What about cross-package vulnerabilities?
    - [ ] Impact on scan duration? (Multiple Grype invocations vs. one)
  - [ ] **Risk**: COMPLEX - Grype may rely on full SBOM context for accuracy
  - [ ] **Benefit**: Could reduce peak memory from 1.5GB → 200MB per scan
  - [ ] **Status**: Research only - implement AFTER basic batching fixes proven
  - [ ] **Related**: Node SBOM memory investigation (Test 2.1 results)

### Performance & Stability
- [ ] Cache `/api/summary/*` endpoints with write-triggered invalidation
  - [ ] Apply same notifyWrite() pattern to summary endpoints (scan-status, by-namespace, by-distribution)
  - [ ] These hit the DB on every UI load; caching eliminates read transactions during WAL-heavy periods
- [ ] Move OTEL staleness tracking entirely to memory (eliminate per-cycle bulk DB writes)
  - [ ] Track `last_seen_unix` per metric series in memory only
  - [ ] Only flush to DB when a series disappears (tombstone write) or on graceful shutdown
  - [ ] Eliminates ~6,500 WAL frames/5-min on k3s (~26,400 staleness rows rewritten every minute)
  - [ ] Risk: staleness state lost on crash; stale metrics may persist until next cycle flushes tombstones
- [ ] Improve log output format to show component before msg
  - [ ] Update `scanner-core/logging/logger.go` to customize slog handler field ordering
  - [ ] Update standalone loggers in `pod-scanner/main.go` and `k8s-update-controller/main.go`
  - [ ] Goal: Output format should be `component=X msg=Y` instead of `msg=Y component=X`
- [ ] Remove gomezboe.com dependency from grype database update tests
  - [ ] Replace `scripts/test-grype-db-updater` with self-contained unit tests
  - [ ] Consider mocking distribution.Client for IsUpdateAvailable tests
  - [ ] Or set up local test fixtures that don't require external hosting
- [ ] Use kube-system namespace UID as cluster_id in metrics (Kubernetes mode only)
  - [ ] Auto-detect cluster ID from kube-system namespace UID
  - [ ] Fall back to hostname or configurable ID for non-Kubernetes deployments
  - [ ] Add cluster_id label to relevant metrics
- [ ] Add host_ip tracking to metrics (requires storing Kubernetes node IP in database or querying K8s API)
- [ ] Clean up agent configuration management:
  - [ ] Make defaults.conf the single source of truth (embed in binary at compile time)
  - [ ] Move defaults from scanner-core to component-specific (agent, k8s-scan-server)
  - [ ] Ensure agent.conf.example matches actual code defaults
  - [ ] Add --show-config flag to display current configuration
- [ ] Test bjorn2scan-agent install.sh on major Linux distributions:
  - [X] Ubuntu 22.04/24.04 LTS
  - [X] Debian 11/12
  - [ ] Alpine Linux (BusyBox compatibility)
  - [ ] Amazon Linux 2/2023
  - [ ] RHEL/Rocky/AlmaLinux 8/9
  - [ ] Fedora (latest)
  - [ ] Raspberry Pi OS (ARM64)
- [ ] Other K8s distributions
  - [ ] GKE
  - [ ] EKS
  - [ ] AKS

## Recently Completed
- [x] [2026-03-25] Eliminated N+1 database queries and fixed WAL growth
  - Replaced `GetAllImageDetails` 1+N pattern (one vuln GROUP BY per image) with a single LEFT JOIN + conditional SUM query
  - Inlined COUNT subqueries in `GetNode`/`GetAllNodes`/`GetNodesNeedingRescan` — eliminated 2 extra `QueryRow` calls per node
  - Switched WAL checkpoint from PASSIVE to RESTART so the monitor makes progress while long-running readers (Prometheus scrapes, OTEL exports) are active
  - Lowered WAL warning threshold from 500k to 25k frames (~100MB)
  - Deleted dead code: `GetScannedContainers` and `GetContainerVulnerabilities` (streaming variants used everywhere)
- [x] [2026-03-23] Supply-chain security: cosign signature verification and image digest pinning
  - **Agent**: Real sigstore/sigstore-go verification in `bjorn2scan-agent/updater/verifier.go` — fetches Sigstore trusted root, verifies `.sigstore` bundle against tarball before extraction; on by default
  - **Controller**: Real sigstore/sigstore-go verification in `k8s-update-controller/controller/registry_client.go` — downloads bundle from GitHub releases via HTTP, verifies chart `.tgz` before applying; on by default
  - **Pipeline**: `go-binary-reusable.yaml` now emits `.sigstore` bundle (+ legacy `.sig`/`.cert`); `release.yaml` signs Helm chart `.tgz` as blob and uploads bundle to GitHub releases
  - **Image digest pinning**: `digest: ""` added to all 3 image blocks in `values.yaml`; templates use `repo@sha256:...` when set; release pipeline injects real digests via `docker buildx imagetools inspect` before `helm package`
  - **Config**: Added `releaseBaseURL` to update-controller config/types/defaults/configmap/values
- [x] [2026-03-23] Fast first-ready UX: async startup and Grype DB initialization
  - **Root cause**: Two blocking operations delayed HTTP server: `SyncInitialPods`/`SyncInitialNodes` API calls before server start (k8s-scan-server), and synchronous Grype init in agent
  - **Fix**: Removed redundant blocking sync calls — K8s informers already handle initial cache sync internally via `WaitForCacheSync`
  - **Fix**: Added async Grype initialization to bjorn2scan-agent (was previously missing entirely)
  - **Fix**: Wired `DatabaseReadinessState` into agent scan queue and rescan job
  - **Fix**: Reduced readiness probe from `initialDelaySeconds:10/periodSeconds:10` → `2/3` (was adding 10–20s of probe wait after server was already ready)
  - **Enhancement**: Added grey UI banner that shows while Grype DB is initializing, auto-dismisses when ready
  - **Enhancement**: Grype DB now defaults to data PVC (`/var/lib/bjorn2scan/grype/`) — persists across restarts, no re-download on upgrade
  - **Files**: `k8s-scan-server/main.go`, `bjorn2scan-agent/main.go`, `scanner-core/static/shared.js`, `helm/bjorn2scan/values.yaml`, helm templates
- [x] [2026-03-21] Resolved OOMKilled pod restarts during node vulnerability scanning
  - **Root cause**: Node scans require 1.5-2.0 GB peak memory for Grype vulnerability scanning, exceeding 2Gi pod limit
  - **Solution**: Increased scan-server memory limit from 2Gi → 3Gi in `helm/bjorn2scan/values.yaml`
  - **Enhancement**: Added `automemlimit` for automatic GOMEMLIMIT configuration based on cgroup limits
  - **Investigation**: Instrumented memory usage at granular level to identify exact spike location (Grype scan, not storage)
  - **Key finding**: Scanning is already single-threaded - OOM from single node scan, not concurrent scans
  - **Memory breakdown**: 277-387 MB heap, 1105-1747 MB system memory (2.9-4.5x ratio due to CGO/SQLite)
  - **Documentation**: Full investigation moved to `dev-local/oom-investigation/`
  - **Test results**: kubeadm-worker-1 scan completed successfully with 64% memory headroom
- [x] [2026-03-11] Implemented code simplification suggestions (net ~330 lines removed)
  - Created `scanner-core/handlers/queryhelpers.go` with shared SQL filter building helpers
  - Consolidated 4 CSV export functions into single `exportQueryResultAsCSV()` function
  - Extracted vulnerability label building in metrics with `buildVulnerabilityLabels()` helper
  - Refactored `buildImagesQuery`, `buildPodsQuery`, `buildNamespaceSummaryQuery`, `buildDistributionSummaryQuery`
  - Refactored `collectScannedContainerMetrics`, `collectVulnerabilityMetrics`, `collectVulnerabilityExploitedMetrics`, `collectVulnerabilityRiskMetrics`
- [x] [2026-03-11] Added integration tests for database migrations with realistic data
  - Created `scanner-core/database/migration_integration_test.go`
  - Tests populate database with realistic data before running migrations
  - Includes deadlock timeout detection (30 seconds)
  - Tests for v25 (architecture), v27 (reference), concurrent access, and large datasets
  - Addresses the v25 bug that caused 30k+ pod restarts in production
- [x] [2026-01-18] Fixed grype database timestamp handling issues
  - Added RFC3339 parsing support for grype v6 timestamps in `vulndb/database_updater.go`
  - Fixed stale timestamp issue in `grype/grype.go` by reading actual timestamp from SQLite after loading
  - Added `extractGrypeDBBuiltFromJSON()` in `database/scanning.go` to ensure `grype_db_built` column matches scan JSON
  - Root cause: grype's `LoadVulnerabilityDB()` returns cached/stale timestamps, causing repeated rescans every 30 minutes
- [x] [2026-01-03] Fixed agent auto-update failure caused by corrupted atom feed titles
  - Root cause: GitHub shows tag annotation content in `<title>` before release is created
  - Added `extractTagFromID()` and `isReleaseReady()` to handle tag vs release detection
- [x] [2026-01-03] Added `currentVersion` field to `/api/update/status` endpoint
- [x] [2026-01-03] Updated vulnerability metrics to multiply by instance count
- [x] [2025-12-30] Implemented Prometheus metrics endpoint at /metrics
- [x] [2025-12-30] Fixed release workflow race condition - implemented atomic release creation
- [x] [2025-12-30] Implemented updater asset availability validation with retry logic
- [x] [2025-12-29] Fixed URL filter parameter application and navigation in web UI
- [x] [2025-12-29] Fixed agent systemd service to work without Docker installed

---

**Notes:**
- This file persists across Claude conversation contexts
- Claude reads this at session start to understand current work
- Tasks move from Active → In Progress → Recently Completed
- Keep Recently Completed items for ~30 days for reference
