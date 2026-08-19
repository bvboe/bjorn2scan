# bjorn2scan TODO List

## Active Tasks
- [ ] None currently

## In Progress
- [ ] None currently

## Backlog

### Production Readiness (v2.0.x → prod hardening)
From the 2026-06-18 defaults review. **Organizing principle:** flip to *secure-and-production by default*, with an explicit opt-in `devMode` (one Helm flag + one agent config flag) that re-enables debug endpoints, looser verification, and aggressive intervals. Dev becomes the documented exception. Most items below are individual defaults that flip under that principle.

#### Tier 1 — Must fix before calling v2 "production-ready"
- [x] **Disable debug endpoints by default** — DONE: `helm/bjorn2scan/values.yaml:105` is `debugEnabled: false` (code default `scanner-core/config/config.go:98` also `false`), so unauthenticated `/api/debug/sql` is off by default; any deployment running with it on is an explicit opt-in. The read-only SQL restriction (`sql_validator.go`) was intentionally **waived** (2026-06-26): write access under debug is occasionally useful, and the scanner DB is fully reconstructible (no backups — resetting the install rebuilds all data over time), so the worst case from a bad debug write is self-healing. `ValidateQuery` deliberately keeps allowing all statement types.
- [x] **[BUG] Gate the always-on destructive debug endpoints** — DONE: `JobsTriggerHandler` (`POST /api/debug/jobs/{name}/trigger`) and `DatabaseReinitHandler` (`POST /api/debug/db/reinit`, wipes/re-downloads vuln DB) now take a `*debug.DebugConfig` and return `403 "Debug mode not enabled"` when debug is off — same pattern as `DebugSQLHandler`. Read-only siblings (`/ready`, `/api/db/status`, `/api/debug/jobs`, `/api/debug/jobs/history`) stay always-on. Wired through `RegisterDatabaseReadinessHandlers` / `RegisterJobsHandlers[WithDB]` in both `k8s-scan-server` and `bjorn2scan-agent`. Since `debugEnabled` defaults to `false`, these are now off by default. Regression test: `TestDestructiveDebugEndpointsAreGated` (handlers). Gating chosen over auth, consistent with the rest of the debug surface.
- [x] **Tighten the cosign identity regexp** — DONE: anchored, tag-only `^https://github\.com/bvboe/bjorn2scan/\.github/workflows/[^@]+@refs/tags/.+$` applied across `config.go` (×2), `values.yaml`, the update-controller configmap, `agent.conf.example`, tests, and the docs' cosign-verify examples. Verified it cosign-verifies the real v2.0.1 chart (`release.yaml` signer) and agent binary (`go-binary-reusable.yaml` signer), and that a too-tight (release.yaml-only) regexp correctly fails the agent.
- [x] **Add scan-server securityContext/podSecurityContext** — DONE: `values.yaml` now sets pod `runAsNonRoot/runAsUser/runAsGroup/fsGroup: 65532` + `seccompProfile: RuntimeDefault`, and container `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, `runAsNonRoot/runAsUser: 65532` (the deployment template already wired both blocks). Works because the image is the nonroot Chainguard static base (uid 65532) and all writes go to the data PVC (`/var/lib/bjorn2scan`), grype-cache (`/var/cache/grype`), and `/tmp` volumes. Now Pod Security "restricted"-compliant. `helm lint`/`template` verified; **`readOnlyRootFilesystem` runtime-validated by CI's kind/minikube integration tests** (the scan-server can't run outside a cluster, so it isn't locally smoke-testable).
- [x] **Agent listener: configurable bind + mutating endpoints gated — DONE.** Two parts: (1) the mutating `POST /api/update/{trigger,pause,resume}` endpoints are gated behind debug mode (off by default → `403`), mirroring the scan-server's destructive-endpoint gating — `registerUpdaterHandlers` takes `debugConfig`, `test-agent-updater` runs with `debug_enabled=true`, `agent.conf.example` documents it. (2) the listener bind is configurable via `listen_address` / `LISTEN_ADDRESS` (`scanner-core/config`), **default `0.0.0.0`** to keep it easy to use and preserve the fleet's remote health-checks. Operators harden by setting `listen_address=127.0.0.1` (loopback only — verified on macOS that the socket then binds `127.0.0.1:port` vs `*:port`) or disabling the API entirely with `web_ui_enabled=false`; metrics still flow via Prometheus push, so direct API access is optional. **No token auth — by decision** (key-rotation overhead not worth it). Net: the read-only API stays network-exposed by default (accepted, documented trade-off), but mutation is closed by default and hardening is one config line.
- [x] **Default auto-update OFF for production** — WON'T DO (keep ON by decision): auto-update stays enabled by default to minimize operational overhead ("it's just an agent"). Instead, documented the trade-off for operators who want full control in `docs/AUTO_UPDATE.md` → new **RBAC & Privilege Surface** section: spells out the broad ClusterRole that `updateController.enabled` grants (cluster-wide write on `secrets` + `clusterroles`/`clusterrolebindings` = privilege-escalation surface, on the long-running scan-server SA), and how to drop it (`updateController.enabled=false` + self-driven `helm upgrade`) or constrain/audit it. **RBAC scoping — two-step migration (stage N DONE):** the broad write perms (secrets, clusterroles/clusterrolebindings, workloads) now live on a dedicated `*-update-controller` ServiceAccount + ClusterRole used only by the CronJob (`templates/update-controller-rbac.yaml`), which also mirrors the scan-server's *read* perms (pods/pods-status/nodes) so it can rewrite the scan-server ClusterRole during upgrades **without** the dangerous `escalate`/`bind` verbs. **Why two-step (verified on kind):** doing the de-privileging in one release breaks the FIRST auto-update — the *old* controller runs `helm upgrade` **as the scan-server SA**, and stripping that SA's own perms mid-upgrade leaves helm unable to even write its release Secret (`✗ RBAC INSUFFICIENT`). So this (stage N) release **temporarily keeps** the broad block on the scan-server ClusterRole (gated on `updateController.enabled`, clearly marked `TRANSITION` in `templates/clusterrole.yaml`). Stage N+1 (next release — see action item below) removes that block; by then the CronJob already runs as the dedicated SA, so removing the scan-server SA's perms no longer de-privileges the upgrader. Full `old → N → N+1` path + read-only end state validated on kind.
- [x] **Stage N+1 of the update-controller RBAC migration — DONE: transition block deleted.** Removed the `{{- if .Values.updateController.enabled }}` broad-perms block from `templates/clusterrole.yaml`; the scan-server ClusterRole is now read-only (pods + pods/status + nodes + services:[get]) — the real end state, so the long-running scan-server / pod-scanner no longer carry any write/privilege-escalation surface. `templates/update-controller-rbac.yaml` left untouched: it keeps the broad write perms **and** the mirrored scan-server read perms (pods/pods-status/nodes), which the dedicated SA needs to rewrite the scan-server ClusterRole during upgrades without `escalate`/`bind`. Shipped only **after** the stage-N release was out, so clusters auto-update `old → N → N+1` one step at a time (a cluster that jumped straight `old → N+1` would hit the self-de-privileging hazard — by design we waited for N to land first). Re-validated on kind: the `N → N+1` upgrade performed by the dedicated SA succeeds and leaves the scan-server SA unable to create secrets/clusterrolebindings.

#### Tier 2 — Should change
- [ ] **HTTP server timeouts** on scan-server (`k8s-scan-server/main.go:603`) — set Read/Write/Idle/ReadHeader timeouts (slowloris/resource exhaustion).
- [x] **OTEL `insecure: true` → `false`** by default — DONE: consistent across all locations — `scanner-core/config/config.go:142` `OTELMetricsInsecure: false` (one package feeding both scan-server and agent), `helm/bjorn2scan/values.yaml:115` `insecure: false` (wired via `OTEL_METRICS_INSECURE`), and `bjorn2scan-agent/agent.conf.example:178` `otel_metrics_insecure=false`. Repo-wide scan confirms no remaining `insecure…true` default.
- [ ] **PodDisruptionBudget for scan-server** — it's a SQLite singleton (can't just scale), but a node drain silently evicts it (+~10min WAL recovery). Ship a PDB and document the singleton constraint. _(On hold 2026-06-28 — will be folded into the production deployment guide below as the singleton/no-HA constraint + PDB guidance.)_
- [x] **Agent: run as dedicated user + systemd hardening** — DONE (mostly):
  - **systemd hardening** is in place on `bjorn2scan-agent.service` (`ProtectSystem=strict` + scoped `ReadWritePaths`, `NoNewPrivileges`, `ProtectHome=read-only`, `ProtectKernel*`, `ProtectControlGroups`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies`, `RestrictSUIDSGID`, `LockPersonality`, …); `-compat.service` carries the v219-safe subset.
  - **"Dedicated user" resolved by removing the orphan**: the agent must stay `User=root` (it scans the whole host filesystem) — documented in the unit. The unused `bjorn2scan` user **and group** are removed from `install.sh` (nothing chown'd to them; logrotate uses `copytruncate`).
  - **install.sh hardening**: self-contained install — unit/config/logrotate now bundled into the signed release tarball via a new `extra-files` input on `go-binary-reusable.yaml` (install.sh prefers the bundled copy, falls back to the pinned `v${VERSION}` ref); `set -eu` + `umask 022`; `agent.conf` → `640`; robust systemd-version parse; README "verify the installer" note + install-path fix.
  - **Deferred** (need test-host validation, noted in the unit): `SystemCallFilter`, `CapabilityBoundingSet`. **Skipped by decision**: cosign in install.sh (most hosts lack it; the auto-updater already cosign-verifies). The full **non-root via `CAP_DAC_READ_SEARCH` + `docker` group** path remains an unproven future experiment.
- [ ] **Prerelease auto-install guard** — the agent's `releases.atom` parser doesn't filter prereleases (`bjorn2scan-agent/updater/atom_feed.go`); a published prerelease would auto-install. Filter, or ensure none are published.
- [ ] **DaemonSet `maxUnavailable: 100%` → 25%** (`pod-scanner-daemonset.yaml:12`) so a bad pod-scanner image doesn't drop node scanning fleet-wide at once.
- [ ] **install.sh: fetch unit/config/logrotate from the release tag**, not `main` (`bjorn2scan-agent/install.sh:306,377,400`) — reproducible, non-drifting installs.

#### Tier 3 — Polish / document
- [ ] Pin Docker base images by `@sha256:` digest (currently `cgr.dev/chainguard/*:latest` in all 4 Dockerfiles — minimal/nonroot already, so low risk).
- [ ] Document that the dashboard + all `/api/*` endpoints are unauthenticated (fine at the ClusterIP default) — must front with auth before any LoadBalancer/NodePort exposure.
- [ ] Agent log file perms `0644` → `0640`/`0600` (`bjorn2scan-agent/main.go:247`); revisit 7-day log retention.
- [ ] Add `-trimpath` to Go builds; set a meaningful default `clusterName` (currently `"kubernetes"`). (Auto-update interval default resolved → 24h across values.yaml/agent.conf.example/config.go; `// Todo - revert` removed.)

#### Inherent risk — document the trade-off (not a simple flip)
- [ ] **pod-scanner DaemonSet runs `privileged: true` + root** with host-root read mount + runtime sockets (`values.yaml:219-221`). Genuinely needs elevation for SBOM scanning, but `privileged` is broader than necessary — tighten to specific caps + socket group where feasible, make node scanning opt-in, and document the accepted trade-off. _(On hold 2026-06-28 — agreed approach: drop `privileged:true` → `capabilities.add:[DAC_READ_SEARCH]` + `readOnlyRootFilesystem`, keep the host-root RO mount + runtime socket, make node scanning opt-in. MUST kind-test that a host/node SBOM still completes before committing — this can break host scanning.)_

#### Beyond defaults — additional production-readiness gaps
From the 2026-06-18 follow-up review. These need *new* work, not just default flips; each was verified as currently missing. (Graceful shutdown, cleanup/retention jobs, and some operational metrics already exist, so they're excluded.)

**Security & access**
- [ ] **Authn/authz for the dashboard + all `/api/*`** — currently none. Ship optional built-in auth (or a first-class authenticating-ingress example + token). Highest-impact gap: the service exposes the full cluster vuln inventory + SBOMs. _(On hold 2026-06-28 — explicitly deferred.)_
- [ ] **NetworkPolicy template** — none in the chart. Default-deny ingress (allow only Prometheus/ingress) + scoped egress. _(On hold 2026-06-28 — agreed proposal: opt-in `networkPolicy.enabled:false`; default-deny ingress + explicit allows — scan-server `:8080` ← ingress/Prometheus/pod-scanner; egress → DNS, kube-apiserver, `:443` (GHCR/GitHub), OTEL `:9090`. Document the FQDN-egress limitation: vanilla NetworkPolicy is IP/CIDR-only, so GHCR/GitHub egress can't be FQDN-pinned without an FQDN-aware CNI.)_
- [ ] **`SECURITY.md` + vulnerability-disclosure policy** — none at repo root (only `LICENSE`). Also consider publishing SLSA provenance attestations on the images (already cosign-signed).

**Operations & data**
- [x] **Backup & restore / DR for the scan DB** — WON'T DO (2026-06-26): the scan DB holds only derived data and fully reconstructs by rescanning, so it is not a system of record worth backing up. Worst case, reset the install and the data rebuilds over time. No backup/restore/DR needed by design.
- [ ] **Air-gapped / restricted-egress support + documented egress requirements** — signature verification fetches the Sigstore TUF root from `tuf.sigstore.dev` (`bjorn2scan-agent/updater/verifier.go:48`, `k8s-update-controller/controller/registry_client.go`), plus Grype-DB downloads and GitHub for auto-update. No offline mode or documented egress allowlist — blocks regulated/disconnected clusters.
- [ ] **Auto-update rollback ↔ DB-migration safety** — migrations are forward-only (`scanner-core/database/migrations.go`) but the update controller auto-rolls-back the chart on health-check failure; old code against a migrated DB can break. _(On hold 2026-06-28 — agreed approach: NO down-migrations. The DB is reconstructible, so on startup, if the DB's schema version > the code's max known migration (rolled back onto a newer DB), wipe+recreate the DB and let rescans rebuild it. Gate `db_reset_on_downgrade` (default true); one shared `scanner-core/database` path covers both scan-server and agent. Kind-testable: deploy vN, roll image back to vN-1, confirm reset+recovery.)_

**Chart quality & safety**
- [ ] **`values.schema.json`** — none; typos/wrong-typed values are silently accepted at install/upgrade. Add a schema to catch misconfig early.
- [ ] **`values-production.yaml` example + `helm test` hooks** — a vetted production baseline + an install smoke test. _(On hold 2026-06-28 — agreed plan: `values-production.yaml` overlay (PDB + NetworkPolicy enabled, `debugEnabled:false`, tuned resources/persistence, OTEL endpoint set, controlled auto-update posture, host-scanning opt-in); `templates/tests/test-connection.yaml` with `helm.sh/hook: test` curling `/health` + `/api/config` and asserting the update-controller SA exists.)_

**Quality gates**
- [ ] **Dogfood: scan our own images in CI and gate on criticals** — CI validates that Grype/Syft work but doesn't scan the bjorn2scan images themselves for CVEs. A scanner should scan itself.

**Observability & docs**
- [ ] **Self-observability + alerting** — expand operational metrics (queue depth, scan-duration histogram, last-successful-scan age, DB/WAL size) and ship example Prometheus alert rules / SLOs. (Some exist today: `vuln_scan_failed`, `scan_status`.)
- [ ] **Production deployment guide** (`docs/`) — prod install guide covering resource sizing by cluster size, the singleton/HA constraints, hardening, **documented scale limits** (max images/nodes the SQLite singleton is tested to), and PVC capacity planning. _(On hold 2026-06-28 — planned as new `docs/PRODUCTION.md`: sizing, the SQLite singleton/no-HA constraint + PDB guidance (absorbs the PDB item above), the hardened posture (securityContext + scoped update-controller RBAC + NetworkPolicy), documented scale limits, PVC capacity, and the auto-update/rollback story.)_

### Data & OTEL Architecture (2026-08-19 review)

Full analysis, measurements, options, and trade-offs: **`docs/OTEL-DATA-ARCHITECTURE.md`**.
Short version: the bottleneck is not the storage engine (reads are already cached,
staleness is already diff-based) but the **export encoding** — 99.8% of the 666k
series on kubeadm are per-finding gauges whose value is always 1, forcing 288
retransmissions/day of data that changes once a day. Measured `/metrics`: kubeadm
**383 MB / 666,445 series**; chainguard 313 KB / 943 (same code — volume tracks
finding count). Constraint: aggregating detail away is **not** acceptable as a
default — carrying full vulnerability detail over OTEL is the project's hypothesis,
and with agent UIs disabled upstream is the only place to answer "which deployments
have CVE-X" / "what's in container Y".

**Do first — no fidelity loss, non-breaking:**
- [ ] **Enable OTLP wire compression** — there is none today (`otel_direct.go` sets only `Content-Type: application/x-protobuf`; the gRPC client sets no compressor). Payload is pathologically compressible (`deployment_uuid` appears in 7 attributes on every one of 666k datapoints). Highest value/effort ratio in this whole list.
- [ ] **Stop duplicating invariant attributes** — `deployment.name`/`deployment.uuid` are on the OTLP Resource *and* repeated on every datapoint; move everything deployment-invariant to the Resource only.

- [ ] **Delete `deployment_uuid_namespace_image_digest`** — emitted on every image datapoint, **used by zero dashboard panels** (audited 2026-08-19). Non-breaking.
- [ ] **Fix the dead `deployment_uuid_namespace_image_id` reference** in `docs/grafana-*-dashboard.json` — referenced by dashboards, never emitted by code (drift from an old rename).
- [ ] **One OTLP Resource per scanned entity** — 83% of payload is node findings carrying 7 per-node invariants (`os_release`, `kernel_version`, `hostname`, `node`, `architecture`, …) on all 630k datapoints. Today there's a single Resource for the whole scan-server, so subject identity is stuffed into every datapoint; OTLP allows multiple `ResourceMetrics` per request. Verify how the target backend surfaces resource attributes first (Prometheus uses `target_info` / `promote_resource_attributes`).

**Breaking — needs a dashboard migration (see the doc's Migration section):**
- [ ] **Drop the 5 remaining composite `deployment_uuid_*` attributes** — they are Grafana `joinByField` keys (that transform joins on a single field only), not query denormalization. Replace with PromQL `label_join(...)` at query time: same capability, zero wire cost, multi-panel edit. Note these are only ~11% of payload — the node-side Resource fix above is the bigger win. Update `docs/grafana-*-dashboard.json` + `docs/PROMETHEUS_METRICS.md` in lockstep.
- [ ] **Add the OTLP logs signal for findings** (currently metrics-only) and move to a tiered export: aggregates always on, findings-as-events default on, SBOM opt-in. Preserves both required queries; removes the cardinality penalty.
- [ ] **Match cadence to change rate** — emit on change + daily resync aligned with the 24h rescan (~288× volume reduction, zero fidelity loss). Requires specifying the delta/resync contract.

**Larger restructuring:**
- [ ] **Content-address scan results** by `(artifact_digest, grype_db_version)`; instances reference a result. Measures homogeneity rather than assuming it (kubeadm's 6 nodes → 2 distinct package sets), so it stays correct under host-filesystem drift and doubles as a drift detector. Keep per-instance observation timestamps separate from per-content scan timestamps.
- [ ] **Split hot aggregate tier from cold detail tier** — rollups drive UI/metrics; full findings + SBOM stay as compressed blobs read only for detail pages. Unlocked by the logs-signal work above.
- [ ] **Decide SBOM-over-OTEL encoding before building it** — a real node SBOM is 15.6 MB; 100 nodes × per-cycle push ≈ 1.5 GB/cycle. Recommended: event carries digest+URI, object storage carries bytes. Note gRPC's 4 MB default max message size.
- [ ] Consider aligning finding events to **OCSF Vulnerability Finding** + OTel security semantic conventions (ingestible by Splunk/Elastic/Security Lake with no custom mapping).
- [ ] **Storage engine change: explicitly deferred** — re-measure only after the above. Postgres buys write concurrency we don't need (singleton writer).

**Prerequisite measurements (currently missing — everything above is estimated without them):**
- [ ] **DB + WAL size metric** — not exported today (see also the Self-observability item above, which lists it).
- [ ] Distinct `(digest, grype_db)` pairs vs total instance rows → exact dedup ratio.
- [ ] pprof one push cycle → confirms export-vs-DB split; note ~666k `map[string]string` allocations per cycle in the label builders.

**Schema / migration debt — investigated 2026-08-19, less than it appeared:**
- The `*_new` tables are **not** leftovers: each is created and `RENAME TO`'d away inside the same migration (standard SQLite table-rewrite idiom — no `ALTER COLUMN`). Actual state is 50 migrations over ~14 coherent tables, documented in `docs/SCANNER-CORE-DESIGN.md`. **No cleanup needed.**
- [ ] **Squash the migration chain to a single baseline — but bundle it with the data-model redesign, not as standalone cleanup.** A schema reset is a one-time budget; squashing now and restructuring later pays it twice. The wipe-on-mismatch machinery is already the agreed plan for the auto-update rollback item. Real costs: a wipe means full rescan (node scans 30–100s each, 1.5–2 GB peak, OOM history), and rollback across the reset boundary becomes impossible. Strongest argument in favor is reduced upgrade-time risk — the v25 migration bug caused 30k+ pod restarts.

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
