# OTEL Data Architecture — Findings and Options

> **⚠️ Work in progress.** This is a research/decision document from the
> 2026-08-19 data-scaling review, not an implementation spec. Nothing here has
> been built. Measurements are point-in-time and will drift — re-measure before
> acting on them.

This document records why the current data model does not scale, what was
measured, which constraints any redesign must respect, and the options
considered. It exists so the reasoning survives past the conversation that
produced it.

---

## The goal this must serve

A primary goal of bjorn2scan is to **demonstrate that OpenTelemetry can be used
to transport and analyze vulnerability information**. This is the hypothesis the
project exists to test, and it constrains every option below.

Consequences that are easy to get wrong:

- The agent is a **collector**, in the same role as a SIEM agent (Splunk UF,
  Elastic Beats, Datadog Agent). The central destination is **deliberately
  unspecified** — Prometheus + Grafana is what we experiment with because it is
  open source and easy to obtain, but Splunk, Datadog, or Elastic are equally
  valid targets.
- The **built-in web UI is architecturally limited**: it only ever shows a single
  deployment. Cross-deployment analysis is the point, and that requires the data
  upstream.
- We intend to support **disabling the agent web UI entirely**
  (`web_ui_enabled=false`). When that happens the host holds no queryable copy,
  so upstream becomes the *only* place these questions can be answered.
- **SBOM transport over OTEL is planned**, which increases volume substantially.

### Queries that must remain answerable upstream

These are the acceptance criteria for any change to what we export. Aggregation
that breaks them is not acceptable as a default.

1. **Which deployments are affected by CVE-X?** — the cross-deployment question;
   the reason data goes upstream at all.
2. **Which CVEs are present in container/node Y?** — impossible from upstream
   data alone if we only ship aggregates, and impossible locally if the agent UI
   is off.

---

## Measured baseline (2026-08-19, `/metrics` scrape)

| Deployment | Payload | Series | Notes |
|---|---|---|---|
| kubeadm | **383 MB** | 666,445 | 6 nodes, 26 images |
| k3s | 132 MB | 244,510 | |
| microk8s | 107 MB | 189,958 | |
| chainguard | 313 KB | 943 | minimal OS → few findings |

Series by family on kubeadm:

| Family | Series | Share |
|---|---|---|
| `bjorn2scan_node_vulnerability` + `_risk` | 630,760 | **94.6%** |
| `bjorn2scan_image_vulnerability` + `_risk` | 34,742 | 5.2% |
| everything else (db histograms, scan status, deployment) | ~950 | 0.2% |

**99.8% of all series are per-vulnerability-instance.** Each carries 16–22 string
attributes. K8s deployments push every 5 minutes; agents every 15.

Chainguard is the control that isolates the cause: identical code and storage
engine, 943 series, because it has ~12 node findings instead of ~45,000. The
volume tracks finding count, not deployment size or code path.

### Label bloat

Node findings carry 16 attributes; image findings ~22, including six pre-joined
composites:

```
deployment_uuid_host_name, deployment_uuid_namespace,
deployment_uuid_namespace_image, deployment_uuid_namespace_image_digest,
deployment_uuid_namespace_pod, deployment_uuid_namespace_pod_container
```

`deployment_uuid` therefore appears in **seven** attributes on every image
datapoint, alongside repeated full image digests, namespaces, and pod names.

**Corrected 2026-08-19 — the composites are *not* the main payload driver.**
Measured bytes per series on kubeadm:

| Family | Series | Avg bytes | Family total | Composites? |
|---|---|---|---|---|
| `node_vulnerability` (×2 with `_risk`) | 315,380 | 528 | ~318 MB (**83%**) | **no** |
| `image_vulnerability` (×2 with `_risk`) | 17,371 | 1,276 | ~42 MB (11%) | yes |

Composites make image series 2.4× fatter, but node series dominate by count and
carry none. The node-side bloat is instead **per-node invariants repeated on
every finding** — `os_release="Ubuntu 24.04.3 LTS"`, `kernel_version`,
`hostname`, `node`, `architecture`, `deployment_name`, `deployment_uuid` on all
630k datapoints.

**Composite label audit (2026-08-19):**

Classification is by **exact-token** reference and by **kind** of reference.
Both matter, and getting either wrong flips the verdict — see the two
methodology notes below.

| Attribute | Emitted | Functional use | Bytes | Verdict |
|---|---|---|---|---|
| `deployment_uuid_namespace_pod_container` | yes | **9 PromQL + the `joinByField` key** | 4.19 MB | needs `label_join` first |
| `deployment_uuid_namespace_image_digest` | yes | none at all | 5.44 MB | **removable** |
| `deployment_uuid_namespace_image` | yes | cosmetic only | 3.82 MB | **removable** |
| `deployment_uuid_namespace_pod` | yes | cosmetic only | 3.48 MB | **removable** |
| `deployment_uuid_namespace` | yes | cosmetic only | 2.61 MB | **removable** |
| `deployment_uuid_host_name` | yes | cosmetic only | 2.75 MB | **removable** |
| `deployment_uuid_namespace_image_id` | **no** | 2 cosmetic refs | — | **dead dashboard reference** (rename drift) |

**Only ONE composite is functional.** All six are emitted by two label builders
(`buildContainerBaseLabels`, `buildContainerVulnerabilityLabels`), so they appear
on `image_scanned`, `image_vulnerability`, `image_vulnerability_risk`, and
`image_vulnerability_exploited` — never on node metrics. All references live in
the **container dashboard only**; the node dashboard has none. There are no
Prometheus alert or recording rules in the repo.

*Methodology note 1 — match exact tokens, not substrings.* An earlier revision
claimed `deployment_uuid_namespace` and `..._pod` each had 9 PromQL uses. They
have none: both are **prefixes** of `..._pod_container`, so one set of 9
expressions was counted three times. Use a token-boundary regex
(`(?<![A-Za-z0-9_])name(?![A-Za-z0-9_])`), not `in`/`grep`.

*Methodology note 2 — classify by kind of reference.* An even earlier revision
counted raw string hits and marked `_image` and `_host_name` as load-bearing.
References inside a panel's `organize` transformation (`excludeByName` /
`indexByName` / `renameByName`) only hide, order, or rename table columns and are
harmless when the field never arrives — so they do **not** make an attribute
required. Only `expr` (PromQL) and `joinByField.byField` references are
functional.

The one functional composite exists as a **synthetic join key for Grafana's
`joinByField` transformation**, which can only join on a single field — it is not
query denormalization.

### Measured cost (kubeadm, one scrape of 365.4 MB)

| Group | Bytes | Share |
|---|---|---|
| the 5 removable with **no dashboard query changes** | **18.10 MB** | **4.95%** |
| `deployment_uuid_namespace_pod_container` (needs `label_join` first) | 4.19 MB | 1.15% |
| **all 6 composites** | **22.28 MB** | **6.10%** |

Note that removing an attribute changes a series' fingerprint, so affected
series get new identities once. Existing queries keep working (PromQL matches
only the labels it names), but expect a one-time discontinuity in the TSDB.

### `vulnerability_id` — intentional, do not remove

`vulnerability_id` is `fmt.Sprintf("%s.%d", deploymentUUID, v.VulnID)` where
`VulnID` is the `INTEGER PRIMARY KEY AUTOINCREMENT` row id. Rescans
`DELETE`+`INSERT` rather than upsert (`sbom_parser.go:397`, `nodes.go:166/864`),
and `AUTOINCREMENT` never reuses ids, so the value changes on **every rescan**
(~daily). Measured on MicroK8s node findings: distinct `vulnerability_id` values
grow 91,882 (30m) → 160,246 (24h) → 277,886 (3d), while distinct
`(cve, package, version)` stays flat at ~46,000 — roughly 62k dead series
accumulating per day on a 2-node cluster. It costs **41.2 MB (11.3%)** per
scrape and is referenced by zero dashboard panels.

**It is nevertheless deliberate and stays (decision 2026-08-19).** Its purpose is
to correlate a specific finding *at a specific point in time* across the three
metric families emitted from the same row (`_vulnerability`, `_risk`,
`_exploited`); the per-rescan change is what pins it to a scan generation. Do not
propose deleting it as dead weight.

If a *stable* per-finding identity is ever wanted alongside it, the right
construction is a content hash of
`(deployment_uuid, artifact_digest, cve, package_name, package_version)` —
deterministic across rescans and rebuilds. Option D (content addressing) would
produce exactly that key as a by-product.

### Node data is duplicated but *not* guaranteed homogeneous

kubeadm's 6 nodes collapse to 2 distinct package sets; k3s's 2 nodes are
identical:

```
kubeadm-controlplane  pkgs=6662 vulns=45280     k3s-controlplane  6375 / 59586
kubeadm-worker-1      pkgs=6672 vulns=59848     k3s-worker-1      6375 / 59586
kubeadm-worker-2      pkgs=6662 vulns=45280
kubeadm-worker-3      pkgs=6662 vulns=45280
kubeadm-worker-4      pkgs=6672 vulns=59846
kubeadm-worker-5      pkgs=6672 vulns=59846
```

**Homogeneity must not be assumed.** Kubernetes permits host filesystem access,
so any node can drift at any time. See "content addressing" below for why this
is an argument *for* the design rather than against it.

---

## What is already optimized (do not redo)

Read-path work is largely done, which is why the database engine is **not** the
bottleneck:

- `DB.nodeVulnRows` / `DB.containerVulnRows` cache the full result sets in
  memory, invalidated by `notifyWrite()` with a 30-minute TTL safety net
  (`scanner-core/database/db.go`). Per-cycle DB reads are ~0.
- `StalenessStore` is diff-based: active metrics that stay active cost zero DB
  I/O per cycle (`scanner-core/metrics/tracker.go`).
- SBOM and vulnerability JSON are already stored as gzip-compressed blobs.
- Metric emission streams through a 64 KB buffer rather than materializing.

---

## Diagnosis

The problem is **not** the volume of information, the storage engine, or the
fidelity. It is that **record/state data is being carried in the metrics
signal**.

`scanner-core/metrics/otel_direct.go` uses only
`go.opentelemetry.io/proto/otlp/collector/metrics/v1`. Every finding is a
**gauge whose value is always 1**, with the real content in string attributes.
That forces three costs unrelated to how much data we send:

1. **Mandatory retransmission.** Gauges must reappear every cycle to remain
   "current" under TSDB staleness semantics. Immutable data is therefore
   retransmitted **288×/day** at a 5-minute interval. The observation that "the
   data almost never changes" is exactly the saving the metrics model cannot
   exploit.
2. **Cardinality indexing** in the backend — the classic TSDB failure mode, and
   the cause of the `/metrics` scrape timeouts that failed health checks.
3. **No home for a document.** An SBOM cannot be expressed as a gauge at all,
   so the planned SBOM transport has nowhere to go in the current model.

**Prometheus cannot ingest logs — but that is a Prometheus limitation, not an
OTEL one.** The risk to the hypothesis is concluding "OTEL is too expensive for
vulnerability data" when the finding is really "a metrics-only backend is the
wrong sink for finding-level detail."

---

## Options

### Status as of 2026-08-19

| Option | State |
|---|---|
| A1 — OTLP wire compression (gzip) | **DONE** (`cac37db`) — configurable, on by default; 50–66× measured |
| A2 — stop duplicating invariant attributes | **BLOCKED** by the `/metrics` consistency constraint below |
| A3/A4 — dead composite + dead dashboard ref | **DONE** — folded into the full composite removal |
| A″ — drop all six composite attributes | **DONE** (`8900d2d`, `0b4154a`) — 22.28 MB / 6.1% |
| — per-node invariants off vuln metrics | **DONE** (`f12dfcd`) — 46.32 MB / 12.7%, plus ~35 MB less cache memory |
| A′ — one Resource per scanned entity | **REJECTED** — see below |
| B — right OTEL signal per data shape | open (the hypothesis work) |
| C — match cadence to change rate | **open — largest remaining win, and constraint-compatible** |
| D — content-address scan results | open |
| E — hot/cold tier split | open (unlocked by B) |
| F — storage engine change | deferred by decision |

Cumulative shipped reduction before compression: ~68 MB off a 383 MB payload,
then gzip on the remainder. All of it lands on the next release.

### A. Free wins — no fidelity loss, no breaking change

1. **Enable OTLP wire compression.** There is none today: the HTTP sender sets
   only `Content-Type: application/x-protobuf` (no `Content-Encoding: gzip`) and
   the gRPC client configures no compressor (`otel_direct.go`). The payload is
   pathologically compressible given the repetition described above. Expect a
   large multiple for a config change. **Do this regardless of any other
   decision.**
2. **Stop duplicating invariant attributes — BLOCKED, not free after all.**
   `deployment.name` and `deployment.uuid` are on the OTLP Resource *and*
   repeated on all 666k datapoints as `deployment_name`/`deployment_uuid`
   (48.73 MB / 13.3%). Dropping the datapoint copies looks like pure waste
   elimination, but it is the same mistake as A′: `/metrics` has no Resource to
   fall back on, so the two paths would report different label sets. Blocked by
   the consistency constraint below. Listed here as a trap, not a task.
3. **Delete `deployment_uuid_namespace_image_digest`** — emitted on every image
   datapoint, used by nothing (see the audit above). Non-breaking.
4. **Fix the dead `deployment_uuid_namespace_image_id` dashboard reference** —
   referenced by the committed dashboards but never emitted by the code; drift
   from an old rename.

### A′. One OTLP Resource per scanned entity — REJECTED (2026-08-19)

*This option was investigated, measured, and rejected. It is kept here with the
reasoning so it does not get re-proposed on the strength of its headline number.*

The idea: OTLP permits multiple `ResourceMetrics` per request, and Resource
attributes are transmitted once per block rather than once per datapoint. Today
there is a **single Resource for the whole scan-server**, so each of ~630k node
datapoints repeats the subject's identity. Emitting one Resource per scanned node
would hoist those attributes into ~6 Resource blocks.

Measured prize on kubeadm (live, one scrape of 365.4 MB):

| Scope | Attributes | Bytes | Share |
|---|---|---|---|
| Deployment-scoped | `deployment_uuid` (33.09 MB) + `deployment_name` (15.64 MB) | **48.73 MB** | 13.3% |
| Node-scoped | `node` (14.78) + `hostname` (17.19) + `os_release` (19.25) | **51.22 MB** | 14.0% |
| **total** | | **99.96 MB** | **27.4%** |

**Why it was rejected — three reasons, in order of decisiveness:**

1. **It is backend-specific by construction.** The point of Resource attributes
   is that the *receiver* decides how to surface them. Verified empirically
   against Prometheus 3.12.0: a probe with `node`/`hostname`/`os_release` on the
   Resource produced a series carrying only
   `{job, instance, severity, vulnerability}` — the resource attributes were
   dropped from the series and synthesized into a separate `target_info` series
   instead. A Collector→Elastic pipeline flattens them onto documents; Splunk
   differs again. So this does not yield one portable query model, it yields
   per-backend semantics. Prometheus 3.x can opt in via
   `promote_resource_attributes`, but requiring receiver-side config in every
   consumer contradicts the deliberately-unspecified destination.
2. **`/metrics` cannot express it.** Prometheus text exposition has no Resource
   concept — every label must appear on every series. Per-entity Resources would
   make the OTLP push and the `/metrics` scrape describe the same data with
   *different* label sets. See the consistency constraint below.
3. **One deployment has many nodes, so the useful half is the blocked half.**
   The deployment-scoped attributes are genuinely redundant today (the Resource
   already carries `deployment.uuid`/`deployment.name`; the datapoints repeat
   them as `deployment_uuid`/`deployment_name`) — but they cannot be dropped
   from datapoints without breaking `/metrics` consistency. The node-scoped
   attributes are exactly the ones a single per-deployment Resource cannot
   carry, so hoisting them requires multi-Resource emission and deepens the
   divergence.

---

## Design constraint: the OTLP push and `/metrics` must agree

**Any change to the exported shape must produce the same logical data on both the
OTLP push path and the `/metrics` scrape path.** They are two encodings of one
model, not two independent products; a consumer must not need different queries
depending on which path the data arrived by.

This rules out anything that relies on a transport-specific container the other
path cannot represent — per-entity Resources being the concrete example above.
It does *not* constrain changes to **what** is generated or **how often** it is
sent, which is why cadence (option C) and content addressing (option D) remain
viable while resource-hoisting does not.

A corollary: prefer reductions that are visible identically in both encodings —
dropping a redundant attribute, deriving a value at query time, sending less
often — over anything that moves information between structural layers.

### A″. Drop the remaining composite attributes (breaking)

The three functional composites (`deployment_uuid_namespace`, `..._pod`,
`..._pod_container`) are Grafana `joinByField` keys. Replace with PromQL
`label_join(...)` at query time — same capability, zero wire cost, but a

### A″. Drop the remaining composite attributes (breaking)

The three functional composites (`deployment_uuid_namespace`, `..._pod`,
`..._pod_container`) are Grafana `joinByField` keys. Replace with PromQL
`label_join(...)` at query time — same capability, zero wire cost, but a
multi-panel dashboard edit. See Migration below. The other two
(`..._namespace_image`, `deployment_uuid_host_name`) need no dashboard work at
all — see the audit above.

### B. Use the right OTEL signal per data shape

| Signal | Carries | Cost profile |
|---|---|---|
| **Metrics** | posture aggregates (counts by severity / fix status / exploitable) | hundreds of series; drives dashboards + alerting |
| **Logs / Events** | individual findings, full fidelity | append-only; emit on change; no cardinality penalty |
| **Logs (structured body) or reference** | SBOM documents | large; content-addressed |

OTLP logs carry arbitrary structured attributes with no cardinality penalty and
no retransmission requirement — which is how SIEM agents have always shipped
findings. This **preserves both acceptance-criteria queries**; in a log/event
store "which deployments have CVE-X" is an indexed term query, typically
*cheaper* than a high-cardinality label lookup in a TSDB.

### C. Match cadence to change rate

Emit a finding event when it appears / changes / clears, plus a periodic full
resync (daily, aligned with the 24h rescan). Roughly a **288× reduction in
transmitted volume with zero loss of detail**. Only possible once findings are
events rather than gauges.

Open design point: the resync/delta protocol. A log-structured stream plus
periodic full snapshot is the standard SIEM pattern, but the exact contract
(how a backend distinguishes "current" from "historical") needs specifying.

### D. Content-address scan results

Key findings by `(artifact_digest, grype_db_version)` — an immutable, pure
function. Instances (containers, nodes) reference a result rather than own a
copy.

This **measures** homogeneity instead of assuming it: identical nodes collapse
automatically, genuinely different ones do not. If a host filesystem is
modified, the content hash changes and a new result appears on its own — so it
doubles as a **drift detector**, which is the correct behavior for the
heterogeneity risk noted above. A 100-node cluster with two real variants ships
two result bodies plus 100 small references; if one node drifts, a third body
appears without special handling.

Also makes the 24h rescan a genuine no-op when `(digest, db_version)` is
unchanged, and makes DB-update rescans scale with distinct content rather than
instance count.

**Caveat:** per-instance *observation* timestamps must stay separate from
per-content *scan* timestamps. These are conflated today.

### E. Split hot aggregate tier from cold detail tier

- **Hot:** per-`(scan_result, severity)` rollups + instance→result mapping.
  Drives list pages, summaries, and the metrics signal. Memory-resident.
- **Cold:** full finding list + SBOM — already compressed blobs, read only for
  the handful of detail pages.

Per-finding rows currently exist in *both* relational tables and blobs. The
relational copy largely exists to feed the metrics fan-out and list filtering.
Once B lands, the per-finding relational table becomes mostly optional — keep
rollups plus a narrow index for filterable dimensions. **B unlocks E**, which is
where the large storage reduction is.

### F. Storage engine change — explicitly deferred

Not recommended yet. Reads are already cached and staleness is already
diff-based, so the engine is not the measured bottleneck, and a swap would not
reduce the 383 MB export. Postgres buys write concurrency we do not need (we are
a deliberate singleton writer) at significant operational cost. Re-measure after
A–E; D and E likely extend SQLite's runway substantially, which also defers the
known singleton/no-HA constraint.

---

## Export tiering (instead of a binary switch)

A single detail-vs-aggregate switch removes capability from users. Prefer
independently toggleable layers:

| Tier | Content | Default |
|---|---|---|
| 0 | posture aggregates | always on |
| 1 | findings as events | on |
| 2 | SBOM documents | opt-in |

Aggregates are derivable from Tier 1 at the backend, so no one is cut off by
default, and the switch becomes edge cost-control rather than capability loss.
Given the intent to disable agent UIs, **Tier 1 must default on**.

---

## Backend landscape

Ingest support is near-universal; the **indexing model** is the discriminator,
because it decides whether acceptance query #1 works.

| Tool | OTLP logs | "Who has CVE-X" | Notes |
|---|---|---|---|
| **Loki** | native (3.x) | ⚠️ brute-force scan | Zero friction beside Grafana; cheapest retention |
| **OpenSearch / Elasticsearch** | via Collector exporter | ✅ inverted index | Best ad-hoc field search; heavier ops |
| **ClickHouse** | via Collector exporter | ✅ columnar + skip/bloom indexes | Best compression for repetitive data; findings-as-wide-table |
| **Splunk / Datadog / Elastic Cloud** | native or via Collector | ✅ | These *are* the hypothesis's "someone else's SIEM" |

### Loki caveats (verified 2026-08-19)

Loki is the obvious first stop but its model works against query #1:

- OTLP attributes land as **structured metadata, which is explicitly not
  indexed** — queryable only after a label selector narrows the stream, so
  "find CVE-X everywhere" degrades to a scan.
- Promoting CVE to an index label is not a fix: Loki defaults to a **15
  index-label cap**, and a CVE-ID label recreates the cardinality explosion.
- **Resource attributes not promoted to labels are replicated per log entry** —
  the same duplication problem we are trying to remove.
- The **log body is string-only**; nested documents get stringified, so an SBOM
  body survives but is not queryable as structure.
- Structured metadata must be enabled (`allow_structured_metadata: true`) or
  Loki rejects OTLP with HTTP 400.

Conclusion: fine for proving the pipeline, poor for proving analytical value.

References:
- <https://grafana.com/docs/loki/latest/get-started/labels/structured-metadata/>
- <https://grafana.com/docs/loki/latest/send-data/otel/>
- <https://grafana.com/docs/grafana-cloud/send-data/logs/collect-logs-with-otel/>

### Recommended posture

**Target the OpenTelemetry Collector, not a backend.** The agent speaks OTLP;
the Collector's exporter ecosystem becomes the integration surface. This is what
keeps the destination genuinely vendor-neutral, and "works with the SIEM you
already run" becomes a demonstrable property rather than a claim.

For experimentation, run two exporters from one Collector: **Loki** (keeps
Grafana as a single UI beside existing Prometheus dashboards, proves end-to-end
flow) and **ClickHouse** (the bet for the real fidelity story — strong
compression, fast aggregation, and `ReplacingMergeTree` gives current-state
semantics per finding rather than an ever-growing log). Grafana has a ClickHouse
datasource, so one UI covers both.

---

## SBOM transport

A measured node SBOM is **15.6 MB** (2,434 artifacts, EKS Chainguard node).
Naively pushed per node per cycle, a 100-node cluster is ~1.5 GB *per cycle*.

Recommended shape: **event carries a reference, object storage carries the
bytes** — emit an event with the content digest plus a URI, store the document
content-addressed (S3/MinIO). Combined with D (content addressing) and
compression, a 100-node cluster with two variants stores and ships two bodies
instead of a hundred.

Practical constraint: **gRPC's default max message size is 4 MB**, so a 15 MB
document needs chunking, HTTP with raised limits, or reference-plus-fetch.

Settle the encoding question *before* building SBOM export — this is the case
where the architecture decision is existential rather than an optimization.

---

## Schema alignment opportunity

Shape finding events to **OCSF's Vulnerability Finding class** (Open
Cybersecurity Schema Framework). Splunk, Elastic, Snowflake, and AWS Security
Lake all consume OCSF, so "OTLP logs carrying OCSF-shaped vulnerability
findings" would be ingestible by real security tooling with no custom mapping —
a far stronger demonstration than a bespoke schema. Also check the current state
of OTel's own security/vulnerability semantic conventions; aligning early is
much cheaper than renaming attributes later.

---

## Migration / compatibility

Any change to exported attributes or families is **breaking for existing Grafana
dashboards and alerts**, including the two committed dashboards in
`docs/grafana-*-dashboard.json` and everything described in
`docs/PROMETHEUS_METRICS.md`. Both must be updated in lockstep.

Suggested path: emit old and new shapes concurrently for one release behind a
flag, then retire the old. Composite-attribute removal (A3) and the metrics
family changes (B) are the breaking pieces; A1 (compression) and A2 (Resource
attributes) are not.

**Composite removal turned out not to need a lockstep migration**, because
`label_join` can be written to the *same* label name — which overwrites with an
identical value while the label is still emitted, verified as a no-op. So the
dashboard change and the code change are fully decoupled: ship either first, in
either order, with no dual-emit period and no cutover window.

### Status: dashboard side done (2026-08-19)

`docs/grafana-container-dashboard.json` — all 9 expressions now derive
`deployment_uuid_namespace_pod_container` via `label_join(...)` (9 insertions,
9 deletions; `joinByField`, `organize`, panels, `schemaVersion`, and `uid`
untouched). Verified three ways, all identical to the pre-change results
(233/155/190/166/153/51/126/190/41 series):

1. direct Prometheus, all 9 expressions;
2. through Grafana's own `/api/ds/query`;
3. re-read from the edited file.

Also **deployed to the live Grafana** at 192.168.2.57 (uid `adtgfct`, now
version 2; v1 remains in Grafana's version history for rollback). All 9 panel
queries return data with no errors.

Two gotchas worth remembering for any future import:

- The committed JSON is Grafana **export format** with `${DS_PROMETHEUS}`
  placeholders, which only resolve through the import wizard. A raw
  `POST /api/dashboards/db` of that file leaves every panel pointing at a
  nonexistent datasource. The deploy was done by applying the rewrite to the
  **live** dashboard object instead, preserving datasource bindings and version
  lineage.
- Grafana here has **no PVC and no external database** (`/var/lib/grafana` is an
  emptyDir), so the live dashboard is lost whenever that pod is *recreated*. It
  has survived so far only because the pod has not been replaced since
  2026-06-22. Provisioning the dashboards as `grafana_dashboard=1` ConfigMaps
  would fix this; deferred by decision while the dashboard is still changing.

**Phase 2 (removing the six composites from the Go code) is unblocked** — no
dashboard depends on the emitted labels any more.

---

## The experiment worth running

The hypothesis is about OTEL as a vulnerability transport, so measure that
directly rather than tuning Prometheus. Ship the *same* finding set as
(a) metrics and (b) OTLP logs, and compare:

- bytes on the wire (with and without gzip)
- backend ingest cost and storage footprint
- query latency for "who has CVE-X" and "what's in container Y"
- full-resync-every-cycle vs. delta + daily resync

That produces a defensible answer about OTEL for security data, which is a more
interesting result than a well-tuned TSDB.

## Prerequisite measurements (currently missing)

1. **DB + WAL size** is not exported today (open TODO item), so all storage
   scaling claims — including those above — are estimates.
2. **Distinct `(digest, grype_db)` pairs vs. total instance rows** → the exact
   dedup ratio, which sizes option D.
3. **pprof of one push cycle** (time + allocations) → confirms the export-vs-DB
   split inferred from cache behavior. Note ~666k `map[string]string`
   allocations per cycle in the label builders.

## Schema state — investigated 2026-08-19, no cleanup needed

An earlier draft of this document claimed the schema contained leftover
migration tables. **That was wrong.** Every `*_new` table is created and
`ALTER TABLE ... RENAME TO`'d away within the same migration — the standard
SQLite table-rewrite idiom, since SQLite has no `ALTER COLUMN`.
(`metric_staleness_v` was an artifact of a grep pattern that truncated
`metric_staleness_v37`.)

Actual state: **50 migrations, ~14 coherent tables**, documented in
`docs/SCANNER-CORE-DESIGN.md` including the rename history
(`container_images → images`, `container_instances → containers`,
`packages → image_packages`, `vulnerabilities → image_vulnerabilities`). There
is no junk to clean up.

### On squashing the migration chain

Tempting given the DB is fully reconstructible (see
[[scanner-db-reconstructible]] reasoning: derived data, no backups), and the
wipe-on-mismatch machinery is **already the agreed plan** for the auto-update
rollback item ("if the DB's schema version exceeds the code's max known
migration, wipe and recreate", gated by `db_reset_on_downgrade`).

**But a schema reset is a one-time budget — spend it on the data-model redesign,
not on cosmetic cleanup.** Squashing now and then implementing content
addressing + the hot/cold split later pays the cost twice. Do it *as the last
step of* that redesign, when the schema is being rewritten anyway and the reset
is effectively free.

Real costs to weigh, since "the data is recreatable" is not the same as "free":
- A wipe means a full rescan. Node scans take 30–100s each and peak at
  1.5–2 GB (there is OOM history), so a fleet-wide simultaneous
  wipe-and-rebuild is an operational event.
- Rollback across the reset boundary becomes impossible — old code cannot read
  the new baseline. This interacts directly with auto-update rollback.
- 50 migrations is a number, not a pain. What actually hurts is table-rewrite
  migrations on large tables (slow, WAL-heavy) and upgrade-time risk — the v25
  bug caused 30k+ pod restarts. Fewer migrations reduce that risk, which is the
  strongest argument *for* eventually squashing.
