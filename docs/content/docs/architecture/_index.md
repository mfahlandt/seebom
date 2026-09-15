---
title: "Architecture"
linkTitle: "Architecture"
type: docs
weight: 2
description: >
  System architecture, data flow, ClickHouse schema, and component overview.
---

{{% pageinfo %}}
This page contains the full architecture blueprint for BOMHort.
{{% /pageinfo %}}

## TL;DR

Kubernetes-native SBOM platform as a monorepo. Go backend with four binaries (CronJob Ingestion-Watcher, scalable Parsing-Workers, stateless API-Gateway, background CVE-Refresher). ClickHouse as the analytical database with MergeTree tables and array-based dependency storage. Angular frontend with virtual scrolling, OnPush change detection, full-text search, dark-mode toggle, and custom CSS theming.

## Components

| Binary | Type | Purpose |
|--------|------|---------|
| `ingestion-watcher` | K8s CronJob | Scans SBOM/VEX directory, hash-dedup, enqueues jobs |
| `parsing-worker` | Deployment (N replicas) | Processes SBOMs (SPDX→ClickHouse), VEX files, OSV lookups, license resolution, compliance checks |
| `api-gateway` | Deployment | Stateless REST API (25 endpoints) |
| `cve-refresher` | K8s CronJob (daily) | Checks all known PURLs for newly disclosed CVEs |

## Data Flow

```
┌─────────────────────────────────────────────────────────┐
│                    SBOM Sources                          │
│  S3 (default):                                           │
│    s3://cncf-subproject-sboms/k3s-io/...spdx.json       │
│  Local (alternative):                                    │
│    sboms/*.spdx.json + *.openvex.json                   │
└──────────────────────┬──────────────────────────────────┘
       │ S3 ListObjects (streamed) + filepath.Walk (local)
       │ SHA256 hashing + file-type detection (sbom|vex)
       ▼
Ingestion Watcher (CronJob)
       │ Hash dedup → batch INSERT INTO ingestion_queue (500/batch)
       ▼
ClickHouse: ingestion_queue (status='pending')
       │ SELECT + Claim (status='processing')
       ▼
Parsing Workers (N replicas)
       ├── Local files: os.Open(filepath.Join(sbomDir, sourceFile))
       ├── S3 files:    s3.GetObject(bucket, key) → io.ReadCloser
       ├── job_type=sbom:
       │     1. Auto-detect format (SPDX / CycloneDX / in-toto envelope)
       │     2. Parse via appropriate backend (built-in or protobom)
       │     2a. Store original bytes → blob store, INSERT document_store
       │         (before any other row, so a blob-store outage retries cleanly)
       │     2b. Resolve unknown licenses via GitHub API
       │        (well-known Go module mappings + API fallback + static overrides)
       │        then via package registries (npm, NuGet) for what is still unknown
       │     3. Batch INSERT sboms + sbom_packages (with resolved licenses)
       │     4. OSV Batch Query → INSERT vulnerabilities
       │     5. License Compliance Check → INSERT license_compliance
       └── job_type=vex:  OpenVEX Parse → INSERT vex_statements
       ▼
ClickHouse: sboms, sbom_packages, vulnerabilities, license_compliance, vex_statements
       │
       │         ┌──────────────────────────────────┐
       │         │ CVE Refresher (CronJob, daily)   │
       │         │  OSV BatchQuery (1000/chunk)      │
       │         │  Dedup + reverse-lookup + INSERT  │
       │         └──────────────────────────────────┘
       ▼
API Gateway (REST) → 24 Endpoints → Angular UI
```

## ClickHouse Schema

| Table | Engine | Purpose |
|-------|--------|---------|
| `sboms` | ReplacingMergeTree | SBOM metadata |
| `sbom_packages` | MergeTree | Parallel arrays (names, PURLs, licenses, relationships) |
| `vulnerabilities` | MergeTree | OSV results |
| `license_compliance` | SummingMergeTree | License compliance per SBOM |
| `ingestion_queue` | ReplacingMergeTree | Job queue (job_type: sbom/vex) |
| `dashboard_stats_mv` | SummingMergeTree (MV) | Pre-aggregated daily stats |
| `vex_statements` | ReplacingMergeTree | OpenVEX statements |
| `cve_refresh_log` | MergeTree | CVE refresh run history |
| `github_license_cache` | ReplacingMergeTree | Resolved GitHub licenses cache |
| `github_repo_metadata` | ReplacingMergeTree | GitHub repo metadata (archived, fork, stars) |
| `registry_license_cache` | ReplacingMergeTree | Resolved package-registry licenses cache (npm, NuGet), keyed by `(registry, package@version)` |
| `document_store` | ReplacingMergeTree | Reference + `sha256` of the **original SBOM bytes** captured at ingest (#256). The bytes live in a blob store (S3 prefix or PVC), not in ClickHouse. |

All core tables (`sboms`, `sbom_packages`, `vulnerabilities`, `license_compliance`, `ingestion_queue`, `vex_statements`) include a `cluster LowCardinality(String) DEFAULT ''` column for multi-cluster support.

## Multi-Cluster Data Model

BOMHort supports tagging all ingested data with a **cluster identifier** for multi-cluster deployments. This is fully optional — single-instance deployments work without any configuration.

### How it works

```
┌────────────────────────────────────┐
│  S3 Buckets with per-bucket cluster │
│                                      │
│  bucket: prod-eu-sboms               │
│  cluster: "prod-eu"                  │
│                                      │
│  bucket: staging-sboms               │
│  cluster: "staging"                  │
│                                      │
│  bucket: other-sboms                 │
│  cluster: "" (inherits CLUSTER_NAME) │
└────────────────┬─────────────────────┘
                 │
                 ▼
    Ingestion Watcher
    (resolves cluster per object)
                 │
                 ▼
    ingestion_queue.cluster = "prod-eu" | "staging" | ""
                 │
                 ▼
    Parsing Worker
    (propagates job.Cluster → all inserts)
                 │
                 ▼
    sboms.cluster / vulnerabilities.cluster / etc.
```

### Configuration

| Method | Use case |
|--------|----------|
| No config (default) | Single instance, no cluster differentiation |
| `CLUSTER_NAME=prod-eu` | All data from this instance tagged as `prod-eu` |
| Per-bucket `"cluster"` in `S3_BUCKETS` JSON | One watcher instance ingests from multiple clusters |
| Mix: per-bucket + `CLUSTER_NAME` fallback | Buckets without explicit cluster inherit the global value |

### Priority

1. Per-bucket `cluster` field in S3 config (highest)
2. Global `CLUSTER_NAME` environment variable (fallback)
3. Empty string `""` (no cluster, single-instance mode)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/healthz` | Health check |
| GET | `/livez` | Liveness probe |
| GET | `/readyz` | Readiness probe (checks ClickHouse) |
| GET | `/api/v1/stats/dashboard` | Dashboard statistics |
| GET | `/api/v1/stats/dependencies?limit=N` | Top-N dependencies cross-project |
| GET | `/api/v1/stats/version-skew?page=&page_size=&search=` | Version skew detection |
| GET | `/api/v1/sboms?page=&page_size=` | Paginated SBOM list |
| GET | `/api/v1/sboms/{id}/detail` | SBOM detail with severity breakdown |
| GET | `/api/v1/sboms/{id}/vulnerabilities` | Vulnerabilities for an SBOM |
| GET | `/api/v1/sboms/{id}/licenses` | License breakdown for an SBOM |
| GET | `/api/v1/sboms/{id}/dependencies` | Dependency tree |
| GET | `/api/v1/vulnerabilities?page=&vex_filter=` | Paginated vulnerabilities |
| GET | `/api/v1/vulnerabilities/{id}/affected-projects` | CVE impact across projects |
| GET | `/api/v1/licenses/compliance` | Global license compliance |
| GET | `/api/v1/projects?page=&page_size=&search=` | Grouped project listing |
| GET | `/api/v1/projects/license-compliance` | Projects with license violations |
| GET | `/api/v1/license-exceptions` | Active license exceptions |
| GET | `/api/v1/license-policy` | Active license policy |
| GET | `/api/v1/vex/statements?page=&page_size=` | Paginated VEX statements |
| GET | `/api/v1/packages/archived` | Archived GitHub repo packages |
| GET | `/api/v1/packages/search?q=&page=&page_size=` | Fuzzy package name search |
| GET | `/api/v1/packages/detail?name=&page=&page_size=` | All projects using a specific package |
| GET | `/api/v1/clusters` | List all clusters with summary stats |
| GET | `/api/v1/clusters/{name}/stats` | Per-cluster dashboard statistics |
| GET | `/api/v1/clusters/{name}/sboms?page=&page_size=` | SBOMs for a specific cluster |

## VEX Architecture

- **Format:** OpenVEX (JSON, Spec v0.2.0)
- **File Detection:** `*.openvex.json` or `*.vex.json`
- **Statuses:** `not_affected`, `affected`, `fixed`, `under_investigation`
- **URL Normalization:** VEX vulnerability `@id` URLs are reduced to plain IDs
- **Dashboard:** `effective_vulnerabilities = total - suppressed_by_vex`

## CVE Refresher

Lightweight daily CronJob that queries all unique PURLs (~20k) against the OSV API in 1000-PURL batch chunks, deduplicates against existing vulnerabilities, and inserts new findings — without re-scanning all SBOMs.

## OSV Integration

- **Endpoint:** `POST https://api.osv.dev/v1/querybatch`
- **Batch Limit:** 1000 PURLs per request
- **Rate Limiting:** Token bucket (10 req/s, burst 5)
- **Retry:** Exponential backoff on HTTP 429/503

## License Governance

- **License Policy** (`license-policy.json`): Defines permissive vs. copyleft classifications
- **License Exceptions** (`license-exceptions.json`): Empty by default; explicit organization-managed blanket or package/license/project rules. No CNCF download or implicit global approval. Configure through `licenseExceptions.custom`; Helm rolls out API and workers on changes. Existing SBOMs must be re-processed to update stored compliance results.
- **Argo CD / GitOps:** Git-backed Helm values update the exception ConfigMap and deterministic checksums on both Deployment pod templates. Argo sync triggers Kubernetes rollouts without Helm upgrade hooks; it does not re-process existing SBOMs. Deploy matching chart and API/worker image revisions. See [Argo CD deployment](../deployment/#argo-cd-gitops).
- **Permissive licenses** (MIT, Apache-2.0, BSD) are **never** tracked as non-compliant
- **Visual:** Green = exempted copyleft, Red = violation, Orange = exempted in dependency tree

## SBOM Parsers

BOMHort supports **multiple SBOM formats** through a format-detection dispatch layer (`internal/sbom`):

| Format | Detection | Parser |
|--------|-----------|--------|
| SPDX 2.3 JSON | `spdxVersion` field present | Built-in (`internal/spdx`) |
| In-toto envelope (SPDX) | `predicateType` contains "spdx" | Built-in (`internal/spdx`) |
| SPDX 3.0.1 JSON-LD | `@context` references `spdx.org/rdf/3.x` | protobom (`internal/protobomparser`), always |
| CycloneDX 1.0–1.7 JSON | `bomFormat: "CycloneDX"` | Built-in (`internal/cyclonedx`) |
| All above via protobom | (opt-in) | `internal/protobomparser` |

**File extensions recognized:** `.spdx.json`, `.cdx.json`, `.json` (any JSON file — format auto-detected at parse time)

Files starting with a configurable prefix (`SBOM_IGNORE_PREFIX`, default `_`) are skipped during local filesystem scanning. Config files (`license-policy.json`, `license-exceptions.json`) are always excluded.

Two parser backends are available:

- **Built-in (default)** — Lightweight, high-performance parsers using `goccy/go-json`. Zero additional dependencies. Best for production with known formats.
- **Protobom** — Uses [github.com/protobom/protobom](https://github.com/protobom/protobom) for maximum format coverage. Always used for SPDX 3 (JSON-LD), which the built-in parsers do not understand. Enable for all formats with `USE_PROTOBOM=true`.

Both backends use `internal/sbomname` to replace empty or temporary (`tmp.*`)
document names with an unambiguous described root package and version, or a source
label when no usable root exists. Meaningful names, raw SBOM bytes, source identity,
and package data are preserved. This is applied during ingestion and stored in
`document_name`; existing records need re-processing. Exact project-scoped license
exceptions use the resolved name, while S3 project grouping remains source-based.

See the [Parsers documentation](/docs/development/parsers/) for configuration details,
fallback rules, upgrade implications, and trade-offs.

## License Resolution

For packages with `NOASSERTION`, `NONE` or empty licenses (common in container-image SBOMs generated by Syft), the parsing worker tries to resolve the license before the data is written to ClickHouse. Resolution runs in two passes: first the **GitHub resolver** (source repositories), then the **package-registry resolvers** (npm, NuGet) for whatever is still unknown. Each pass can be disabled independently (`SKIP_GITHUB_RESOLVE`, `SKIP_NPM_RESOLVE`, `SKIP_NUGET_RESOLVE`).

### GitHub (source repositories)

The GitHub resolver maps a PURL to a repository and asks the GitHub API for its license, using multiple strategies:

1. **Direct PURL extraction** — `pkg:golang/github.com/{owner}/{repo}` → `github.com/{owner}/{repo}`
2. **Well-known Go module mappings** (50+ entries) — Maps non-GitHub import paths to their GitHub repos:
   - `golang.org/x/*` → `github.com/golang/*`
   - `gopkg.in/yaml.v3` → `github.com/go-yaml/yaml`
   - `go.uber.org/zap` → `github.com/uber-go/zap`
   - `k8s.io/client-go` → `github.com/kubernetes/client-go`
   - `oras.land/oras-go` → `github.com/oras-project/oras-go`
   - `dario.cat/mergo` → `github.com/darccio/mergo`
   - `pkg:golang/stdlib` (Go standard library, emitted by Syft and others) → `github.com/golang/go`
   - And many more (see `internal/github/purl.go`)
3. **Fallback to `/license` endpoint** — If the repo API returns `NOASSERTION`, the dedicated `/repos/{owner}/{repo}/license` endpoint is tried (it does deeper file analysis)
4. **License-text classification** — If GitHub only labels the file as `Other` (custom preamble, reformatted whitespace, unusual copyright line), the returned license text is classified locally by matching distinctive phrases of common OSS licenses (`internal/licensetext`) and mapped to an SPDX ID
5. **Static overrides** — For repos where even that fails, manually verified overrides are applied (e.g., `opencontainers/go-digest` → Apache-2.0, `shopspring/decimal` → MIT)

Results are cached in-memory per worker and persisted to the `github_license_cache` and `github_repo_metadata` ClickHouse tables for cross-worker reuse.

### Package registries (npm, NuGet)

Packages that are still unknown after the GitHub pass are offered to the registry resolvers. Each resolver only handles PURLs of its own ecosystem, requires no authentication, and is throttled to **5 req/s (burst 10)** per worker.

| Registry | PURL | Strategy |
|---|---|---|
| **npm** | `pkg:npm/{name}@{version}` | `GET registry.npmjs.org/{name}/{version}` → `license` field of the version manifest (string, legacy `{"type": …}` object, or deprecated `licenses` array). Without a version, the `latest` dist-tag is used. |
| **NuGet** | `pkg:nuget/{id}@{version}` | NuGet V3 API: registration leaf → catalog entry → `licenseExpression`. Legacy packages without `licenseExpression` fall back to (a) a well-known OSI `licenseUrl` mapped to an SPDX ID, or (b) a `licenseUrl`/`projectUrl` pointing at a GitHub repo, which is delegated to the GitHub resolver. Packages that only ship a license file inside the `.nupkg` (`aka.ms/deprecateLicenseUrl`) or proprietary EULAs remain unresolved. |

Results (including negative ones) are cached in-memory and persisted to the `registry_license_cache` table, keyed by `(registry, package@version)`, so a package version is looked up at most once across all workers and restarts.

{{% alert title="Important" color="warning" %}}
License resolution runs **before** the ClickHouse insert so that `sbom_packages.package_licenses` contains the resolved values from the start. This ensures the dependency tree API returns correct licenses without requiring a separate join or lookup.
{{% /alert %}}

## Original Document Store (Tier-2 Fidelity)

ClickHouse is tuned as an **analytical** store: `sbom_packages` holds the dependency tree as parallel `Array()` columns, which is ideal for search and aggregation but drops most document-level detail (copyright text, supplier/originator, external references, formatting). To hand back the *exact* document later — download, enriched export, re-signing (#255) — the parsing worker captures the original bytes at ingest (#256).

```
Parsing Worker                                  Blob store              ClickHouse
──────────────                                  ──────────              ──────────
read source ──▶ sha256 ──▶ Put(<sbom_id>/<name>) ──▶ s3://bucket/_bomhort/originals/…
                                                     or  fs://<sbom_id>/<name>
                                     └──▶ INSERT document_store (ref, sha256, size)
                                                    ──▶ then sboms, sbom_packages, …
API Gateway
───────────
GET /sboms/{id}/download ──▶ document_store? ──▶ Get(ref) ──▶ stream original
                                  └── none / unreadable ──▶ fall back to source_file
```

**Design decisions**

- **Bytes never go into ClickHouse.** MB-scale blobs in a MergeTree bloat parts and slow merges. `document_store` holds only `(sbom_id, cluster, source_file, storage_backend, storage_ref, sha256_hash, size_bytes, content_type)` as a `ReplacingMergeTree(stored_at)` keyed by `sbom_id`.
- **Two backends, one interface** (`internal/docstore`): `s3` writes to a configured bucket under a reserved prefix (default `_bomhort/originals/`, skipped by the ingestion watcher so originals are never re-ingested); `fs` writes atomically (temp file + rename) below a directory — a PVC shared by workers and gateway for air-gapped setups. References are opaque (`s3://…`, `fs://…`), so the gateway resolves them without knowing how they were produced.
- **Capture happens before any ClickHouse insert.** If the blob store is unavailable the job fails and is retried; had the SBOM row been written first, the idempotency guard would skip the retry and the original would be lost for good.
- **The worker computes the sha256 itself.** S3-discovered jobs carry the bucket ETag as their dedup hash, which is not a sha256 (and never is for multipart uploads).
- **Download stays backward compatible.** `GET /api/v1/sboms/{id}/download` prefers the stored original (with `ETag`, `X-BOMHort-SHA256`, `X-BOMHort-Original: true`) and falls back to re-reading `source_file` for SBOMs ingested before this feature or with the store disabled.
- **Single capture point covers push uploads too.** `POST /api/v1/sboms/upload` only stages the file and enqueues a job; the worker reads that same file, so pushed and pulled SBOMs are treated identically.

Configuration: `ORIGINAL_STORE_BACKEND=auto|s3|fs|none` (`auto` → `s3` when S3 buckets are configured, else `fs` when `ORIGINAL_STORE_FS_PATH` is set, else `none`), `ORIGINAL_STORE_S3_BUCKET`, `ORIGINAL_STORE_S3_PREFIX`, `ORIGINAL_STORE_FS_PATH`. See the [Deployment Guide](/docs/deployment/#original-document-store) for Helm values.

{{% alert title="Forward-only" color="warning" %}}
Originals can only be captured at ingest. SBOMs ingested before this feature was enabled, or while `ORIGINAL_STORE_BACKEND=none`, are permanently limited to the parsed representation — a full re-ingestion is the only way to back-fill them.
{{% /alert %}}

## Angular UI

13 lazy-loaded routes with virtual scrolling, OnPush change detection, dark mode toggle, and CSS custom properties theming. Includes package search with fuzzy name matching and paginated detail views. External `custom-theme.css` and `ui-config.json` are mountable without rebuild.

