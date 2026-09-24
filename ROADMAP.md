# BOMHort Product Roadmap

> Last updated: 2026-09-24
> Project Board: https://github.com/orgs/seebom-labs/projects/1
> Milestone v1.0.0: https://github.com/seebom-labs/BOMHort/milestone/1

## Executive Summary

BOMHort is transitioning from a single-instance SBOM visualization tool into an **enterprise-grade, multi-cluster Software Supply Chain Security platform**. Phase 1 (foundation, auth, multi-cluster model, push ingestion) is complete and shipped in v0.4–v0.6.

The roadmap is now organised around one hard deadline — the **v1.0.0 schema and API freeze** — and what must land before it:

1. **Phase 2 — v1.0 Freeze Preparation (Sep–Nov 2026):** one coordinated migration wave (`014`–`022`, complete) for every forward-only item, the API-contract changes, the **consumer-facing contract** (project-centric read model #398, MCP server #399), the chart/correctness hygiene that `values.yaml` stability demands (#344, #355, #391, #392, #397), plus versioned docs. Anything that can be added later without breaking the contract is *deliberately* pushed past 1.0.
2. **Phase 3 — Automation & Fleet Operations (v1.1.0, Q1 2027):** the [VEXViper](https://github.com/seebom-labs/VEXViper) integration epic (automated VEX generation), namespace/workload views, auditor exports, OSV mirror, attestation verification.
3. **Phase 4 — Analytics & Compliance (v1.2.0, 2027 H1):** CRA readiness scoring, EPSS, Scorecard, Lottery Factor, SBOM diff, enriched SBOM export.

The sequencing is driven by one rule: **if it can't be back-filled, it lands before 1.0; if it's additive, it lands after.**

> **Re-plan 2026-09-24.** Two newly filed issues are pulled into 1.0, and the backlog
> is now fully triaged — **every open issue carries a milestone**.
> **#398 (project-centric view)** changes what a "project" *is* and fixes the double-counted
> `package_count`/`vuln_count` in the already-frozen `ProjectListItem` — a row-semantics
> change of the same class as #335. **#399 (MCP server)** is the first external consumer of
> the REST contract and needs its own `values.yaml` block, which freezes with 1.0.
> Consequences: **#58 (Aggregated SBOM View) moves from Phase 3 to Phase 2** (it is the
> aggregation half of #398); **five previously unsorted issues (#344, #355, #391, #392,
> #397) join Phase 2** because they either touch `values.yaml` or invalidate a box the 1.0
> criteria already tick; **#57 moves to v1.1.0** (its column shipped, only the post-1.0
> policy work remains); and the 1.0 target moves from end-October to **end-November 2026**.
> Milestones `v1.1.0`, `v1.2.0` and `v2.0.0` now exist to hold Phases 3, 4 and the
> breaking-change backlog.

---

## Phase 1: Foundation & Security ✅ (Q1–Q2 2026) — Complete

**Theme:** Make BOMHort deployable in production environments with real security requirements.

| # | Issue | Status |
|---|-------|--------|
| ~~#131~~ | ~~Cluster-aware data model~~ | ✅ `cluster` column via migration `012`. |
| ~~#134~~ | ~~API Authentication (Service Token + API Key)~~ | ✅ `authMiddleware`, constant-time compare. |
| ~~#137~~ | ~~Enhanced health checks (/readyz, /livez)~~ | ✅ `/livez`, `/readyz` (ClickHouse ping → 503). |
| ~~#139~~ | ~~Headless mode (API-only)~~ | ✅ `ui.enabled=false` skips all UI resources. |
| ~~#59~~ | ~~Expose API externally (Ingress)~~ | ✅ Ingress template + TLS docs. |
| ~~#8~~ | ~~Project List View~~ | ✅ `GET /api/v1/projects` + UI. |
| ~~#144~~ | ~~SBOM Download~~ | ✅ `GET /api/v1/sboms/{id}/download`. |
| ~~#55~~ | ~~CycloneDX Support~~ | ✅ `internal/cyclonedx`, multi-format dispatch. |
| ~~#37~~ | ~~Version Skew Detection~~ | ✅ PRs #103, #126. |
| ~~#132~~ / ~~#133~~ | ~~Cluster listing + detail endpoints~~ | ✅ `GET /api/v1/clusters`, `/clusters/{name}/{stats,sboms}`. |
| ~~#135~~ | ~~SBOM Upload (Push Model)~~ | ✅ `POST /api/v1/sboms/upload` (auth-gated, S3 or `pushed/` dir). |
| #136 | Enhanced CORS | 🟡 **Functionally done** — `POST` on the upload route, `X-API-Key`/`X-Service-Token`/`X-Filename` headers, configurable origins. Remaining scope (`CORS_ALLOW_CREDENTIALS`, configurable methods/headers) is additive → **moved to 1.x**, removed from the v1.0 milestone. |

**Delivered beyond the roadmap:** Global Search (`GET /api/v1/search`), Package Search + detail page, in-toto attestation unwrapping, protobom parsing backend, license resolution via GitHub + npm + NuGet registries with license-text classification (`internal/licensetext`), SPDX file-level filtering, dark mode, white-label theming.

---

## Phase 2: v1.0 Freeze Preparation (Sep–Nov 2026)

**Theme:** Land every forward-only data capture, every API-contract change and the first external consumer of that contract in **one coordinated wave**, then freeze.

### 2a. Schema wave `014`–`022` (must land together, before the freeze) ✅

Migration `013` is taken by `013_create_registry_license_cache` (shipped in v0.6.x). The issues below previously claimed `013` — numbering is now fixed as follows. The wave is **complete**; `018`–`022` are listed in the Schema Change Register below.

| Migration | # | Issue | Type | Why pre-1.0 |
|-----------|---|-------|------|-------------|
| `014_create_document_store` | **#256** | Tier-2 fidelity capture — persist original SBOM bytes at ingest | New table (`ReplacingMergeTree`, reference + `sha256` only; bytes in configurable blob store: S3/MinIO prefix **or** PVC) | **The real 1.0 driver.** Forward-only: SBOMs ingested before this exist permanently lose round-trip/export fidelity. Also needs a follow-up hook in the already-merged upload handler (#135). Enables #255, and makes every other column below back-fillable. |
| `015_add_namespace_project_columns` ✅ | **#138** | Namespace filtering | `ADD COLUMN namespace LowCardinality(String) DEFAULT ''` on core tables (same pattern as `cluster`; **no** `ORDER BY` change — not possible on MergeTree without rebuild) | Ingestion path convention (`{bucket}/{cluster}/{namespace}/…`) + upload field. `?namespace=` on list endpoints is an additive query param, but the ingestion contract should be fixed before 1.0. |
| `016_add_source_columns` ✅ | **#332** | `source_repo` / `source_ref` as first-class SBOM attribute | `ADD COLUMN source_repo String, source_ref String` on `sboms` | Cheap `ADD COLUMN`; populated at parse time from SPDX `downloadLocation`/`ExternalRef` and CycloneDX `externalReferences[vcs]`/`pedigree.commits`. Overridable via `X-Source-Repo`/`X-Source-Ref` upload headers and `PATCH /api/v1/sboms/{id}`. Correctness blocker for the VEXViper sidecar (#338). ⚠️ **Column shipped, extraction does not work in practice — see #355 in 2d.** |
| `017_add_vex_provenance` ✅ | **#334** (columns only) | VEX statement provenance | `ADD COLUMN author, role, tooling, status_notes` on `vex_statements` | OpenVEX already carries these; capturing them at ingest is forward-only-ish (VEX docs are small and re-uploadable, but automated producers won't re-send). UI badge + `?vex_source=` filter → Phase 3. |
| *(bundled with 015)* | **#57** (column only) | `project` column | `ADD COLUMN project LowCardinality(String) DEFAULT ''` on core tables | Roadmap already asked to batch this with the `ADD COLUMN` wave. **Only the column** lands now; per-project policies / exception scopes are additive → Phase 3. |

### 2b. API-contract changes (before the freeze, no migration)

| # | Issue | Why pre-1.0 |
|---|-------|-------------|
| **#335** ✅ | One row per `(vuln_id, purl)` in `/sboms/{id}/vulnerabilities` — latest VEX statement wins, expose `vex_timestamp` | **Changes row semantics** of a frozen endpoint. `argMax()`/`LIMIT 1 BY` in the ClickHouse query + DTO fields (`vex_timestamp`, `vex_author`, `vex_tooling`). Small, but must be in the 1.0 contract. |
| **#177** ✅ | `cluster` in `SBOMListItem` DTO + badge | Additive DTO field; trivial. Shipped in v0.7.0 together with `namespace`/`project`, so the list contract is complete. |

### 2c. Consumer-facing contract (new — added 2026-09-24)

Everything so far made BOMHort *capture* the right data. These two make it *answerable* —
and both change or lock down surfaces that 1.0 freezes.

| # | Issue | Type | Why pre-1.0 |
|---|-------|------|-------------|
| **#398** | Project-centric read model: `GET /api/v1/projects/{name}` + `/{name}/{sboms,packages,vulnerabilities}`, de-duplicated across all SBOMs of a project | Query + DTO, **no migration** (columns exist since `015`/`022`) | **Row-semantics change on a frozen endpoint**, same class as #335. `ProjectListItem.package_count` / `vuln_count` today `sum()` per-SBOM counts, so a project with 5 SBOMs of one component reports it 5×. Fixing that after 1.0 silently changes every number an operator has been reporting. The project *identity* rule (explicit `project` column → path derivation → `document_name` fallback, `projectKeyExpr`) also becomes contract — it decides what "OpenTelemetry" means versus `OpenTelemetry/subproject@v1.2.3`. |
| **#399** | BOMHort MCP server — read-only tool surface over the REST API (`cmd/mcp-server`), port of the VEXViper MCP server | New component + **new `values.yaml` block** (`mcp.enabled`, transport, auth) | Helm values freeze with 1.0 (see the milestone criteria below). Shipping the server in 1.1 means either a breaking values reshuffle or living with a badly-guessed schema for a whole major. It is also the **first external consumer of the frozen REST contract** — it surfaces exactly the gaps #398 fixes, so it must be built *before* the freeze, not after. |
| **#58** | Aggregated SBOM View — group N versions of one project into an expandable row | UI + query | **Moved up from Phase 3.** This is the UI half of #398 — same aggregation, same dedup semantics. Splitting them across the freeze would mean designing the de-dup twice. |

**Dependency decision for #399 — approved 2026-09-24.** The official Go SDK
(`github.com/modelcontextprotocol/go-sdk`) is accepted as direct dependency **#6**, raising
the budget from 5 to 6. `AGENTS.md:113` needs updating with the new list.

**Minimum version `v1.4.1` — this is not a style preference.** Everything below it carries
four HIGH advisories, and three of them describe exactly the scenario a BOMHort MCP server
would run in:

| Advisory | What it breaks |
|----------|----------------|
| CVE-2026-27896 | `encoding/json` case-insensitive key matching (`Method` ≡ `method`, plus Unicode `ſ`/`K` folding) — a proxy or policy layer matching exact JSON-RPC field names can be walked straight past. Fixed in `v1.3.1` via `segmentio/encoding`. |
| GHSA-q382-vc8q-7jhj | The `v1.3.1` fix itself: trailing `NUL` in keys + duplicate keys → last-key-wins override. Needs `segmentio/encoding v0.5.4`, pulled in by SDK `v1.4.1`. |
| CVE-2026-33252 | Streamable-HTTP transport accepted cross-site `POST` without `Origin` or `Content-Type` validation → cross-site tool execution against an unauthenticated local server. |
| CVE-2026-34742 | DNS-rebinding protection off by default for localhost HTTP servers. On by default from `v1.4.0`. |

`v1.4.1` requires **Go 1.25+**; `backend/go.mod` is on `1.26.8`, so there is no toolchain
blocker. It also pulls `segmentio/encoding` + `segmentio/asm` as indirects — `segmentio/asm`
is already in the tree via `clickhouse-go`.

Practical consequences, all of which belong in the 1.0 contract rather than a later patch:

- **Pin `>= v1.4.1` in `go.mod` and add the SDK to the Dependabot/CVE watch list.** A
  supply-chain tool shipping a transitively vulnerable MCP server is the kind of headline
  the project does not recover from.
- **Default transport is stdio.** HTTP transport is opt-in via `mcp.transport=http`, and
  when enabled the chart must require either auth or an explicit allowed-origins list —
  CVE-2026-33252 and -34742 are both "unauthenticated HTTP on localhost" bugs.
- Both decisions are `values.yaml` shape, which is why they cannot wait for 1.1.

**Scope guard for #399:** read-only tools only (`list_projects`, `get_project`,
`search_packages`, `list_vulnerabilities`, `get_sbom`). No write tools, no LLM calls in-tree
— that stays a Non-Goal (see below). Uploading and VEX generation remain VEXViper's job.

### 2d. Chart & correctness hygiene (added 2026-09-24)

Five issues that had no milestone. Each one either invalidates something the 1.0 criteria
already claim as done, or changes `values.yaml` — which freezes with the tag.

| # | Issue | Why pre-1.0 |
|---|-------|-------------|
| **#355** | `source_repo` extraction yields 0 % on real SBOMs — `documentNamespace` ignored when `DESCRIBES` is absent | **This is the sharpest one.** #332 is ticked off in the 1.0 criteria above, but on 500 CNCF SBOMs it populates `source_repo` for **zero** of them, while every one carries the repo in `documentNamespace`. Tagging 1.0 with a checked box for a feature at 0 % real-world coverage is the freeze claiming something it does not do — and #338/VEXViper depends on that field to know what to clone. Fix is one last-resort fallback branch in `extractSourceRepo` + release-URL handling in `sourcerepo.Normalize`. |
| **#397** | `licenseExceptions.existingConfigMap` (+ `licensePolicy`) | Pure `values.yaml` addition → freezes with 1.0. Without it GitOps users must inline a ~180 KB exceptions file into an Argo `Application` (cncf/automation#703). Adding the key in 1.1 is fine mechanically, but the mutual-exclusion semantics with `custom` and the rollout-annotation behaviour are contract, not implementation. |
| **#391** | Seed job never seeds — clone commented out since 2026-03, hangs forever | Ships broken in every release since March, renders whenever `gitSync.enabled=false` — which is **our own** `values-production.yaml` recommendation. Needs a `seedJob.enabled` flag (new value → freeze) and `activeDeadlineSeconds`, or removal. Either way `examples/` must stop pointing at it. |
| **#392** | Chart ships ClickHouse 24.8, CI tests 24.12 | Not currently broken — all 22 migrations and the smoke-tested queries pass on 24.8 (measured in the issue). But the **support policy starts at 1.0**, so the supported ClickHouse floor has to be a deliberate, written-down decision before the tag, not a value nobody touched since the first commit. Either move the chart to 24.12 or add 24.8 to the test matrix and record the LTS intent. |
| **#344** | UI latency: N+1 loops, `FINAL` everywhere, unused `dashboard_stats_mv`, no caching, 5000-row UI loads | The issue argues it needs no freeze — true for findings A–D and F–H, which stay additive. Two parts do not: **E** (`enrichProjectStats` full-scans `sbom_packages` + `vulnerabilities` for *all* projects) is the exact function #398 rewrites, so they must land together or the de-dup gets built twice; and **I** proposes ClickHouse `max_threads`/`max_memory_usage`/`max_execution_time` defaults in `values.yaml`. Priority is already `high`. |

> **Sequencing note:** #344-E and #398 touch `queries_projects.go` in the same places.
> Do #398 first (it defines the correct semantics), then #344-E makes those semantics fast.
> Doing it the other way round means optimising a query that is about to change.

### 2e. Release engineering

| # | Issue | Notes |
|---|-------|-------|
| **#145** | Versioned documentation | Docsy `params.versions`, `release/vX.Y` branch → `docs.bomhort.dev/vX.Y/`. Must ship **with** the 1.0 tag, prepared beforehand. |
| — | Data-migration Job covers all tables | ✅ `registry_license_cache` (#341) and `document_store` (#256) both covered. |
| — | Helm chart ships every migration | ✅ Fixed while landing `015`: `013` and `014` had never been copied into `deploy/helm/bomhort/migrations/`, so Helm deployments never applied them. `make check-migrations` now guards the whole directory. |
| — | Migration guide + `values.yaml` stability review | Required by our major-version policy (see `AGENTS.md`). The review must cover the **new** keys landing in this phase: `mcp.*` (#399), `licenseExceptions/licensePolicy.existingConfigMap` (#397), `seedJob.enabled` (#391), ClickHouse query limits (#344-I) and the ClickHouse image pin (#392). They all freeze together. |
| — | `AGENTS.md` dependency list | Must go from 5 to 6 direct dependencies (`modelcontextprotocol/go-sdk >= v1.4.1`) — see 2c. |
| — | Milestone hygiene | ✅ Done 2026-09-24: milestone 1 due date → `2026-11-30`; `v1.1.0`/`v1.2.0`/`v2.0.0` created; all 33 open issues assigned. See the milestone map below. |

### 🎯 v1.0.0 Milestone

**Target: end of November 2026** (milestone due date set to `2026-11-30` on 2026-09-24).
Moved twice: the previous re-plan pushed it from `2026-09-30` to end-October for #145 and
soak time, and the 2026-09-24 re-plan added #398/#399/#58 plus the five hygiene issues
(#344, #355, #391, #392, #397) on top.

- API contract frozen (no breaking changes without major version bump)
- ClickHouse schema stable (no `ORDER BY`/type changes; `ADD COLUMN` and new tables remain allowed)
- Helm chart values stable — including `mcp.*` (#399), `existingConfigMap` (#397), `seedJob.enabled` (#391) and the ClickHouse limits (#344-I)
- Supported ClickHouse version floor decided, written down and covered by CI (#392)
- Support policy (current − 2) takes effect
- Versioned documentation enabled (#145)

**v1.0 Criteria:**
- [x] ~~Version Skew Detection~~ (#37)
- [x] ~~API Authentication~~ (#134)
- [x] ~~Cluster-aware schema~~ (#131)
- [x] ~~Cluster listing + detail endpoints~~ (#132, #133)
- [x] ~~Upload endpoint stable~~ (#135)
- [x] ~~CycloneDX parsing~~ (#55)
- [x] ~~Health probes~~ (#137)
- [x] ~~Tier-2 fidelity capture — `document_store` + blob store (#256)~~
- [x] ~~Namespace column + ingestion convention (#138)~~ — migration `015`, `INGEST_PATH_LAYOUT`, `?namespace=` on upload
- [x] ~~`source_repo`/`source_ref` columns (#332)~~ — migration `016`, `X-Source-Repo`/`X-Source-Ref` headers, `PATCH /sboms/{id}`
- [x] ~~VEX provenance columns (#334, columns only)~~ — migration `017`
- [x] ~~`project` column (#57, column only)~~ — migration `015`, `?project=` on upload
- [x] ~~One row per `(vuln_id, purl)` — latest VEX wins (#335)~~
- [x] ~~`cluster` in `SBOMListItem` (#177)~~ — badges in the explorer
- [ ] **Project-centric read model + de-duplicated project counts (#398)** — locks the project identity rule and fixes frozen row semantics
- [ ] **Aggregated SBOM View (#58)** — UI half of #398
- [ ] **MCP server + `mcp.*` Helm values (#399)** — read-only, SDK `>= v1.4.1`, stdio by default
- [ ] **`source_repo` fallback to `documentNamespace` (#355)** — un-breaks the #332 checkbox above
- [ ] **`licenseExceptions/licensePolicy.existingConfigMap` (#397)** — values shape
- [ ] **Seed job fixed, gated or removed (#391)** — new `seedJob.enabled` value
- [ ] **ClickHouse supported-version floor decided and tested (#392)** — support policy starts at 1.0
- [ ] **Perf findings E + I (#344)** — `enrichProjectStats` (lands with #398) + ClickHouse limits in values
- [ ] Versioned docs (#145) — must ship *with* the tag

**Open 1.0 blockers: #398, #58, #399, #355, #397, #391, #392, #344, #145.** (#145 was the
only one until the 2026-09-24 re-plan; the other eight were either new or had no milestone.)

### Milestone map

Every open issue now carries a milestone — "no milestone" is no longer a valid state.

| Milestone | Due | Phase | Open issues |
|-----------|-----|-------|-------------|
| [v1.0.0](https://github.com/seebom-labs/seebom/milestone/1) | 2026-11-30 | Phase 2 — freeze | #58, #145, #344, #355, #391, #392, #397, #398, #399 |
| [v1.1.0](https://github.com/seebom-labs/seebom/milestone/2) | 2027-03-31 | Phase 3 — automation & fleet | #57, #60, #62, #136, #140, #143, #176, #266, #267, #333, #336, #337, #338 |
| [v1.2.0](https://github.com/seebom-labs/seebom/milestone/3) | 2027-06-30 | Phase 4 — analytics & compliance | #7, #38, #56, #61, #63, #64, #82, #141, #254, #255 |
| [v2.0.0](https://github.com/seebom-labs/seebom/milestone/4) | — | breaking only | #268 |

`v2.0.0` has no due date on purpose: per the major-version policy in `AGENTS.md` it is
driven by accumulated breaking changes (earliest Q1/Q2 2028), not by a calendar.

**#57 moved from v1.0.0 to v1.1.0.** Its `project` column shipped in migration `015` and is
ticked off above; what remains in the issue is per-project *policies*, which are Phase 3 and
additive. Leaving it on the 1.0 milestone made the freeze look blocked by work that is
explicitly post-freeze.

**Landed after the last re-plan, all still pre-1.0** (migrations `019`–`022`): OSV alias
matching, the VEX rescue pass, `document_version`, and free-form `tags` (#357) with the
`/tags` endpoint and the namespace drill-down. These close the schema wave — every column
a post-1.0 feature is known to need now exists. **This is why #398 needs no migration:**
`project` (`015`), `tags` (`022`) and `document_version` (`021`) already carry everything
a project-centric read model has to group and de-duplicate by. What's left is query and
DTO work — which is exactly the part that freezes.

**Exit criteria:** Every SBOM ingested from 1.0 onward can be reproduced byte-for-byte; every column a later feature needs already exists; the vulnerability endpoint returns deterministic rows; **a project can be answered for as a project (de-duplicated, stable identity), and an agent can ask that question over MCP.**

---

## Phase 3: Automation & Fleet Operations (v1.1.0, Q1 2027)

**Theme:** Make BOMHort a first-class platform for *automated* supply-chain workflows — starting with VEX generation — and finish the fleet-scale views.

### 3a. Epic #338 — Automated VEX generation (VEXViper integration)

[VEXViper](https://github.com/seebom-labs/VEXViper) is an out-of-tree Go sidecar that reads findings via the REST API, gathers evidence (govulncheck, version compare), asks a configurable LLM or rule engine and uploads go-vex-validated OpenVEX back. Sub-issues, in the order the sidecar needs them:

| # | Issue | Type | Notes |
|---|-------|------|-------|
| ~~#332~~ / ~~#335~~ | Correctness blockers | — | Landed in Phase 2. |
| **#336** | Idempotent VEX upload + `GET /api/v1/uploads/{job_id}` (applied / matched / unmatched) | New table `upload_jobs` (additive) + content-hash dedupe | Unblocks scale; also surfaces PURL/vuln-id mismatches in the UI. |
| **#333** | Incremental listing (`since`/`cursor`) + `vex_status=missing` filter | Query-only, additive params | Cuts a 15 000-SBOM sweep from >25 min to seconds. |
| **#334** | VEX provenance UI: automated vs. human badge, `status_notes`, `?vex_source=` | Frontend + query (columns from `017`) | Auditors see *who/what* decided. |
| **#337** | Outbound webhooks (`sbom.ingested`, `findings.updated`, `vex.applied`, `upload.rejected`) | New Helm values + `internal/webhook` (stdlib only) | Replaces polling; HMAC-signed payloads. |
| — | `docs/integrations/vexviper` | Docs | Once the above stabilises. |

### 3b. Fleet operations

| # | Issue | Rationale |
|---|-------|-----------|
| **#138** (API + UI) | `?namespace=` filters + namespace chips | Column landed in `015`; this is the consumer side. |
| **#267** → **#176** | Cluster filter via query param → full Cluster Picker (`/clusters` route, per-cluster dashboard) | Backend ready since #132/#133; UI has zero cluster awareness. #267 is the help-wanted Phase 1. |
| **#140** | Workload vulnerability summary | Image → posture cross-reference; powers #141. |
| **#57** (policies) | Per-project license policies, severity thresholds, exception scopes | Column landed in `015`; the project identity rule is fixed by #398, so policies finally have a stable key to attach to. Resolution via bucket config / upload payload / name convention. |
| ~~**#58**~~ | ~~Aggregated SBOM View~~ | **Moved to Phase 2c** — it is the UI half of #398 and shares its de-dup semantics. |
| **#136** (rest) | `CORS_ALLOW_CREDENTIALS`, configurable methods/headers | Small, additive. |
| **#399** (write tools) | MCP write/mutation tools, if ever wanted | The 1.0 server is read-only by design. Additive tools need no contract change — that's the whole point of doing the read surface first. |

### 3c. Compliance foundations

| # | Issue | Rationale |
|---|-------|-----------|
| **#266** → **#62** | CSV export for vulnerabilities (stdlib `encoding/csv`, no new dependency) → full auditor reports (PDF; needs maintainer decision on `gofpdf` vs `pdfcpu`) | Auditors don't use UIs. CSV first, PDF after the dependency decision. |
| **#60** | Local OSV Mirror | Removes the osv.dev runtime dependency; offline / air-gapped scans; no rate limits. |
| **#143** | In-toto Witness integration | New `attestations` table (additive), signature verification, provenance display. Phased: Phase 1 no new deps; Sigstore/Fulcio via `sigstore-go` later. Prerequisite for #141. |

**Exit criteria:** An external tool can discover new findings without polling, push VEX idempotently and see the result; multi-cluster/namespace views exist in the UI; vulnerability data exports to CSV; OSV works offline.

---

## Phase 4: Analytics & Compliance (v1.2.0, 2027 H1)

**Theme:** Regulatory readiness scoring and supply-chain intelligence on top of the mature data model.

| # | Issue | Rationale |
|---|-------|-----------|
| **#141** | CRA Compliance Dashboard | EU Cyber Resilience Act enforcement 2027. Needs #140, #143, #62. |
| **#255** | Editable/enriched SBOMs + enriched download (+ companion VEX, in-toto re-sign) | Builds on #256 originals. Overlay table `ReplacingMergeTree` (latest wins); export re-signed with BOMHort as transforming instance. Additive → no major bump. |
| **#254** | Evaluate protobom/storage relational schema for ClickHouse | Research issue. Informs #255's overlay design; **not** a rewrite of the analytical `sbom_packages` array model. |
| **#38** | SBOM Diff (tree divergence) | "What changed between v1.7.1 and v1.7.2?" |
| **#56** | Dependency Tree View | Hierarchical visualization of transitive chains. |
| **#63** | Blast Radius Search | Extends Package Search with version constraints, vuln context, direct/transitive. |
| **#64** | EPSS Scores | Exploit probability > CVSS. Free daily bulk data; extends `cve-refresher`. |
| **#61** | OpenSSF Scorecard | Upstream project health; extends `internal/github`. |
| **#82** | Lottery Factor | Single-maintainer risk; extends `internal/github`. |
| **#7** | CVE Fix Time (MTTR) | Key KPI for SOC2 / ISO 27001 audits. |
| **#268** | Evaluate official ClickHouse operator (vs. Altinity) | Breaking `values.yaml` change → **requires a major bump and migration guide**; only if maturity gate is met. Candidate for v2.0. |

**Exit criteria:** CRA readiness score per cluster, exploit-probability prioritisation, dependency-health metrics, SBOM diff, enriched export.

---

## Schema Change Register

Everything that touches `db/migrations/` or a frozen response shape, in one place. Rule: **`ORDER BY` or column-type changes are never allowed after 1.0** (MergeTree can't alter them in place). `ADD COLUMN … DEFAULT` and new tables are fine at any time.

| Migration | Issue | Change | Pre/Post 1.0 |
|-----------|-------|--------|:------------:|
| `012_add_cluster_column` | #131 | `ADD COLUMN cluster` on core tables | ✅ shipped |
| `013_create_registry_license_cache` | #330 | New table | ✅ shipped |
| `014_create_document_store` | #256 | New table (reference + hash; blob store external) | **pre** |
| `015_add_namespace_project_columns` | #138, #57 | `ADD COLUMN namespace`, `ADD COLUMN project` on core tables (+ `document_store`) | ✅ shipped (**pre**) |
| `016_add_source_columns` ✅ | #332 | `ADD COLUMN source_repo, source_ref` on `sboms` + `ingestion_queue` | **pre** |
| `017_add_vex_provenance` ✅ | #334 | `ADD COLUMN author, role, tooling, status_notes` on `vex_statements` | **pre** |
| `018_add_vex_sbom_scope` ✅ | #350 | `ADD COLUMN sbom_id` on `vex_statements`, `ADD COLUMN target_sbom_id` on `ingestion_queue` — VEX statements scoped to the SBOM/product they describe | **pre** |
| `019_add_vulnerability_aliases` ✅ | — | `ADD COLUMN aliases Array(String)` on `vulnerabilities` — OSV alias IDs (GHSA ↔ CVE); VEX suppression matches a statement by `vuln_id` **or** any alias | **pre** |
| `020_add_vex_product_ref` ✅ | — | `ADD COLUMN product_ref` on `vex_statements` — persisted OpenVEX product `@id`; enables the post-ingest **VEX rescue** pass that scopes previously unresolvable statements | **pre** |
| `021_add_document_version` ✅ | — | `ADD COLUMN document_version` on `sboms` — version of the described product (SPDX root `versionInfo`, CycloneDX `metadata.component.version`) | **pre** |
| `022_add_sbom_tags` ✅ | #357 | `ADD COLUMN tags Array(String)` on `sboms` + `ingestion_queue` — grouping labels orthogonal to cluster/namespace/project, for catalogue instances that group projects without deploying them. Tags label projects, they do not replace them | **pre** |
| — (query only) ✅ | #335 | Row semantics of `/sboms/{id}/vulnerabilities` | **pre** (API contract) |
| — (DTO only) | #177 | `cluster` in `SBOMListItem` | **pre** (API contract) |
| — (query + DTO) | **#398** | De-duplicated `package_count`/`vuln_count` in `ProjectListItem`; project identity rule (`projectKeyExpr`) becomes contract; new `/projects/{name}` sub-resources | **pre** (API contract — row semantics) |
| — (Helm values) | **#399** | New `mcp.*` values block; no schema change, read-only consumer | **pre** (values contract) |
| — (Helm values) | **#397** | `licenseExceptions.existingConfigMap` + `licensePolicy.existingConfigMap`, mutually exclusive with `custom` | **pre** (values contract) |
| — (Helm values) | **#391** | New `seedJob.enabled` gate + `activeDeadlineSeconds` (or removal of the Job) | **pre** (values contract) |
| — (Helm values) | **#392** | ClickHouse image pin / supported version floor | **pre** (support policy) |
| — (Helm values) | **#344**-I | ClickHouse `max_threads`, `max_memory_usage`, `max_execution_time` defaults | **pre** (values contract) |
| — (parser only) | **#355** | `documentNamespace` fallback in `extractSourceRepo` — fixes 0 % population of the `016` columns | **pre** (makes #332 actually true) |
| `02x_create_package_index_mv` | #344-C/D/E | MV + skip indexes for search/aggregation | post (additive, no contract) |
| `02x_create_upload_jobs` | #336 | New table | post |
| `02x_create_attestations` | #143 | New table | post |
| `02x_*` | #64, #61, #82, #7, #255, #60 | New enrichment / overlay / mirror tables | post |
| — | #268 | Operator swap (`values.yaml` breaking) | **v2.0** |

---

## Dependency Graph

```
#256 (Fidelity capture / document_store) ──┬── #255 (Enriched SBOM export + re-sign)
                                           ├── makes #138/#332/#334 back-fillable
                                           └── follow-up hook in #135 (Upload)

#332 (source_repo) ──┐
#335 (latest VEX)  ──┼── #338 Epic (VEXViper) ── #336 (idempotent upload) ── #333 (since/cursor) ── #337 (webhooks)
#334 (provenance)  ──┘                                                       └── #334 UI badge

#131 (Cluster) ── #132/#133 ── #177 (badge) ── #267 (query-param filter) ── #176 (Cluster Picker)
              └── #138 (Namespace) ── #140 (Workload Summary) ──┐
                                                                ├── #141 (CRA Dashboard)
#143 (Witness) ─────────────────────────────────────────────────┤
#266 (CSV) ── #62 (Auditor reports) ────────────────────────────┘

PRE-1.0 project cluster:
#57 (project column, 015) ──┐
#357 (tags, 022)            ├── #398 (Project-centric read model) ──┬── #58 (Aggregated SBOM View)
#021 (document_version)     ┘        │                              └── #399 (MCP: get_project)
                                     └── locks projectKeyExpr as contract
                                     └── post-1.0: #57 (policies) — needs #398's stable key

#399 (MCP server) ── read-only over the frozen REST surface
                  └── post-1.0: write tools, agentic workflows

#60 (OSV Mirror) ── standalone
#64 (EPSS) ── extends cve-refresher
#61 (Scorecard), #82 (Lottery) ── extend internal/github
#254 (protobom schema eval) ── informs #255
#268 (operator eval) ── v2.0 candidate
```

---

## Prioritization Rationale

### Why a single migration wave before 1.0?

After the freeze we can still add columns and tables — but we can never recover data we didn't capture. #256 (original bytes) is the only truly irrecoverable one; the others (#138, #332, #334, #57) are cheap `ADD COLUMN`s whose *ingestion* side we want frozen so producers (CI pipelines, VEXViper) can rely on the contract. Landing them together minimises the number of times operators run migrations against production ClickHouse.

### Why #398 (project-centric view) before 1.0, when it needs no migration?

Because "no migration" is not the same as "no contract". Two things freeze with it:

1. **The numbers.** `ProjectListItem.package_count` and `vuln_count` currently sum per-SBOM
   counts (`queries_projects.go`), so a project with five SBOMs that all contain `libcurl`
   reports it five times. That is arguably a bug — but it is a *shipped* one, and operators
   are already putting those numbers in reports. Correcting it post-1.0 changes every
   dashboard silently, with no version signal. Correcting it pre-1.0 is just a fix.
2. **What a project *is*.** `projectKeyExpr` resolves identity through three fallbacks
   (explicit column → path derivation → `document_name`). #398 is precisely about that:
   this yields `OpenTelemetry/subproject@v1.2.3` where users expect `OpenTelemetry`. Changing
   the identity rule later re-shards every project in every installation — it is
   forward-only in effect, even though no `ALTER TABLE` is involved.

#58 rides along because it is the same de-duplication expressed in the UI. Building it in
Phase 3 against Phase-2 semantics would mean designing the aggregation twice.

### Why #399 (MCP server) before 1.0, when it's purely additive?

The component is additive; its **Helm values are not**. `values.yaml` stability is an
explicit 1.0 criterion, so an `mcp.*` block added in 1.1 is either a breaking reshuffle
or a schema we guessed once and live with for a major cycle.

The second reason is cheaper to state than to discover later: an MCP server is a
*consumer* of the REST contract, and consumers find contract holes that internal callers
never hit. #398 exists because the UI can paper over bad aggregates with grouping logic in
Angular; an agent calling `get_project` cannot. Building the consumer before the freeze is
how we verify the freeze is worth freezing.

It stays read-only in 1.0 deliberately — write tools are additive (Phase 3) and keep the
blast radius of an agent pointed at a compliance database at zero.

### Why break the 5-dependency rule for #399?

The rule exists to limit supply-chain exposure in a supply-chain tool, so the instinct is
to hand-roll JSON-RPC 2.0 — the MCP surface is small enough. The four HIGH advisories
against `go-sdk < v1.4.1` are the argument *against* that instinct, not for it: three of
them (case-folded JSON keys, `NUL`-terminated duplicate keys, cross-site POST without
`Origin` validation) are exactly the class of bug a hand-rolled parser and handler would
reproduce from scratch, with nobody auditing it. The SDK has already been through a
Doyensec review and shipped the fixes; we would be starting at the pre-review state.

Taking the dependency means we inherit those fixes *and* the future ones, on the condition
that the version is pinned `>= v1.4.1` and tracked. That condition is the whole trade.

### Why do five "housekeeping" issues block a freeze?

Because four of the five add or change `values.yaml` keys (#397, #391, #392, #344-I), and
values stability is one of the five things 1.0 promises. A key added in 1.1 is not free:
it either ships with a shape we guessed under time pressure, or it gets reshaped and
breaks the promise.

The fifth, #355, is a different problem: the 1.0 criteria above *tick off* #332 source
attribution, while on the most obvious real corpus — 500 published CNCF SBOMs — it
populates the column for zero of them. Freezing a contract is a claim about what the
software does. A ticked box with 0 % real-world coverage makes that claim false, and
#338/VEXViper is built on the assumption that it is true.

### Why VEXViper before analytics?

Automated VEX turns a wall of CVEs into a triaged queue. Every analytics feature (EPSS, CRA score, MTTR) is more useful once `not_affected` noise is gone. The sidecar exists today; BOMHort-side gaps (#332–#337) are the bottleneck.

### Why CRA compliance in 2027 H1, not Q4 2026?

The EU CRA reporting obligations start September 2026 for vulnerabilities; full conformity obligations December 2027. #141 needs #140, #143 and #62 first — they're Phase 3. Shipping #141 in H1 2027 still gives adopters ~9 months before the full obligations.

### Why enrichment features (EPSS/Scorecard/Lottery) as a batch?

Same pattern: fetch external data → ClickHouse table → API → UI. Implementing together maximises reuse.

### Cluster vs. project vs. namespace

Three orthogonal low-cardinality dimensions:

| Dimension | Question | Example | Cardinality | Owner |
|-----------|----------|---------|-------------|-------|
| `cluster` | Where is it deployed? | `prod-eu` | 1–50 | Platform |
| `namespace` | Which tenant/team boundary inside the cluster? | `payments` | 10–500 | Platform / team |
| `project` | What is it / who owns it? | `payment-service` | 50–5000 | Dev teams |

All three are `LowCardinality(String) DEFAULT ''` columns; none is in `ORDER BY`. Filtering is by `WHERE`, which is fine for the data volumes involved.

---

## Success Metrics

| Phase | Metric | Target |
|-------|--------|--------|
| Phase 2 | Round-trip fidelity | 100 % of SBOMs ingested post-1.0 downloadable byte-identical (`sha256` match) |
| Phase 2 | Project aggregation (#398) | A component present in N SBOMs of one project is counted **once**; `GET /projects/{name}` answers in < 500 ms at 15 000 SBOMs |
| Phase 2 | MCP surface (#399) | All five read tools callable from a stock MCP client; SDK pinned `>= v1.4.1`; stdio default, HTTP opt-in and never unauthenticated |
| Phase 2 | Source attribution (#355) | `source_repo` populated for **> 90 %** of the 500-SBOM CNCF corpus (today: 0 %) |
| Phase 2 | Chart honesty (#391, #392, #397) | `helm template` with our own `values-production.yaml` renders nothing that hangs; chart and CI pin the same ClickHouse version |
| Phase 2 | UI latency (#344-E) | Projects page stops full-scanning `sbom_packages` + `vulnerabilities` for every project |
| Phase 3 | Automated triage | VEXViper `watch` pass over 15 000 SBOMs < 60 s; 0 duplicate VEX rows |
| Phase 3 | Fleet views | Cluster + namespace filter on all list pages |
| Phase 4 | CRA readiness | All 5 CRA conditions evaluable, score > 80 % for managed clusters |

---

## Non-Goals (Explicitly Out of Scope)

- **Custom Kubernetes Operator**: Helm + ClickHouse Operator. No custom CRDs.
- **In-tree VEX generation / LLM calls**: stays in the VEXViper sidecar. The MCP server (#399) is a *transport* — it exposes read tools to whatever agent the operator runs. BOMHort never calls an LLM itself, and MCP is not a plugin surface.
- **MCP write tools in 1.0**: read-only by design. Mutation tools are additive → Phase 3.
- **Write APIs for license exceptions**: Frontend is public. Policy changes require config file updates.
- **Multi-repo split**: Monorepo is a hard constraint for AI-assisted development.
- **Real-time streaming**: Batch ingestion (CronJob + queue) plus outbound webhooks (#337) is sufficient.
- **RBAC/multi-tenancy**: Auth is binary. Fine-grained RBAC is beyond this roadmap.
- **Full OIDC in BOMHort**: User authentication is the upstream proxy's responsibility.
- **Relational rewrite of the dependency model** (#254): protobom/storage's normalized schema is evaluated for the *overlay* only; the analytical `sbom_packages` array model stays.
- **A second project hierarchy** (#398): projects are grouped by `tags` (migration `022`), not by a new org/sub-project table. Tags label projects, they do not replace them.

