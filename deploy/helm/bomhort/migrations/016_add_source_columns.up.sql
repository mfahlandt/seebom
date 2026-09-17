-- Migration 016: Add source_repo and source_ref columns (#332).
--
-- Part of the coordinated pre-1.0 schema wave (014-017, see ROADMAP.md).
-- Makes the product's source repository a first-class SBOM attribute instead
-- of something every consumer re-guesses from PURLs and SBOM hints. External
-- triage tooling (VEXViper: clone repo, run govulncheck, emit OpenVEX) needs
-- to know *where the source lives*; Syft dir: SBOMs, pkg:generic roots and
-- monorepos resolve badly from PURLs alone, and every miss is a manual pin.
--
--   source_repo  Repository URL, e.g. https://github.com/example-org/example-app
--   source_ref   Commit SHA, tag or branch the SBOM was generated from
--
-- Column types differ deliberately:
--   * source_repo is LowCardinality(String): one fleet has 50-5000 distinct
--     repositories, far under the ~100k threshold where LowCardinality
--     dictionaries stop paying off.
--   * source_ref is a plain String: commit SHAs are unique per build, so a
--     dictionary would just add indirection on top of high-cardinality data.
--
-- Neither column joins ORDER BY (same reasoning as cluster/namespace/project
-- in 012/015: MergeTree cannot alter a sort key in place, and a WHERE-scan is
-- fine for these access patterns).
--
-- Non-destructive: existing rows get DEFAULT '' (= unknown). Values are
-- populated at parse time from the document (SPDX root downloadLocation /
-- vcs ExternalRef; CycloneDX metadata.component.externalReferences[type=vcs]
-- and pedigree.commits[0].uid), overridable via X-Source-Repo/X-Source-Ref
-- upload headers and PATCH /api/v1/sboms/{id}.
--
-- Why pre-1.0: the *contract* (extraction rules, header names, PATCH shape)
-- must be frozen before VEXViper and CI pipelines start relying on it.
--
-- ingestion_queue also gets both columns: the upload headers have to travel
-- from the gateway to the parsing worker, and the queue is that channel
-- (exactly how cluster/namespace/project travel). The queue is append-only —
-- every writer rewrites the full row — so all writers share one column list
-- (see queueColumns in internal/clickhouse/queue.go, guarded by tests).

ALTER TABLE sboms
    ADD COLUMN IF NOT EXISTS source_repo LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_ref  String                 DEFAULT '';

ALTER TABLE ingestion_queue
    ADD COLUMN IF NOT EXISTS source_repo LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_ref  String                 DEFAULT '';

