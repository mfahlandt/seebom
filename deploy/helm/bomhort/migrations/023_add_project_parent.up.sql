-- 023_add_project_parent.up.sql
-- Parent (product) grouping of projects.
--
-- A project can belong to a parent: the CNCF subproject argo-cd/argo-workflows
-- belongs to argo, an internal service to a product line. The parent is
-- resolved at query time (internal/projectgroup) so a changed mapping file or
-- bucket config takes effect without re-ingesting. These columns only store
-- the raw inputs that resolution needs and that were not stored before:
--
--   parent     an explicit assignment from the ingest path: a bucket's
--              "parent", the "parent" path-layout token, ?parent= on upload or
--              the PARENT default. '' = none; resolution then falls back to
--              the mapping file and the automatic signals.
--   root_purl  the package URL of the component the SBOM describes (SPDX
--              root package, CycloneDX metadata.component). Its namespace
--              (maven groupId, npm scope, Go module owner) groups products
--              that have no repository URL.
--   supplier   who ships the product (CycloneDX manufacturer/supplier, SPDX
--              root package supplier/originator), for vendor SBOMs that carry
--              neither a repository nor a namespaced purl.
--
-- ingestion_queue carries parent so the explicit value survives the hop from
-- the watcher/gateway to the parsing worker, like cluster/namespace/project.
--
-- Cheap ADD COLUMNs, no ORDER BY change. Rows ingested before this migration
-- have '' everywhere; they still group through source_repo and document_name.
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS parent LowCardinality(String) DEFAULT '';
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS root_purl String DEFAULT '';
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS supplier String DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS parent LowCardinality(String) DEFAULT '';

