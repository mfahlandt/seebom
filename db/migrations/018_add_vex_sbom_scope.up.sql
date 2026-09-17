-- 018_add_vex_sbom_scope.up.sql
-- Scope VEX statements to the SBOM/product they describe (#350).
--
-- A VEX statement asserts the status of a vulnerability FOR A PRODUCT
-- (OpenVEX: `products[]` is the deliverable an SBOM describes, the vulnerable
-- library is a `subcomponent`). Justifications like
-- vulnerable_code_not_in_execute_path are reachability claims about one
-- product — project A may never call the vulnerable function while project B,
-- with the identical library version, is exploitable. Until this migration,
-- BOMHort matched statements fleet-wide on (vuln_id, product_purl), silently
-- suppressing real findings in unrelated projects.
--
--   vex_statements.sbom_id   The SBOM the statement is scoped to. Empty =
--                            global/legacy statement: it keeps matching every
--                            SBOM (backwards compatible), but an SBOM-scoped
--                            statement always beats a global one.
--   ingestion_queue.target_sbom_id
--                            Explicit mapping for pushed VEX documents
--                            (?sbom_id= on upload), carried to the worker.
--                            Empty for watcher jobs and SBOM jobs.
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS sbom_id String DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS target_sbom_id String DEFAULT '';

