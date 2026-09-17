-- Migration 015: Add namespace (#138) and project (#57) columns to core tables.
--
-- Part of the coordinated pre-1.0 schema wave (014-017, see ROADMAP.md).
-- Both columns follow the exact pattern established by `cluster` in migration
-- 012: LowCardinality(String) DEFAULT '', a regular column, NOT part of
-- ORDER BY. MergeTree cannot alter ORDER BY in place, and adding these to the
-- sort key would require a full table rebuild for a filter dimension whose
-- cardinality (10-500 namespaces, 50-5000 projects) is low enough that a
-- WHERE-scan is fine at the data volumes involved.
--
-- Non-destructive: existing rows get DEFAULT '' (= unassigned). The value is
-- populated at ingest time from the ingestion path convention
-- ({cluster}/{namespace}/{project}/file.json, opt-in via INGEST_PATH_LAYOUT),
-- from static per-bucket config, or from upload query params.
--
-- Why pre-1.0: the columns themselves are cheap ADD COLUMNs that could land
-- any time, but the *ingestion contract* that populates them (path layout +
-- upload params) must be frozen before producers (CI pipelines, VEXViper)
-- start relying on it.
--
-- The three dimensions are orthogonal:
--   cluster   - where is it deployed?           (prod-eu)         1-50
--   namespace - which tenant/team boundary?     (payments)        10-500
--   project   - what is it / who owns it?       (payment-service) 50-5000

ALTER TABLE sboms ADD COLUMN IF NOT EXISTS namespace LowCardinality(String) DEFAULT '';
ALTER TABLE sbom_packages ADD COLUMN IF NOT EXISTS namespace LowCardinality(String) DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS namespace LowCardinality(String) DEFAULT '';
ALTER TABLE license_compliance ADD COLUMN IF NOT EXISTS namespace LowCardinality(String) DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS namespace LowCardinality(String) DEFAULT '';
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS namespace LowCardinality(String) DEFAULT '';
ALTER TABLE document_store ADD COLUMN IF NOT EXISTS namespace LowCardinality(String) DEFAULT '';

ALTER TABLE sboms ADD COLUMN IF NOT EXISTS project LowCardinality(String) DEFAULT '';
ALTER TABLE sbom_packages ADD COLUMN IF NOT EXISTS project LowCardinality(String) DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS project LowCardinality(String) DEFAULT '';
ALTER TABLE license_compliance ADD COLUMN IF NOT EXISTS project LowCardinality(String) DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS project LowCardinality(String) DEFAULT '';
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS project LowCardinality(String) DEFAULT '';
ALTER TABLE document_store ADD COLUMN IF NOT EXISTS project LowCardinality(String) DEFAULT '';

