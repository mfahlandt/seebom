-- 014_create_document_store.up.sql
-- Tier-2 fidelity capture (#256): reference to the original SBOM bytes as
-- ingested, so that a document can be reproduced byte-for-byte later
-- (download, enriched export, re-signing — see #255).
--
-- The raw bytes are deliberately NOT stored in ClickHouse: MB-scale blobs in
-- an OLAP MergeTree bloat parts and slow merges. They live in a configurable
-- blob store (S3/MinIO prefix or a mounted volume, ORIGINAL_STORE_*), and this
-- table only holds the reference plus integrity metadata.
--
-- ReplacingMergeTree(stored_at) keyed by sbom_id: re-ingesting the same
-- document (same sbom_id) replaces the reference; the latest capture wins.

CREATE TABLE IF NOT EXISTS document_store (
    stored_at        DateTime                DEFAULT now(),
    sbom_id          UUID,
    cluster          LowCardinality(String)  DEFAULT '',
    source_file      String,                                   -- as seen by the ingestion queue (s3://… or relative path)
    storage_backend  LowCardinality(String),                   -- s3 | fs
    storage_ref      String,                                   -- s3://bucket/key or fs://relative/path
    sha256_hash      String,                                   -- hex sha256 of the stored bytes (computed by the worker, not the S3 ETag)
    size_bytes       UInt64,
    content_type     LowCardinality(String)  DEFAULT 'application/json'
) ENGINE = ReplacingMergeTree(stored_at)
ORDER BY (sbom_id);

