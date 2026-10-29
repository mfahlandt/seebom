-- Rebuild the queue because ClickHouse cannot change a ReplacingMergeTree
-- version column's type in place. Stop all queue writers during this migration.
DROP TABLE IF EXISTS ingestion_queue_migration_next;

CREATE TABLE ingestion_queue_migration_next (
    created_at      DateTime64(3) DEFAULT now64(3),
    job_id          UUID,
    source_file     String,
    sha256_hash     FixedString(64),
    status          LowCardinality(String) DEFAULT 'pending',
    job_type        LowCardinality(String) DEFAULT 'sbom',
    claimed_by      String DEFAULT '',
    claimed_at      Nullable(DateTime),
    finished_at     Nullable(DateTime),
    error_message   String DEFAULT '',
    cluster         LowCardinality(String) DEFAULT '',
    namespace       LowCardinality(String) DEFAULT '',
    project         LowCardinality(String) DEFAULT '',
    source_repo     LowCardinality(String) DEFAULT '',
    source_ref      String DEFAULT '',
    target_sbom_id  String DEFAULT '',
    tags            Array(String) DEFAULT [],
    parent          LowCardinality(String) DEFAULT '',
    retry_after     DateTime DEFAULT toDateTime(0)
) ENGINE = ReplacingMergeTree(created_at)
ORDER BY (status, created_at, job_id);

INSERT INTO ingestion_queue_migration_next
SELECT
    toDateTime64(created_at, 3),
    job_id,
    source_file,
    sha256_hash,
    status,
    job_type,
    claimed_by,
    claimed_at,
    finished_at,
    error_message,
    cluster,
    namespace,
    project,
    source_repo,
    source_ref,
    target_sbom_id,
    tags,
    parent,
    retry_after
FROM ingestion_queue;

EXCHANGE TABLES ingestion_queue AND ingestion_queue_migration_next;
DROP TABLE IF EXISTS ingestion_queue_migration_next;

INSERT INTO data_migrations (name)
SELECT 'ingestion_queue_created_at_datetime64'
WHERE (SELECT count() FROM data_migrations FINAL WHERE name = 'ingestion_queue_created_at_datetime64') = 0;
