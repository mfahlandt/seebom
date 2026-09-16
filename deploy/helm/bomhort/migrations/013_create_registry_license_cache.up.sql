-- Migration 013: Generic package-registry license cache.
-- Used by registry-based license resolvers (npm today, others later) to avoid
-- redundant API calls across worker restarts. Mirrors github_license_cache.
CREATE TABLE IF NOT EXISTS registry_license_cache (
    registry    LowCardinality(String),   -- e.g. 'npm'
    package     String,                   -- registry-specific key, e.g. '@scope/name@1.2.3'
    spdx_id     LowCardinality(String),   -- resolved expression, '' = negative result
    fetched_at  DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(fetched_at)
ORDER BY (registry, package);

