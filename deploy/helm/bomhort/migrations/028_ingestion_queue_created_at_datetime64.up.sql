-- Millisecond precision prevents concurrent queue transitions from sharing
-- the same ReplacingMergeTree version timestamp.
ALTER TABLE ingestion_queue
    MODIFY COLUMN created_at DateTime64(3) DEFAULT now64(3);
