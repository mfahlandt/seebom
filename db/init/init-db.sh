#!/bin/bash
# init-db.sh – Run on ClickHouse first start.
# Creates the bomhort database and runs all migrations.
set -e

echo "⏳ Creating bomhort database..."
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS bomhort"

echo "⏳ Running migrations..."
for f in /docker-entrypoint-initdb.d/migrations/*.sql; do
  echo "  → $f"
  if [[ "$(basename "$f")" == "028_ingestion_queue_created_at_datetime64.up.sql" ]]; then
    applied="$(clickhouse-client --database=bomhort --query "SELECT count() FROM data_migrations FINAL WHERE name = 'ingestion_queue_created_at_datetime64'")"
    if [[ "$applied" != "0" ]]; then
      echo "  ↪ already applied"
      continue
    fi
  fi
  clickhouse-client --database=bomhort --multiquery < "$f"
done

echo "✅ Database initialized."
