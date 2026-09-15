package clickhouse

import (
	"context"
	"fmt"
)

// QueryRegistryLicenseCache loads all cached package→license mappings for a
// registry (e.g. "npm") from registry_license_cache.
func (c *Client) QueryRegistryLicenseCache(ctx context.Context, registry string) (map[string]string, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT package, spdx_id
		FROM registry_license_cache FINAL
		WHERE registry = ?
	`, registry)
	if err != nil {
		return nil, fmt.Errorf("failed to query %s license cache: %w", registry, err)
	}
	defer rows.Close()

	cache := make(map[string]string)
	for rows.Next() {
		var pkg, spdxID string
		if err := rows.Scan(&pkg, &spdxID); err != nil {
			return nil, fmt.Errorf("failed to scan %s license cache row: %w", registry, err)
		}
		cache[pkg] = spdxID
	}
	return cache, nil
}

// InsertRegistryLicenseCache batch-inserts resolved registry licenses into the cache.
func (c *Client) InsertRegistryLicenseCache(ctx context.Context, registry string, entries map[string]string) error {
	if len(entries) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO registry_license_cache (registry, package, spdx_id)`)
	if err != nil {
		return fmt.Errorf("failed to prepare %s license cache batch: %w", registry, err)
	}

	for pkg, spdxID := range entries {
		if err := batch.Append(registry, pkg, spdxID); err != nil {
			return fmt.Errorf("failed to append cache entry %s: %w", pkg, err)
		}
	}

	return batch.Send()
}
