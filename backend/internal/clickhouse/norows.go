package clickhouse

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// isNoRows reports whether err means "the query matched nothing".
//
// clickhouse-go returns database/sql's ErrNoRows from Row.Scan, so errors.Is is
// the reliable test. The string comparison is kept as a fallback because the
// driver wraps the sentinel in some paths, and a missed detection here turns a
// perfectly normal 404 into a 500 plus an ERROR log line — see the SBOM detail
// endpoint, which reported "Failed to fetch SBOM detail" for every unknown id.
func isNoRows(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}
	return err.Error() == "sql: no rows in result set"
}

// sbomExists reports whether sboms holds a row for sbomID. Used to tell an
// unknown id (404) apart from a known SBOM whose dependent rows are missing.
func (c *Client) sbomExists(ctx context.Context, sbomID string) (bool, error) {
	var n uint64
	if err := c.Conn.QueryRow(ctx,
		"SELECT count() FROM sboms WHERE sbom_id = ?", sbomID,
	).Scan(&n); err != nil {
		return false, fmt.Errorf("failed to check sbom %s: %w", sbomID, err)
	}
	return n > 0, nil
}
