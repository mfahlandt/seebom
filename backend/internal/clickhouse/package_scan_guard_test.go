package clickhouse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoUnboundedFinalScanOfPackages keeps `SELECT * FROM sbom_packages FINAL`
// out of the package without needing a database.
//
// FINAL merges the ReplacingMergeTree in memory and `*` drags every array
// column along. Five package-wide aggregations were written that way, each
// joined to sboms to derive a project key, and on a 6M-row corpus every one
// exceeded the api-gateway's 512 MiB max_memory_usage. ClickHouse aborted
// mid-stream, rows.Err() was never checked, and /dependencies,
// /version-skew and /package-search rendered empty with a 200.
//
// Read sbom_packages directly: uniqExact/groupUniqArray are unaffected by
// unmerged duplicates, and packageProjectKey replaces the join. A scan that
// is bounded by sbom_id (a single SBOM or a project's SBOMs) may still use
// FINAL — name the columns instead of `*`.
func TestNoUnboundedFinalScanOfPackages(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read package directory: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if strings.Contains(line, "SELECT * FROM sbom_packages FINAL") {
				t.Errorf("%s:%d: SELECT * FROM sbom_packages FINAL — exceeds max_memory_usage on large corpora; read sbom_packages directly with named columns", name, i+1)
			}
		}
	}
}
