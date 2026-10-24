package clickhouse

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestQuerySBOMsByPURLs: one batched lookup returns each SBOM once per PURL
// with the shortest depth, and leaves PURLs no SBOM contains out of the map
// (#486). Needs CLICKHOUSE_HOST, see testClient.
func TestQuerySBOMsByPURLs(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	id := uuid.New()
	hit, miss := "pkg:golang/example.com/hit@"+id.String(), "pkg:golang/example.com/miss@"+id.String()

	if err := c.InsertSBOMPackages(ctx, &models.SBOMPackages{
		IngestedAt:            time.Now(),
		SBOMID:                id,
		SourceFile:            "refresh-purls-test.spdx.json",
		PackageSPDXIDs:        []string{"a", "b"},
		PackageNames:          []string{"hit", "hit-again"},
		PackageVersions:       []string{"1", "1"},
		PackagePURLs:          []string{hit, hit},
		PackageLicenses:       []string{"MIT", "MIT"},
		PackageLicenseSources: []string{"declared", "declared"},
		PackageDepths:         []uint16{3, 1},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := c.QuerySBOMsByPURLs(ctx, []string{hit, miss})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[miss]; ok {
		t.Errorf("unexpected refs for a PURL no SBOM contains")
	}
	refs := got[hit]
	if len(refs) != 1 || refs[0].SBOMID != id {
		t.Fatalf("want exactly one ref to %s, got %+v", id, refs)
	}
	if refs[0].DependencyDepth != 1 {
		t.Errorf("want shortest depth 1, got %d", refs[0].DependencyDepth)
	}
}
