package clickhouse

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
	"github.com/seebom-labs/bomhort/backend/internal/license"
)

func accumulate(t *testing.T, idx *license.ExceptionIndex, rows ...violationRow) []*sbomViolations {
	t.Helper()
	var got []*sbomViolations
	acc := &violationAccumulator{exceptions: idx, emit: func(e *sbomViolations) error {
		got = append(got, e)
		return nil
	}}
	for _, r := range rows {
		if err := acc.add(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := acc.flush(); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestViolationAccumulatorGroupsConsecutiveRows(t *testing.T) {
	got := accumulate(t, nil,
		violationRow{sbomID: "a", documentName: "A", licenseID: "GPL-3.0-only", category: "copyleft", packages: []string{"p1", "p1", "p2"}},
		violationRow{sbomID: "a", documentName: "A", licenseID: "NOASSERTION", category: "unknown", packages: []string{"p3", ""}},
		violationRow{sbomID: "a", documentName: "A", licenseID: "LicenseRef-x", category: "unapproved", packages: []string{"p1"}},
		violationRow{sbomID: "b", documentName: "B", licenseID: "NOASSERTION", category: "unknown", packages: []string{"q"}},
	)
	if len(got) != 2 {
		t.Fatalf("want 2 SBOMs, got %d", len(got))
	}
	a := got[0]
	if a.sbomID != "a" || a.copyleft != 3 || a.unknown != 2 || a.unapproved != 1 {
		t.Fatalf("counts: %+v", a)
	}
	if want := []string{"GPL-3.0-only", "NOASSERTION", "LicenseRef-x"}; !reflect.DeepEqual(a.licenses, want) {
		t.Fatalf("licenses %v, want %v", a.licenses, want)
	}
	// Deduplicated per license row, empty names dropped: p1 under two licenses stays twice.
	if want := []string{"p1", "p2", "p3", "p1"}; !reflect.DeepEqual(a.packages, want) {
		t.Fatalf("packages %v, want %v", a.packages, want)
	}
	if got[1].sbomID != "b" || got[1].unknown != 1 {
		t.Fatalf("second SBOM: %+v", got[1])
	}
}

func TestViolationAccumulatorAppliesExceptions(t *testing.T) {
	idx := license.BuildIndex(&license.ExceptionsFile{
		BlanketExceptions: []license.BlanketException{{License: "MPL-2.0", Status: "approved"}},
		Exceptions: []license.Exception{
			{Package: "exempt-pkg", License: "GPL-3.0-only", Status: "approved"},
			{Package: "pending-pkg", License: "GPL-3.0-only", Status: "pending"},
		},
	})
	got := accumulate(t, idx,
		violationRow{sbomID: "a", licenseID: "MPL-2.0", category: "copyleft", packages: []string{"m"}},
		violationRow{sbomID: "a", licenseID: "GPL-3.0-only", category: "copyleft", packages: []string{"exempt-pkg", "pending-pkg"}},
		// Everything in b is exempt: b must not be emitted at all.
		violationRow{sbomID: "b", licenseID: "GPL-3.0-only", category: "copyleft", packages: []string{"exempt-pkg"}},
		violationRow{sbomID: "c", licenseID: "MPL-2.0", category: "copyleft", packages: []string{"m"}},
	)
	if len(got) != 1 || got[0].sbomID != "a" {
		t.Fatalf("want only SBOM a, got %d entries", len(got))
	}
	if got[0].copyleft != 1 || !reflect.DeepEqual(got[0].packages, []string{"pending-pkg"}) ||
		!reflect.DeepEqual(got[0].licenses, []string{"GPL-3.0-only"}) {
		t.Fatalf("got %+v", got[0])
	}
}

func TestViolationAccumulatorEmitErrorStops(t *testing.T) {
	acc := &violationAccumulator{emit: func(*sbomViolations) error { return fmt.Errorf("boom") }}
	if err := acc.add(violationRow{sbomID: "a", category: "unknown", packages: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	if err := acc.add(violationRow{sbomID: "b", category: "unknown", packages: []string{"y"}}); err == nil {
		t.Fatal("emit error on SBOM change must be returned")
	}
}

func TestSummarizeViolations(t *testing.T) {
	e := &sbomViolations{
		sbomID: "a", sourceFile: "a.json", documentName: "A",
		copyleft: 1, unknown: 3, licenses: []string{"GPL-3.0-only", "NOASSERTION"},
		packages: []string{"d1", "d2", "t1", "root", "none"},
	}
	scopes := map[string]string{
		"d1": depgraph.ScopeDirect, "d2": depgraph.ScopeDirect,
		"t1": depgraph.ScopeTransitive, "root": depgraph.ScopeRoot,
	}
	s := summarizeViolations(e, scopes)
	if s.SBOMID != "a" || s.SourceFile != "a.json" || s.DocumentName != "A" ||
		s.CopyleftCount != 1 || s.UnknownCount != 3 || s.NonCompliantPackageCount != 5 ||
		s.DirectCount != 2 || s.TransitiveCount != 1 {
		t.Fatalf("got %+v", s)
	}
	if none := summarizeViolations(e, nil); none.DirectCount != 0 || none.TransitiveCount != 0 || none.NonCompliantPackageCount != 5 {
		t.Fatalf("no scopes: %+v", none)
	}
}

func TestChunkStrings(t *testing.T) {
	if got := chunkStrings(nil, 3); got != nil {
		t.Fatalf("nil input: %v", got)
	}
	got := chunkStrings([]string{"a", "b", "c", "d", "e", "f", "g"}, 3)
	want := [][]string{{"a", "b", "c"}, {"d", "e", "f"}, {"g"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A batch of SBOM ids interpolated into `IN (...)` must stay well below
// ClickHouse's default max_query_size of 256 KiB. One list of every violating
// SBOM did not, and failed in production with a syntax error at position 262108.
func TestScopeBatchFitsMaxQuerySize(t *testing.T) {
	id := "'" + strings.Repeat("f", 36) + "', "
	if size := scopeBatchSize * len(id); size > 64<<10 {
		t.Fatalf("a batch interpolates %d bytes of ids", size)
	}
}

func TestViolationsQueryFilter(t *testing.T) {
	all := fmt.Sprintf(violationsQuery, "")
	if strings.Contains(all, "%") || strings.Contains(all, "IN (?)") {
		t.Fatalf("unfiltered query must have no placeholder:\n%s", all)
	}
	filtered := fmt.Sprintf(violationsQuery, "AND sbom_id IN (?)")
	if n := strings.Count(filtered, "sbom_id IN (?)"); n != 2 {
		t.Fatalf("filter must apply to both JOIN sides, found %d", n)
	}
	if strings.Contains(all, "SELECT * FROM sboms") {
		t.Fatal("the JOIN's right side must not load every sboms column")
	}
}
