package license

import "testing"

func TestReevaluateMatchesAFreshCheck(t *testing.T) {
	names := []string{"github.com/a/gpl", "github.com/b/gpl", "github.com/a/gpl", "lgpl-lib", "mystery", "mit-lib", "custom"}
	lics := []string{"GPL-3.0-only", "GPL-3.0-only", "GPL-3.0-only", "LGPL-2.1-only", "NOASSERTION", "MIT", "LicenseRef-custom"}

	none := BuildIndex(&ExceptionsFile{BlanketExceptions: []BlanketException{}, Exceptions: []Exception{}})
	perPackage := BuildIndex(&ExceptionsFile{BlanketExceptions: []BlanketException{}, Exceptions: []Exception{
		{ID: "e1", Package: "a/gpl", License: "GPL-3.0-only", Status: "approved"},
		{ID: "e2", Package: "custom", Status: "approved"},
	}})
	scoped := BuildIndex(&ExceptionsFile{BlanketExceptions: []BlanketException{}, Exceptions: []Exception{
		{ID: "e3", Package: "lgpl-lib", License: "LGPL-2.1-only", Project: "my-project", Status: "approved"},
	}})
	blanket := BuildIndex(&ExceptionsFile{BlanketExceptions: []BlanketException{
		{ID: "b1", License: "LGPL-2.1", Status: "approved"},
		{ID: "b2", License: "MIT", Status: "approved"},
	}, Exceptions: []Exception{}})
	revoked := BuildIndex(&ExceptionsFile{BlanketExceptions: []BlanketException{}, Exceptions: []Exception{
		{ID: "e1", Package: "a/gpl", License: "GPL-3.0-only", Status: "revoked"},
	}})

	indexes := map[string]*ExceptionIndex{"nil": nil, "none": none, "perPackage": perPackage, "scoped": scoped, "blanket": blanket, "revoked": revoked}
	for _, project := range []string{"my-project", "other"} {
		for fromName, from := range indexes {
			for toName, to := range indexes {
				stored := byLicense(CheckWithExceptions(names, lics, from, project))
				want := byLicense(CheckWithExceptions(names, lics, to, project))
				for lic, r := range stored {
					got := Reevaluate(r, to, project)
					if r.Category == CategoryPermissive && to == blanket && from != blanket {
						// Documented gap: permissive packages were never listed.
						if len(got.NonCompliantPackages) != 0 {
							t.Fatalf("%s→%s %s: permissive license reported violations", fromName, toName, lic)
						}
						continue
					}
					if !SameOutcome(got, want[lic]) {
						t.Errorf("%s→%s (%s) %s:\n got  nc=%v ex=%v reason=%q\n want nc=%v ex=%v reason=%q",
							fromName, toName, project, lic,
							got.NonCompliantPackages, got.ExemptedPackages, got.ExemptionReason,
							want[lic].NonCompliantPackages, want[lic].ExemptedPackages, want[lic].ExemptionReason)
					}
					if got.Category != r.Category || got.PackageCount != r.PackageCount {
						t.Errorf("%s→%s %s: category/count changed", fromName, toName, lic)
					}
				}
			}
		}
	}
}

func TestReevaluateGrantAndRevoke(t *testing.T) {
	stored := Result{LicenseID: "GPL-3.0-only", Category: CategoryCopyleft, PackageCount: 2, NonCompliantPackages: []string{"x", "y"}}
	grant := BuildIndex(&ExceptionsFile{BlanketExceptions: []BlanketException{}, Exceptions: []Exception{
		{ID: "e", Package: "x", License: "GPL-3.0-only", Status: "approved"},
	}})

	granted := Reevaluate(stored, grant, "p")
	if !sameMultiset(granted.NonCompliantPackages, []string{"y"}) || !sameMultiset(granted.ExemptedPackages, []string{"x"}) {
		t.Fatalf("grant: nc=%v ex=%v", granted.NonCompliantPackages, granted.ExemptedPackages)
	}
	if SameOutcome(stored, granted) {
		t.Fatal("a granted exception must change the outcome")
	}

	revoked := Reevaluate(granted, nil, "p")
	if !sameMultiset(revoked.NonCompliantPackages, []string{"x", "y"}) || len(revoked.ExemptedPackages) != 0 {
		t.Fatalf("revoke: nc=%v ex=%v", revoked.NonCompliantPackages, revoked.ExemptedPackages)
	}
	if !SameOutcome(stored, revoked) {
		t.Fatal("revoking restores the original outcome")
	}
}

func TestSameOutcomeIgnoresOrderButNotMultiplicity(t *testing.T) {
	a := Result{NonCompliantPackages: []string{"a", "b", "a"}}
	if !SameOutcome(a, Result{NonCompliantPackages: []string{"a", "a", "b"}}) {
		t.Fatal("order must not matter")
	}
	if SameOutcome(a, Result{NonCompliantPackages: []string{"a", "b", "b"}}) {
		t.Fatal("multiplicity must matter")
	}
	if SameOutcome(Result{ExemptionReason: "x"}, Result{}) {
		t.Fatal("reason must matter")
	}
}

func byLicense(results []Result) map[string]Result {
	m := make(map[string]Result, len(results))
	for _, r := range results {
		m[r.LicenseID] = r
	}
	return m
}
