package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExceptionsPrimaryIsAuthoritative(t *testing.T) {
	for _, tt := range []struct {
		name, primary string
		wantError     bool
	}{
		{"empty", `{"blanketExceptions":[],"exceptions":[]}`, false},
		{"revoked", `{"blanketExceptions":[{"id":"old","license":"MPL-2.0","status":"revoked"}],"exceptions":[]}`, false},
		{"invalid JSON", `{`, true},
		{"null", `null`, true},
		{"missing arrays", `{}`, true},
		{"null array", `{"blanketExceptions":null,"exceptions":[]}`, true},
		{"wrong array type", `{"blanketExceptions":{},"exceptions":[]}`, true},
		{"unknown rule field", `{"blanketExceptions":[],"exceptions":[{"purl_prefix":"pkg:golang/example.org/lib","status":"approved"}]}`, true},
		{"multiple documents", `{"blanketExceptions":[],"exceptions":[]} {}`, true},
		{"trailing garbage", `{"blanketExceptions":[],"exceptions":[]} invalid`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			primary, fallback := filepath.Join(dir, "primary.json"), filepath.Join(dir, "fallback.json")
			for path, content := range map[string]string{
				primary:  tt.primary,
				fallback: `{"blanketExceptions":[{"id":"stale","license":"MPL-2.0","status":"approved"}],"exceptions":[]}`,
			} {
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			idx, err := LoadExceptionsWithFallback(primary, fallback)
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, wantError = %v", err, tt.wantError)
			}
			if exempt, reason := idx.IsExempt("any-package", "MPL-2.0"); exempt {
				t.Fatalf("fallback must not enable stale approval: %s", reason)
			}
		})
	}
}

func TestExceptionsUnreadablePrimaryDoesNotFallBack(t *testing.T) {
	dir := t.TempDir()
	fallback := filepath.Join(dir, "fallback.json")
	if err := os.WriteFile(fallback, []byte(`{"blanketExceptions":[],"exceptions":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Reading a directory as a file fails even when the tests run as root.
	if _, err := LoadExceptionsWithFallback(dir, fallback); err == nil {
		t.Fatal("expected primary read error, not fallback success")
	}
}

func TestExceptionProjectAndPackageBoundaries(t *testing.T) {
	for _, lic := range []string{"MPL-2.0", ""} {
		t.Run("license="+lic, func(t *testing.T) {
			idx := BuildIndex(&ExceptionsFile{Exceptions: []Exception{
				{ID: "alpha", Package: "team/library", License: lic, Project: "alpha", Status: "approved"},
				{ID: "beta", Package: "team/library", License: lic, Project: "beta", Status: "approved"},
				{ID: "revoked", Package: "team/library", License: lic, Project: "gamma", Status: "revoked"},
			}})
			for _, tt := range []struct {
				pkg, project, reason string
			}{
				{"team/library", "alpha", "alpha"},
				{"team/library", "beta", "beta"},
				{"example.org/team/library", "alpha", "alpha"},
				{"example.org/team/library", "beta", "beta"},
				{"team/library", "gamma", ""},
				{"team/library", "", ""},
				{"team/library", "Alpha", ""},
				{"example.org/team/library-evil", "alpha", ""},
				{"example.org/notteam/library", "alpha", ""},
				{"example.org/team/library/submodule", "alpha", ""},
				{"example.org/TEAM/library", "alpha", ""},
				{"", "alpha", ""},
			} {
				exempt, reason := idx.IsExempt(tt.pkg, "MPL-2.0", tt.project)
				if exempt != (tt.reason != "") || (exempt && !strings.Contains(reason, "Exception: "+tt.reason+" ")) {
					t.Errorf("IsExempt(%q, project=%q) = %v, %q; want %q", tt.pkg, tt.project, exempt, reason, tt.reason)
				}
			}
		})
	}
}

func TestExceptionGlobalProjectDoesNotMeanBlanket(t *testing.T) {
	for _, scope := range []string{"", "*", "All Projects", "All CNCF Projects"} {
		idx := BuildIndex(&ExceptionsFile{Exceptions: []Exception{
			{ID: "package-only", Package: "library", License: "MPL-2.0", Project: scope, Status: "approved"},
		}})
		if exempt, _ := idx.IsExempt("unrelated", "MPL-2.0", scope); exempt {
			t.Errorf("scope %q promoted a package exception to blanket", scope)
		}
		got, _ := idx.IsExempt("library", "MPL-2.0", "my-project")
		if got != (scope != "All CNCF Projects") {
			t.Errorf("scope %q: exempt=%v", scope, got)
		}
	}
}

func TestCheckWithExceptionsProjectContext(t *testing.T) {
	idx := BuildIndex(&ExceptionsFile{Exceptions: []Exception{
		{ID: "only-alpha", Package: "library", License: "MPL-2.0", Project: "alpha", Status: "approved"},
	}})
	for _, project := range []string{"alpha", "beta", ""} {
		results := CheckWithExceptions([]string{"library"}, []string{"MPL-2.0"}, idx, project)
		if len(results) != 1 {
			t.Fatalf("expected one result, got %v", results)
		}
		if (len(results[0].ExemptedPackages) == 1) != (project == "alpha") ||
			(len(results[0].NonCompliantPackages) == 1) != (project != "alpha") {
			t.Errorf("project %q: unexpected result %+v", project, results[0])
		}
	}
}

func TestExceptionDefaultsAndExampleHaveNoApprovals(t *testing.T) {
	for _, path := range []string{
		"../../../sboms/license-exceptions.json",
		"../../../examples/license-exceptions/license-exceptions.example.json",
	} {
		idx, err := LoadExceptions(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(idx.blanketLicenses) != 0 || len(idx.packageLicense) != 0 || len(idx.packageAny) != 0 {
			t.Errorf("%s contains active approvals", path)
		}
	}
}

func TestExceptionMatchOrderIsDeterministic(t *testing.T) {
	idx := BuildIndex(&ExceptionsFile{
		BlanketExceptions: []BlanketException{
			{ID: "short", License: "LicenseRef", Status: "approved"},
			{ID: "long", License: "LicenseRef-team", Status: "approved"},
		},
		Exceptions: []Exception{
			{ID: "first", Package: "team/lib", License: "MPL-2.0", Status: "approved"},
			{ID: "second", Package: "team/lib", License: "MPL-2.0", Status: "approved"},
			{ID: "exact", Package: "example.org/team/lib", License: "MPL-2.0", Status: "approved"},
		},
	})
	for i := 0; i < 50; i++ {
		for _, tt := range []struct{ pkg, lic, reason string }{
			{"pkg", "LicenseRef-team-special", "Blanket exception: long "},
			{"team/lib", "MPL-2.0", "Exception: first "},
			{"other.org/team/lib", "MPL-2.0", "Exception: first "},
			{"example.org/team/lib", "MPL-2.0", "Exception: exact "},
		} {
			exempt, reason := idx.IsExempt(tt.pkg, tt.lic)
			if !exempt || !strings.HasPrefix(reason, tt.reason) {
				t.Fatalf("IsExempt(%q, %q) = %v, %q; want %q", tt.pkg, tt.lic, exempt, reason, tt.reason)
			}
		}
	}
}
