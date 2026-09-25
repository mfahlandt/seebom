package license

import (
	"os"
	"path/filepath"
	"testing"
)

// withMode runs fn with the active policy switched to mode and restores the
// previous policy afterwards. Categorize reads the global policy, so tests
// must serialise around it.
func withMode(t *testing.T, mode ExpressionMode, fn func()) {
	t.Helper()
	policyMu.RLock()
	previous := activePolicy
	policyMu.RUnlock()
	t.Cleanup(func() {
		policyMu.Lock()
		activePolicy = previous
		policyMu.Unlock()
	})
	SetExpressionMode(mode)
	fn()
}

func TestParseExpressionMode(t *testing.T) {
	cases := []struct {
		in      string
		want    ExpressionMode
		wantErr bool
	}{
		{"", DefaultExpressionMode, false},
		{"strict", ExpressionModeStrict, false},
		{"STRICT", ExpressionModeStrict, false},
		{" permissive-wins ", ExpressionModePermissiveWins, false},
		{"off", ExpressionModeOff, false},
		{"lenient", "", true},
	}
	for _, tc := range cases {
		got, err := ParseExpressionMode(tc.in)
		if tc.wantErr != (err != nil) {
			t.Errorf("ParseExpressionMode(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseExpressionMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

type exprCase struct {
	expr                            string
	strict, permissiveWins, offMode Category
}

func TestCategorize_Expressions(t *testing.T) {
	// One table, three columns: what every mode must answer. This is the
	// contract the issue's acceptance criteria spell out.
	cases := []exprCase{
		// All-permissive conjunction: the motivating case. Only "off" flags it.
		{"Apache-2.0 AND MIT", CategoryPermissive, CategoryPermissive, CategoryUnknown},
		{"Apache-2.0 AND BSD-3-Clause AND MIT", CategoryPermissive, CategoryPermissive, CategoryUnknown},
		// Lower-case operators occur in the wild.
		{"Apache-2.0 and MIT", CategoryPermissive, CategoryPermissive, CategoryUnknown},
		// Comma is read as AND.
		{"MIT, BSD-3-Clause", CategoryPermissive, CategoryPermissive, CategoryUnknown},

		// Conjunction with copyleft: strict keeps the obligation visible.
		{"MIT AND GPL-3.0-only", CategoryCopyleft, CategoryPermissive, CategoryUnknown},
		{"GPL-2.0-only AND GPL-2.0-or-later", CategoryCopyleft, CategoryCopyleft, CategoryUnknown},

		// Conjunction with an unclassified operand.
		{"MIT AND SomeWeirdLicense", CategoryUnknown, CategoryPermissive, CategoryUnknown},
		{"GPL-3.0-only AND SomeWeirdLicense", CategoryCopyleft, CategoryUnknown, CategoryUnknown},

		// Disjunction: the consumer chooses, so permissive wins in every mode
		// that evaluates at all.
		{"MIT OR GPL-3.0-only", CategoryPermissive, CategoryPermissive, CategoryUnknown},
		{"GPL-2.0-only OR GPL-3.0-only", CategoryCopyleft, CategoryCopyleft, CategoryUnknown},
		{"GPL-2.0-only OR SomeWeirdLicense", CategoryUnknown, CategoryUnknown, CategoryUnknown},

		// WITH: the exception does not change the base license's class.
		{"GPL-2.0-only WITH Classpath-exception-2.0", CategoryCopyleft, CategoryCopyleft, CategoryUnknown},
		{"Apache-2.0 WITH LLVM-exception", CategoryPermissive, CategoryPermissive, CategoryUnknown},

		// Precedence and grouping: AND binds tighter than OR.
		{"MIT OR (GPL-3.0-only AND SomeWeirdLicense)", CategoryPermissive, CategoryPermissive, CategoryUnknown},
		{"(MIT OR GPL-3.0-only) AND GPL-2.0-only", CategoryCopyleft, CategoryPermissive, CategoryUnknown},
		{"MIT OR GPL-3.0-only AND GPL-2.0-only", CategoryPermissive, CategoryPermissive, CategoryUnknown},

		// Deprecated "+" spelling.
		{"GPL-2.0+", CategoryCopyleft, CategoryCopyleft, CategoryUnknown},
		{"LGPL-2.1+ OR MIT", CategoryPermissive, CategoryPermissive, CategoryUnknown},

		// Malformed: never silently accepted.
		{"MIT AND", CategoryUnknown, CategoryUnknown, CategoryUnknown},
		{"(MIT OR GPL-3.0-only", CategoryUnknown, CategoryUnknown, CategoryUnknown},
		{"AND MIT", CategoryUnknown, CategoryUnknown, CategoryUnknown},

		// Bare identifiers are untouched by the mode.
		{"MIT", CategoryPermissive, CategoryPermissive, CategoryPermissive},
		{"GPL-3.0-only", CategoryCopyleft, CategoryCopyleft, CategoryCopyleft},
		{"MPL-2.0-no-copyleft-exception", CategoryCopyleft, CategoryCopyleft, CategoryCopyleft},
		{"NOASSERTION", CategoryUnknown, CategoryUnknown, CategoryUnknown},
	}

	modes := []struct {
		mode ExpressionMode
		pick func(c exprCase) Category
	}{
		{ExpressionModeStrict, func(c exprCase) Category { return c.strict }},
		{ExpressionModePermissiveWins, func(c exprCase) Category { return c.permissiveWins }},
		{ExpressionModeOff, func(c exprCase) Category { return c.offMode }},
	}

	for _, m := range modes {
		t.Run(string(m.mode), func(t *testing.T) {
			withMode(t, m.mode, func() {
				for _, c := range cases {
					if got, want := Categorize(c.expr), m.pick(c); got != want {
						t.Errorf("[%s] Categorize(%q) = %q, want %q", m.mode, c.expr, got, want)
					}
				}
			})
		})
	}
}

func TestCategorize_VerbatimPolicyEntryWins(t *testing.T) {
	// A policy that lists a whole clause verbatim is honoured before any
	// operand-wise evaluation, in every mode.
	policyMu.RLock()
	previous := activePolicy
	policyMu.RUnlock()
	t.Cleanup(func() {
		policyMu.Lock()
		activePolicy = previous
		policyMu.Unlock()
	})

	for _, mode := range []ExpressionMode{ExpressionModeStrict, ExpressionModePermissiveWins, ExpressionModeOff} {
		policyMu.Lock()
		activePolicy = buildPolicy(
			[]string{"MIT", "GPL-2.0-only WITH Classpath-exception-2.0"},
			[]string{"GPL-2.0-only"},
			mode,
		)
		policyMu.Unlock()
		if got := Categorize("GPL-2.0-only WITH Classpath-exception-2.0"); got != CategoryPermissive {
			t.Errorf("[%s] verbatim WITH entry: got %q, want permissive", mode, got)
		}
	}
}

func TestCheck_ExpressionKeepsFullStringAsKey(t *testing.T) {
	// The aggregation key stays the expression as written, so the UI shows
	// what the SBOM declared; only the category changes.
	withMode(t, ExpressionModeStrict, func() {
		results := Check([]string{"a", "b"}, []string{"Apache-2.0 AND MIT", "MIT AND GPL-3.0-only"})
		byLicense := map[string]Result{}
		for _, r := range results {
			byLicense[r.LicenseID] = r
		}
		if r := byLicense["Apache-2.0 AND MIT"]; r.Category != CategoryPermissive || len(r.NonCompliantPackages) != 0 {
			t.Errorf("Apache-2.0 AND MIT: got %+v", r)
		}
		if r := byLicense["MIT AND GPL-3.0-only"]; r.Category != CategoryCopyleft || len(r.NonCompliantPackages) != 1 {
			t.Errorf("MIT AND GPL-3.0-only: got %+v", r)
		}
	})
}

func TestLoadPolicy_ExpressionMode(t *testing.T) {
	policyMu.RLock()
	previous := activePolicy
	policyMu.RUnlock()
	t.Cleanup(func() {
		policyMu.Lock()
		activePolicy = previous
		policyMu.Unlock()
	})

	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Unset → default.
	if _, _, err := LoadPolicy(write("a.json", `{"permissive":["MIT"],"copyleft":[]}`)); err != nil {
		t.Fatal(err)
	}
	if got := GetExpressionMode(); got != DefaultExpressionMode {
		t.Errorf("default mode = %q, want %q", got, DefaultExpressionMode)
	}

	// Set in file.
	if _, _, err := LoadPolicy(write("b.json", `{"permissive":["MIT"],"copyleft":[],"expressionMode":"permissive-wins"}`)); err != nil {
		t.Fatal(err)
	}
	if got := GetExpressionMode(); got != ExpressionModePermissiveWins {
		t.Errorf("file mode = %q, want permissive-wins", got)
	}
	if got := GetPolicy().ExpressionMode; got != "permissive-wins" {
		t.Errorf("GetPolicy().ExpressionMode = %q", got)
	}

	// Env-style override applied after loading.
	SetExpressionMode(ExpressionModeOff)
	if got := GetExpressionMode(); got != ExpressionModeOff {
		t.Errorf("override mode = %q, want off", got)
	}

	// Invalid value is a load error, not a silent default.
	if _, _, err := LoadPolicy(write("c.json", `{"permissive":[],"copyleft":[],"expressionMode":"bogus"}`)); err == nil {
		t.Error("expected error for invalid expressionMode")
	}
}

func TestSplitLicenses_Nested(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"MIT OR (GPL-2.0-only AND BSD-3-Clause)", []string{"MIT", "GPL-2.0-only", "BSD-3-Clause"}},
		{"GPL-2.0-only WITH Classpath-exception-2.0 OR MIT", []string{"GPL-2.0-only WITH Classpath-exception-2.0", "MIT"}},
		{"MIT AND", []string{"MIT AND"}}, // malformed: kept verbatim
	}
	for _, tc := range cases {
		got := splitLicenses(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitLicenses(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitLicenses(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}
