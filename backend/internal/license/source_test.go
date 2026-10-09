package license

import "testing"

func TestNegativeCacheValueRoundTrip(t *testing.T) {
	for _, reason := range []string{ReasonNotPublished, ReasonNoLicenseUpstream} {
		v := NegativeCacheValue(reason)
		if v == "" || v[0] != '!' {
			t.Fatalf("NegativeCacheValue(%q) = %q, want a !-prefixed marker", reason, v)
		}
		if lic, got := SplitCacheValue(v); lic != "" || got != reason {
			t.Errorf("SplitCacheValue(%q) = (%q, %q), want (\"\", %q)", v, lic, got, reason)
		}
	}
	if v := NegativeCacheValue(""); v != "" {
		t.Errorf("NegativeCacheValue(\"\") = %q, want legacy empty negative", v)
	}
}

func TestSplitCacheValue(t *testing.T) {
	tests := []struct{ in, lic, reason string }{
		{"MIT", "MIT", ""},
		{"MIT OR Apache-2.0", "MIT OR Apache-2.0", ""},
		{"", "", ""}, // legacy negative without a reason
		{"!not-published", "", "not-published"},
	}
	for _, tt := range tests {
		if lic, reason := SplitCacheValue(tt.in); lic != tt.lic || reason != tt.reason {
			t.Errorf("SplitCacheValue(%q) = (%q, %q), want (%q, %q)", tt.in, lic, reason, tt.lic, tt.reason)
		}
	}
}

func TestWithModifier(t *testing.T) {
	tests := []struct{ source, modifier, want string }{
		{"depsdev", ModifierLatest, "depsdev+latest"},
		{"depsdev+latest", ModifierNormalized, "depsdev+latest+normalized"},
		{"depsdev+latest", ModifierLatest, "depsdev+latest"}, // idempotent
		{"", ModifierNormalized, ""},                         // no source, nothing to modify
		{"npm", "", "npm"},
		{"latest", ModifierLatest, "latest+latest"}, // only modifiers count, not the origin
	}
	for _, tt := range tests {
		if got := WithModifier(tt.source, tt.modifier); got != tt.want {
			t.Errorf("WithModifier(%q, %q) = %q, want %q", tt.source, tt.modifier, got, tt.want)
		}
	}
}

func TestIsUnresolvedReason(t *testing.T) {
	for _, r := range UnresolvedReasons {
		if !IsUnresolvedReason(r) {
			t.Errorf("IsUnresolvedReason(%q) = false", r)
		}
	}
	for _, s := range []string{SourceDeclared, SourceGitHub, "npm", "depsdev+latest", "", "unrecorded"} {
		if IsUnresolvedReason(s) {
			t.Errorf("IsUnresolvedReason(%q) = true, want false", s)
		}
	}
}

func TestChoose(t *testing.T) {
	tests := []struct {
		name, concluded, declared string
		wantLic, wantSource       string
	}{
		{"differing conclusion wins", "Apache-2.0", "AFL-1.1 AND Apache-2.0 AND MIT", "Apache-2.0", SourceConcluded},
		{"agreeing values are declared", "MIT", "MIT", "MIT", ""},
		{"declared only", "NOASSERTION", "MIT", "MIT", ""},
		{"declared only, concluded empty", "", "MIT", "MIT", ""},
		{"conclusion as fallback", "MIT", "NOASSERTION", "MIT", ""},
		{"NONE never beats a real value", "NONE", "MIT", "MIT", ""},
		{"NOASSERTION never beats a real value", "NOASSERTION", "GPL-3.0-only", "GPL-3.0-only", ""},
		{"both unusable keeps declared", "NOASSERTION", "NOASSERTION", "NOASSERTION", ""},
		{"both empty", "", "", "", ""},
	}
	for _, tt := range tests {
		lic, src := Choose(tt.concluded, tt.declared)
		if lic != tt.wantLic || src != tt.wantSource {
			t.Errorf("%s: Choose(%q, %q) = (%q, %q), want (%q, %q)", tt.name, tt.concluded, tt.declared, lic, src, tt.wantLic, tt.wantSource)
		}
	}
}
