package clickhouse

import (
	"reflect"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
)

func TestScopeFields(t *testing.T) {
	scope, depth := scopeFields(depgraph.Unknown)
	if scope != depgraph.ScopeUnknown || depth != nil {
		t.Fatalf("unknown: got (%q, %v)", scope, depth)
	}
	scope, depth = scopeFields(1)
	if scope != depgraph.ScopeDirect || depth == nil || *depth != 1 {
		t.Fatalf("direct: got (%q, %v)", scope, depth)
	}
	scope, depth = scopeFields(0)
	if scope != depgraph.ScopeRoot || depth == nil || *depth != 0 {
		t.Fatalf("root: got (%q, %v) - depth 0 must not be dropped", scope, depth)
	}
}

func TestDepthPredicate(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		depgraph.ScopeRoot:       "d = 0",
		depgraph.ScopeDirect:     "d = 1",
		depgraph.ScopeTransitive: "d BETWEEN 2 AND 65534",
		depgraph.ScopeUnknown:    "d = 65535",
		"'; DROP TABLE x; --":    "",
	}
	for scope, want := range cases {
		if got := depthPredicate(scope, "d"); got != want {
			t.Errorf("depthPredicate(%q) = %q, want %q", scope, got, want)
		}
	}
}

func TestPackageScopes(t *testing.T) {
	names := []string{"a", "b", "a", "", "c"}
	depths := []uint16{3, 1, 2, 0, depgraph.Unknown}
	got := packageScopes(names, depths)
	want := map[string]string{"a": depgraph.ScopeTransitive, "b": depgraph.ScopeDirect}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if packageScopes(names, nil) != nil {
		t.Fatal("no depths recorded must yield nil, not an empty map")
	}
}

func TestPickScopes(t *testing.T) {
	all := map[string]string{"a": "direct", "b": "transitive"}
	got := pickScopes(all, []string{"a", "zzz"}, []string{"b"})
	want := map[string]string{"a": "direct", "b": "transitive"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if pickScopes(all, []string{"nope"}) != nil {
		t.Fatal("no matches must yield nil so omitempty drops the field")
	}
	if pickScopes(nil, []string{"a"}) != nil {
		t.Fatal("nil source map must yield nil")
	}
}
