package main

import "testing"

func TestParseScope(t *testing.T) {
	cases := []struct {
		raw   string
		scope string
		ok    bool
	}{
		{"", "", true},
		{"direct", "direct", true},
		{"transitive", "transitive", true},
		{"root", "root", true},
		{"unknown", "unknown", true},
		{"DIRECT", "", false},
		{"indirect", "", false},
		{"1", "", false},
	}
	for _, c := range cases {
		scope, ok := parseScope(c.raw)
		if scope != c.scope || ok != c.ok {
			t.Errorf("parseScope(%q) = (%q, %v), want (%q, %v)", c.raw, scope, ok, c.scope, c.ok)
		}
	}
}
