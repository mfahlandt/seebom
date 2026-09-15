package main

import (
	"reflect"
	"testing"
)

func TestExcludeIndices(t *testing.T) {
	names := []string{"root", "a", "b", "c"}
	lics := []string{"NOASSERTION", "MIT", "Apache-2.0", "GPL-3.0"}

	t.Run("no skip returns inputs unchanged", func(t *testing.T) {
		n, l := excludeIndices(names, lics, nil)
		if !reflect.DeepEqual(n, names) || !reflect.DeepEqual(l, lics) {
			t.Errorf("expected unchanged slices, got %v / %v", n, l)
		}
	})

	t.Run("skips root at index 0", func(t *testing.T) {
		n, l := excludeIndices(names, lics, []uint32{0})
		if !reflect.DeepEqual(n, []string{"a", "b", "c"}) {
			t.Errorf("names: got %v", n)
		}
		if !reflect.DeepEqual(l, []string{"MIT", "Apache-2.0", "GPL-3.0"}) {
			t.Errorf("licenses: got %v", l)
		}
		// Inputs must not be mutated.
		if names[0] != "root" || len(names) != 4 {
			t.Errorf("input slice was mutated: %v", names)
		}
	})

	t.Run("skips multiple and out-of-range indices", func(t *testing.T) {
		n, l := excludeIndices(names, lics, []uint32{1, 3, 99})
		if !reflect.DeepEqual(n, []string{"root", "b"}) || !reflect.DeepEqual(l, []string{"NOASSERTION", "Apache-2.0"}) {
			t.Errorf("got %v / %v", n, l)
		}
	})

	t.Run("pads missing licenses", func(t *testing.T) {
		n, l := excludeIndices([]string{"x", "y"}, []string{"MIT"}, []uint32{5})
		if len(n) != 2 || len(l) != 2 || l[1] != "" {
			t.Errorf("got %v / %v", n, l)
		}
	})
}
