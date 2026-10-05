package clickhouse

import (
	"fmt"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
)

// scopeFields turns a stored depth into the (scope, depth) pair the DTOs
// carry: the label is always set, the numeric depth only when known.
func scopeFields(depth uint16) (string, *uint16) {
	if depth == depgraph.Unknown {
		return depgraph.ScopeUnknown, nil
	}
	d := depth
	return depgraph.Scope(depth), &d
}

// depthPredicate returns a SQL predicate on column col for a scope filter,
// or "" when scope is empty. scope must have passed depgraph.IsValidScope;
// the mapping is a fixed whitelist, nothing from the request is interpolated.
func depthPredicate(scope, col string) string {
	switch scope {
	case depgraph.ScopeRoot:
		return fmt.Sprintf("%s = 0", col)
	case depgraph.ScopeDirect:
		return fmt.Sprintf("%s = 1", col)
	case depgraph.ScopeTransitive:
		return fmt.Sprintf("%s BETWEEN 2 AND %d", col, depgraph.Unknown-1)
	case depgraph.ScopeUnknown:
		return fmt.Sprintf("%s = %d", col, depgraph.Unknown)
	}
	return ""
}

// packageScopes builds the name → scope map for a license breakdown from the
// parallel package arrays, keeping the nearest occurrence of a name.
func packageScopes(names []string, depths []uint16) map[string]string {
	if len(depths) == 0 {
		return nil
	}
	best := make(map[string]uint16, len(names))
	for i, n := range names {
		if n == "" {
			continue
		}
		d := depgraph.DepthOf(depths, i)
		if cur, ok := best[n]; !ok || d < cur {
			best[n] = d
		}
	}
	out := make(map[string]string, len(best))
	for n, d := range best {
		if d != depgraph.Unknown {
			out[n] = depgraph.Scope(d)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
