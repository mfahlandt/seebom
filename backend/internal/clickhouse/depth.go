package clickhouse

import (
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
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

// scopeExpr is the SQL form of depgraph.Scope for a depth column.
func scopeExpr(col string) string {
	return fmt.Sprintf("multiIf(%[1]s = %[2]d, '%[3]s', %[1]s = 0, '%[4]s', %[1]s = 1, '%[5]s', '%[6]s')",
		col, depgraph.Unknown, depgraph.ScopeUnknown, depgraph.ScopeRoot, depgraph.ScopeDirect, depgraph.ScopeTransitive)
}

// scanSeverityScopes consumes (severity, scope, count) rows into the flat
// severity fields of a detail DTO plus its per-scope breakdown.
func scanSeverityScopes(rows driver.Rows, total, critical, high, medium, low *uint64) (map[string]dto.SeverityCounts, error) {
	defer rows.Close()
	all := dto.SeverityCounts{}
	byScope := map[string]dto.SeverityCounts{}
	for rows.Next() {
		var severity, scope string
		var cnt uint64
		if err := rows.Scan(&severity, &scope, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan severity row: %w", err)
		}
		all.Add(severity, cnt)
		sc := byScope[scope]
		sc.Add(severity, cnt)
		byScope[scope] = sc
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	*total, *critical, *high, *medium, *low = all.Total, all.Critical, all.High, all.Medium, all.Low
	return byScope, nil
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
