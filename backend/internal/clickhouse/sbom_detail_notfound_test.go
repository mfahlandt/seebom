package clickhouse

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// Regression guard (#358): QuerySBOMDetail reported a well-formed but unknown
// sbom_id as a generic query failure, so the gateway answered
//
//	500 {"error":"Failed to fetch SBOM detail"}
//
// and wrote an ERROR line for it. A missing resource is a 404, and routine
// client mistakes must not drown out real failures in the error log.
func TestQuerySBOMDetailUnknownIDIsNotFound(t *testing.T) {
	c := testClient(t)

	_, err := c.QuerySBOMDetail(context.Background(), uuid.New().String())
	if err == nil {
		t.Fatal("QuerySBOMDetail for a random uuid returned no error; expected ErrSBOMNotFound")
	}
	if !errors.Is(err, ErrSBOMNotFound) {
		t.Errorf("error = %v, want ErrSBOMNotFound so the gateway can map it to 404", err)
	}
}

// The dependency tree had the same flaw and a second one: an SBOM whose sboms
// row exists but whose packages are not inserted yet (mid-ingest) also came
// back as a 500. Unknown ids are now ErrSBOMNotFound; the known-but-empty case
// is an empty tree (200 with []).
func TestQuerySBOMDependenciesUnknownIDIsNotFound(t *testing.T) {
	c := testClient(t)

	_, err := c.QuerySBOMDependencies(context.Background(), uuid.New().String())
	if !errors.Is(err, ErrSBOMNotFound) {
		t.Errorf("error = %v, want ErrSBOMNotFound so the gateway can map it to 404", err)
	}
}

func TestIsNoRows(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"sentinel text", errors.New("sql: no rows in result set"), true},
		{"wrapped sentinel text", errors.New("scan: sql: no rows in result set"), false},
		{"unrelated", errors.New("connection refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNoRows(tc.err); got != tc.want {
				t.Errorf("isNoRows(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
