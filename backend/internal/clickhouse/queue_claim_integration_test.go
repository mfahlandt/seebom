package clickhouse

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestOwnClaimedJobIDsIgnoresSupersededClaim proves a worker does not process a
// job when another worker's newer claim row is the latest queue state.
// Skipped unless CLICKHOUSE_HOST is set.
func TestOwnClaimedJobIDsIgnoresSupersededClaim(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jobID := uuid.New()
	now := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	insert := func(createdAt time.Time, worker string) {
		t.Helper()
		if err := c.Conn.Exec(ctx, `INSERT INTO ingestion_queue (`+queueColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			createdAt, jobID, "integration-test/claim.spdx.json", uuid.NewString(),
			"processing", "sbom", worker, &createdAt, (*time.Time)(nil), "",
			"", "", "", "", "", "", []string{}, "", time.Time{}); err != nil {
			t.Fatalf("insert claim for %s: %v", worker, err)
		}
	}
	insert(now, "worker-a")
	insert(now.Add(time.Millisecond), "worker-b")

	jobIDs := []uuid.UUID{jobID}
	for _, tc := range []struct {
		worker string
		want   bool
	}{{"worker-a", false}, {"worker-b", true}} {
		owned, err := c.ownClaimedJobIDs(ctx, jobIDs, tc.worker)
		if err != nil {
			t.Fatalf("ownClaimedJobIDs(%q): %v", tc.worker, err)
		}
		_, got := owned[jobID]
		if got != tc.want {
			t.Errorf("worker %q owns job = %v, want %v", tc.worker, got, tc.want)
		}
	}
}
