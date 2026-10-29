package clickhouse

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/claimlock"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestConcurrentClaimJobs returns each pending job to only one caller.
// Skipped unless CLICKHOUSE_HOST is set.
func TestConcurrentClaimJobs(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	job := models.IngestionJob{
		CreatedAt:  time.Now(),
		JobID:      uuid.New(),
		SourceFile: "integration-test/concurrent-claim-" + uuid.NewString() + ".spdx.json",
		SHA256Hash: uuid.NewString(),
		JobType:    "sbom",
	}
	if err := c.EnqueueJobs(ctx, []models.IngestionJob{job}); err != nil {
		t.Fatalf("EnqueueJobs: %v", err)
	}

	locker := claimlock.Local()
	start := make(chan struct{})
	type result struct {
		jobs []models.IngestionJob
		err  error
	}
	results := make(chan result, 2)
	for _, worker := range []string{"claim-a", "claim-b"} {
		go func(worker string) {
			<-start
			jobs, err := c.ClaimJobs(ctx, worker, 10000, locker)
			results <- result{jobs: jobs, err: err}
		}(worker)
	}
	close(start)

	claims := 0
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatalf("ClaimJobs: %v", got.err)
		}
		for _, claimed := range got.jobs {
			if claimed.JobID == job.JobID {
				claims++
			}
		}
	}
	if claims != 1 {
		t.Fatalf("concurrent ClaimJobs returned target job %d times, want once", claims)
	}
}

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
