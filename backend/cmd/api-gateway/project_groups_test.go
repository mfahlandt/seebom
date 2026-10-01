package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/projectgroup"
)

func fakeSignals(calls *int) func(context.Context) ([]projectgroup.Signals, error) {
	return func(context.Context) ([]projectgroup.Signals, error) {
		*calls++
		return []projectgroup.Signals{
			{Project: "argo", SourceRepo: "https://github.com/argoproj/argo-cd"},
			{Project: "argo-cd/argo-workflows", SourceRepo: "https://github.com/argoproj/argo-workflows"},
			{Project: "agones", SourceRepo: "https://github.com/agones-dev/agones"},
		}, nil
	}
}

func TestParentResolverCachesWithinTTL(t *testing.T) {
	calls := 0
	clock := time.Unix(1000, 0)
	p := newParentResolver(fakeSignals(&calls), "")
	p.now = func() time.Time { return clock }

	a, err := p.Assignments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a["argo-cd/argo-workflows"].Parent != "argo" {
		t.Errorf("assignment = %+v, want argo", a["argo-cd/argo-workflows"])
	}
	if _, err := p.Assignments(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("signals queried %d times within the TTL, want 1", calls)
	}

	clock = clock.Add(31 * time.Second)
	if _, err := p.Assignments(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("signals queried %d times after the TTL, want 2", calls)
	}
}

// An edited mapping file applies on the next request, not after the TTL.
func TestParentResolverReloadsChangedRules(t *testing.T) {
	calls := 0
	path := filepath.Join(t.TempDir(), "project-groups.json")
	p := newParentResolver(fakeSignals(&calls), path)

	if a, _ := p.Assignments(context.Background()); a["agones"].Parent != "" {
		t.Fatalf("no rules yet, agones has no parent: %+v", a["agones"])
	}

	rules := `{"groups": [{"parent": "Games", "match": {"projects": ["agones"]}}]}`
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := p.Assignments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a["agones"].Parent != "Games" || a["agones"].Source != projectgroup.SourceConfig {
		t.Errorf("new rule not applied: %+v", a["agones"])
	}
	if calls != 2 {
		t.Errorf("signals queried %d times, want 2 (the file change invalidates the cache)", calls)
	}
}

// A broken mapping file must not take the project listing down: the
// automatic grouping keeps working.
func TestParentResolverIgnoresInvalidRules(t *testing.T) {
	calls := 0
	path := filepath.Join(t.TempDir(), "project-groups.json")
	if err := os.WriteFile(path, []byte(`{"groups": [{}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newParentResolver(fakeSignals(&calls), path)
	a, err := p.Assignments(context.Background())
	if err != nil {
		t.Fatalf("an invalid mapping file must not fail resolution: %v", err)
	}
	if a["argo-cd/argo-workflows"].Parent != "argo" {
		t.Errorf("automatic grouping lost: %+v", a)
	}
}

func TestParentResolverPropagatesQueryErrors(t *testing.T) {
	p := newParentResolver(func(context.Context) ([]projectgroup.Signals, error) {
		return nil, errors.New("clickhouse down")
	}, "")
	if _, err := p.Assignments(context.Background()); err == nil {
		t.Error("a failed signals query must surface as an error")
	}
}
