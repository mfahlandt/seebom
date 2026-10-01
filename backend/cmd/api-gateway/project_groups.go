package main

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/projectgroup"
)

// parentResolver resolves every project's parent (internal/projectgroup) and
// caches the result briefly.
//
// Resolution reads one row of signals per project and runs the rules in Go.
// That is cheap, but the project list, the grouped list and every project
// page would otherwise each repeat it per request. The cache is invalidated
// after ttl, or as soon as the mapping file changes on disk, so an edited
// ConfigMap shows up on the next request rather than after a restart.
//
// An invalid mapping file is logged and ignored: grouping falls back to the
// explicit and automatic rules instead of failing the project listing.
type parentResolver struct {
	signals   func(ctx context.Context) ([]projectgroup.Signals, error)
	rulesPath string
	ttl       time.Duration
	now       func() time.Time

	mu          sync.Mutex
	cached      map[string]projectgroup.Assignment
	cachedAt    time.Time
	rulesMod    time.Time
	rulesSize   int64
	loggedError string
}

func newParentResolver(signals func(ctx context.Context) ([]projectgroup.Signals, error), rulesPath string) *parentResolver {
	return &parentResolver{signals: signals, rulesPath: rulesPath, ttl: 30 * time.Second, now: time.Now}
}

// Assignments returns the resolved parent of every project that has one.
func (p *parentResolver) Assignments(ctx context.Context) (map[string]projectgroup.Assignment, error) {
	mod, size := p.rulesStat()

	p.mu.Lock()
	if p.cached != nil && p.now().Sub(p.cachedAt) < p.ttl && mod.Equal(p.rulesMod) && size == p.rulesSize {
		out := p.cached
		p.mu.Unlock()
		return out, nil
	}
	p.mu.Unlock()

	signals, err := p.signals(ctx)
	if err != nil {
		return nil, err
	}
	rules := p.loadRules()
	assignments := projectgroup.Resolve(signals, rules)

	p.mu.Lock()
	p.cached, p.cachedAt, p.rulesMod, p.rulesSize = assignments, p.now(), mod, size
	p.mu.Unlock()
	return assignments, nil
}

func (p *parentResolver) rulesStat() (time.Time, int64) {
	if p.rulesPath == "" {
		return time.Time{}, -1
	}
	fi, err := os.Stat(p.rulesPath)
	if err != nil {
		return time.Time{}, -1
	}
	return fi.ModTime(), fi.Size()
}

func (p *parentResolver) loadRules() *projectgroup.Rules {
	rules, err := projectgroup.LoadRules(p.rulesPath)
	if err != nil {
		p.mu.Lock()
		if p.loggedError != err.Error() {
			log.Printf("ERROR: %v — project grouping ignores the mapping file until it is fixed", err)
			p.loggedError = err.Error()
		}
		p.mu.Unlock()
		return nil
	}
	p.mu.Lock()
	p.loggedError = ""
	p.mu.Unlock()
	return rules
}
