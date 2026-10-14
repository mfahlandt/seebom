package rulesource

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// ErrInvalid wraps a document that was fetched but rejected by the parser.
// Callers that serve the rules (the API) treat it differently from a source
// that is merely unreachable: unreachable keeps the last good rules, invalid
// is a configuration error someone has to fix.
var ErrInvalid = errors.New("invalid rules document")

// Snapshot is the state of a watched document.
type Snapshot[T any] struct {
	// Value is the parsed document, or the zero value when there is none.
	Value T
	// Digest identifies the document (see Digest). It changes exactly when
	// Value does.
	Digest string
	// Present is false when the source had no document (ErrNotFound).
	Present bool
	// Ready is true once a document — or its confirmed absence — was loaded.
	Ready bool
	// Err is the latest attempt's failure. Value and Digest stay at the last
	// good document when it is set.
	Err error
	// Source names where the document came from.
	Source string
}

// Watcher keeps the parsed form of a rules document current.
type Watcher[T any] struct {
	fetcher Fetcher
	parse   func([]byte) (T, error)

	mu   sync.RWMutex
	snap Snapshot[T]
}

// NewWatcher returns a watcher that has not loaded anything yet.
func NewWatcher[T any](f Fetcher, parse func([]byte) (T, error)) *Watcher[T] {
	return &Watcher[T]{fetcher: f, parse: parse, snap: Snapshot[T]{Source: f.Describe()}}
}

// Remote reports whether the document lives outside the pod (see Fetcher).
func (w *Watcher[T]) Remote() bool { return w.fetcher.Remote() }

// Current returns the latest snapshot.
func (w *Watcher[T]) Current() Snapshot[T] {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.snap
}

// Refresh fetches the document once. changed is true when a different
// document (or its removal) became current, including the first load.
func (w *Watcher[T]) Refresh(ctx context.Context) (changed bool, err error) {
	data, err := w.fetcher.Fetch(ctx)
	present := true
	switch {
	case errors.Is(err, errNotModified):
		w.setErr(nil)
		return false, nil
	case errors.Is(err, ErrNotFound):
		data, present = nil, false
	case err != nil:
		w.setErr(err)
		return false, err
	}

	digest := Digest(data)
	cur := w.Current()
	if cur.Ready && cur.Digest == digest {
		w.setErr(nil)
		return false, nil
	}

	var value T
	if present {
		value, err = w.parse(data)
		if err != nil {
			err = fmt.Errorf("%w: %w", ErrInvalid, err)
			// Otherwise the next poll is a 304 for the same broken document,
			// which would read as "unchanged and fine" and clear the error.
			if f, ok := w.fetcher.(versionForgetter); ok {
				f.forgetVersion()
			}
			w.setErr(err)
			return false, err
		}
	}

	w.mu.Lock()
	w.snap = Snapshot[T]{Value: value, Digest: digest, Present: present, Ready: true, Source: w.fetcher.Describe()}
	w.mu.Unlock()
	return true, nil
}

func (w *Watcher[T]) setErr(err error) {
	w.mu.Lock()
	w.snap.Err = err
	w.mu.Unlock()
}

// Run refreshes every interval until ctx ends and calls onChange (if not nil)
// after each change. interval <= 0 disables polling: the document loaded at
// startup stays current until the process restarts.
func (w *Watcher[T]) Run(ctx context.Context, interval time.Duration, onChange func(Snapshot[T])) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		changed, err := w.Refresh(ctx)
		if err != nil {
			// Logged once per distinct failure, not on every tick of an outage.
			if err.Error() != lastErr {
				log.Printf("ERROR: rules from %s: %v (keeping the last good version)", w.fetcher.Describe(), err)
				lastErr = err.Error()
			}
			continue
		}
		if lastErr != "" {
			log.Printf("Rules from %s readable again", w.fetcher.Describe())
			lastErr = ""
		}
		if changed && onChange != nil {
			onChange(w.Current())
		}
	}
}
