package docstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FSStore persists originals below a root directory (typically a PVC mounted
// into both the parsing-worker and the api-gateway).
type FSStore struct {
	root string
}

// NewFSStore returns a Store rooted at dir, creating it if necessary.
func NewFSStore(dir string) (*FSStore, error) {
	if dir == "" {
		return nil, errors.New("docstore: filesystem root is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("docstore: resolve %q: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("docstore: create %q: %w", abs, err)
	}
	return &FSStore{root: abs}, nil
}

// Backend implements Store.
func (f *FSStore) Backend() string { return BackendFS }

// CheckWritable verifies that the process can create files below the root.
// Writers (the parsing worker) call this at startup so a volume that is
// mounted read-only or owned by another uid (typical for a fresh PVC or
// Docker volume without fsGroup/chown) fails fast with an actionable error
// instead of failing every single ingestion job.
func (f *FSStore) CheckWritable() error {
	probe, err := os.CreateTemp(f.root, ".write-probe-*")
	if err != nil {
		return fmt.Errorf("docstore: %s is not writable by uid %d (%w) — mount the volume read-write and set fsGroup / chown it to the container user", f.root, os.Getuid(), err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// Put implements Store. Writes are atomic (temp file + rename) so a crashed
// worker never leaves a truncated original behind.
func (f *FSStore) Put(ctx context.Context, key string, data []byte) (string, error) {
	rel, err := f.safeRel(key)
	if err != nil {
		return "", err
	}
	abs := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", fmt.Errorf("docstore: mkdir for %s: %w", rel, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(abs), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("docstore: temp file for %s: %w", rel, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", fmt.Errorf("docstore: write %s: %w", rel, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", fmt.Errorf("docstore: close %s: %w", rel, err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		cleanup()
		return "", fmt.Errorf("docstore: rename %s: %w", rel, err)
	}
	return "fs://" + filepath.ToSlash(rel), nil
}

// Get implements Store.
func (f *FSStore) Get(ctx context.Context, ref string) (io.ReadCloser, error) {
	rest, err := splitRef(ref, "fs")
	if err != nil {
		return nil, err
	}
	rel, err := f.safeRel(rest)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(f.root, rel))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, ref)
		}
		return nil, fmt.Errorf("docstore: open %s: %w", ref, err)
	}
	return file, nil
}

// safeRel normalises key into a relative path that cannot escape the root.
func (f *FSStore) safeRel(key string) (string, error) {
	key = strings.ReplaceAll(key, "\\", "/")
	rel := filepath.Clean("/" + key) // anchor, then Clean collapses any ".."
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	if rel == "" || rel == "." {
		return "", fmt.Errorf("docstore: invalid key %q", key)
	}
	return rel, nil
}
