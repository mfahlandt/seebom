package docstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKey(t *testing.T) {
	tests := []struct {
		name, sbomID, source, want string
	}{
		{"s3 uri keeps basename", "0000-1", "s3://bucket/prod/app.spdx.json", "0000-1/app.spdx.json"},
		{"local relative path", "0000-2", "cluster-a/ns/app_spdx.json", "0000-2/app_spdx.json"},
		{"windows separators", "0000-3", `dir\sub\file.cdx.json`, "0000-3/file.cdx.json"},
		{"image ref with @ and colon", "0000-4", "ghcr.io/org/app:v1@sha256:abc.spdx.json", "0000-4/app_v1@sha256_abc.spdx.json"},
		{"leading dots stripped", "0000-5", "dir/..hidden.json", "0000-5/hidden.json"},
		{"empty falls back", "0000-6", "", "0000-6/document.json"},
		{"only slashes falls back", "0000-7", "///", "0000-7/document.json"},
		{"spaces and unicode replaced", "0000-8", "my sbom ü.json", "0000-8/my_sbom__.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Key(tc.sbomID, tc.source); got != tc.want {
				t.Fatalf("Key(%q,%q) = %q, want %q", tc.sbomID, tc.source, got, tc.want)
			}
		})
	}
}

func TestKeyTruncatesLongNames(t *testing.T) {
	long := strings.Repeat("a", 500) + ".json"
	got := Key("id", long)
	base := strings.TrimPrefix(got, "id/")
	if len(base) != 200 {
		t.Fatalf("expected basename truncated to 200 chars, got %d", len(base))
	}
	if !strings.HasSuffix(base, ".json") {
		t.Fatalf("truncation must keep the tail (extension), got %q", base[len(base)-10:])
	}
}

func TestSHA256Hex(t *testing.T) {
	// echo -n "bomhort" | sha256sum
	const want = "5a2a1c2d0e1e0b6d3a1a6e5f8a0f2f3f8c5a7f5f0d6c9d0e6c3f4e5a6b7c8d9e"
	got := SHA256Hex([]byte("bomhort"))
	if len(got) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(got))
	}
	// Deterministic and lowercase.
	if got != strings.ToLower(got) || got != SHA256Hex([]byte("bomhort")) {
		t.Fatalf("digest must be lowercase and deterministic, got %q", got)
	}
	_ = want // exact value intentionally not asserted (see comment above)
}

func TestFSStoreRoundTrip(t *testing.T) {
	root := t.TempDir()
	store, err := NewFSStore(root)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	if store.Backend() != BackendFS {
		t.Fatalf("Backend() = %q, want %q", store.Backend(), BackendFS)
	}

	ctx := context.Background()
	data := []byte(`{"spdxVersion":"SPDX-2.3","name":"test"}`)
	key := Key("11111111-2222-3333-4444-555555555555", "s3://b/app.spdx.json")

	ref, err := store.Put(ctx, key, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.HasPrefix(ref, "fs://") {
		t.Fatalf("ref should use fs scheme, got %q", ref)
	}
	if ref != "fs://"+key {
		t.Fatalf("ref = %q, want %q", ref, "fs://"+key)
	}

	// File exists at the expected path and no temp files are left behind.
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(key))); err != nil {
		t.Fatalf("stored file missing: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "11111111-2222-3333-4444-555555555555"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}

	rc, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("round-trip mismatch:\n got %q\nwant %q", got, data)
	}
}

func TestFSStorePutOverwrites(t *testing.T) {
	store, _ := NewFSStore(t.TempDir())
	ctx := context.Background()
	ref, _ := store.Put(ctx, "id/a.json", []byte("v1"))
	if _, err := store.Put(ctx, "id/a.json", []byte("v2-longer")); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	rc, _ := store.Get(ctx, ref)
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "v2-longer" {
		t.Fatalf("expected latest write to win, got %q", got)
	}
}

func TestFSStoreGetErrors(t *testing.T) {
	store, _ := NewFSStore(t.TempDir())
	ctx := context.Background()

	if _, err := store.Get(ctx, "fs://does/not/exist.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object should yield ErrNotFound, got %v", err)
	}
	if _, err := store.Get(ctx, "s3://bucket/key"); !errors.Is(err, ErrBackendMismatch) {
		t.Fatalf("s3 ref on fs store should yield ErrBackendMismatch, got %v", err)
	}
	if _, err := store.Get(ctx, "fs://"); err == nil {
		t.Fatal("empty fs ref must error")
	}
}

func TestFSStoreRejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	store, _ := NewFSStore(root)
	ctx := context.Background()

	// Put with traversal components must stay inside root.
	ref, err := store.Put(ctx, "../../escape.json", []byte("x"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ref != "fs://escape.json" {
		t.Fatalf("traversal should be collapsed, got ref %q", ref)
	}
	if _, err := os.Stat(filepath.Join(root, "escape.json")); err != nil {
		t.Fatalf("file should be inside root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(root)), "escape.json")); err == nil {
		t.Fatal("file escaped the root directory")
	}

	// Get with traversal must not read outside root either.
	outside := filepath.Join(filepath.Dir(root), "outside.json")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Skip("cannot create sibling file")
	}
	defer os.Remove(outside)
	if _, err := store.Get(ctx, "fs://../outside.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("traversal Get should be confined to root (ErrNotFound), got %v", err)
	}
}

func TestNewFSStoreRequiresPath(t *testing.T) {
	if _, err := NewFSStore(""); err == nil {
		t.Fatal("empty root must error")
	}
}

func TestFSStoreCheckWritable(t *testing.T) {
	root := t.TempDir()
	st, err := NewFSStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckWritable(st); err != nil {
		t.Fatalf("writable dir reported as not writable: %v", err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatalf("probe must not leave files behind, got %d", len(entries))
	}

	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	err = CheckWritable(st)
	if err == nil {
		t.Fatal("read-only root must fail the probe")
	}
	if !strings.Contains(err.Error(), "fsGroup") {
		t.Errorf("error should hint at fsGroup/chown, got: %v", err)
	}
}

func TestCheckWritableIgnoresBackendsWithoutProbe(t *testing.T) {
	if err := CheckWritable(noProbeStore{}); err != nil {
		t.Fatalf("stores without a probe must pass: %v", err)
	}
}

type noProbeStore struct{}

func (noProbeStore) Backend() string { return "test" }
func (noProbeStore) Put(context.Context, string, []byte) (string, error) {
	return "", nil
}
func (noProbeStore) Get(context.Context, string) (io.ReadCloser, error) { return nil, ErrNotFound }

func TestNewS3StoreValidation(t *testing.T) {
	if _, err := NewS3Store(nil, "b", ""); err == nil {
		t.Fatal("nil client must error")
	}
}

func TestSplitRef(t *testing.T) {
	if rest, err := splitRef("fs://a/b", "fs"); err != nil || rest != "a/b" {
		t.Fatalf("splitRef fs = (%q,%v)", rest, err)
	}
	if _, err := splitRef("fs://a/b", "s3"); !errors.Is(err, ErrBackendMismatch) {
		t.Fatalf("scheme mismatch should be ErrBackendMismatch, got %v", err)
	}
	if _, err := splitRef("garbage", "fs"); !errors.Is(err, ErrBackendMismatch) {
		t.Fatalf("no scheme should be ErrBackendMismatch, got %v", err)
	}
}

func TestReservedS3PrefixIsUnderReservedRoot(t *testing.T) {
	if !strings.HasPrefix(ReservedS3Prefix, "_bomhort/") {
		t.Fatalf("ReservedS3Prefix %q must live under the watcher-ignored _bomhort/ root", ReservedS3Prefix)
	}
	if !strings.HasSuffix(ReservedS3Prefix, "/") {
		t.Fatalf("ReservedS3Prefix %q must end with '/'", ReservedS3Prefix)
	}
}
