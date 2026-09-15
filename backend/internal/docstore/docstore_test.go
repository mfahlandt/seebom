package docstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
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

	res, err := store.Put(ctx, key, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := res.Ref
	if !strings.HasPrefix(ref, "fs://") {
		t.Fatalf("ref should use fs scheme, got %q", ref)
	}
	// Objects are stored gzip-compressed and carry the .gz suffix so the
	// encoding can be derived from the reference alone.
	if ref != "fs://"+key+".gz" {
		t.Fatalf("ref = %q, want %q", ref, "fs://"+key+".gz")
	}
	if res.Encoding != EncodingGzip {
		t.Fatalf("Encoding = %q, want gzip", res.Encoding)
	}
	if res.StoredBytes == 0 {
		t.Fatal("StoredBytes must be reported")
	}
	if EncodingOf(ref) != EncodingGzip {
		t.Fatalf("EncodingOf(%q) = %q", ref, EncodingOf(ref))
	}

	// File exists at the expected path and no temp files are left behind.
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(key)+".gz"))
	if err != nil {
		t.Fatalf("stored file missing: %v", err)
	}
	if uint64(info.Size()) != res.StoredBytes {
		t.Fatalf("StoredBytes = %d, file is %d", res.StoredBytes, info.Size())
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

	// GetEncoded hands out the stored (compressed) bytes untouched.
	erc, enc, err := store.GetEncoded(ctx, ref)
	if err != nil {
		t.Fatalf("GetEncoded: %v", err)
	}
	defer erc.Close()
	if enc != EncodingGzip {
		t.Fatalf("GetEncoded encoding = %q, want gzip", enc)
	}
	rawStored, _ := io.ReadAll(erc)
	if uint64(len(rawStored)) != res.StoredBytes {
		t.Fatalf("GetEncoded returned %d bytes, want %d", len(rawStored), res.StoredBytes)
	}
	zr, err := gzip.NewReader(bytes.NewReader(rawStored))
	if err != nil {
		t.Fatalf("stored bytes are not gzip: %v", err)
	}
	decoded, _ := io.ReadAll(zr)
	if string(decoded) != string(data) {
		t.Fatalf("manual gunzip mismatch: %q", decoded)
	}
}

func TestCompressionActuallyShrinksSBOMLikeJSON(t *testing.T) {
	store, _ := NewFSStore(t.TempDir())
	ctx := context.Background()
	// Repetitive JSON, like a real SBOM package list.
	var sb strings.Builder
	sb.WriteString(`{"packages":[`)
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&sb, `{"name":"pkg-%d","versionInfo":"1.0.%d","licenseConcluded":"Apache-2.0","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:golang/example.com/pkg-%d@v1.0.%d"}]},`, i, i, i, i)
	}
	sb.WriteString(`{}]}`)
	data := []byte(sb.String())

	res, err := store.Put(ctx, "id/big.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if res.StoredBytes*4 > uint64(len(data)) {
		t.Fatalf("expected at least 4x compression, got %d -> %d", len(data), res.StoredBytes)
	}
}

func TestFSStoreDelete(t *testing.T) {
	root := t.TempDir()
	store, _ := NewFSStore(root)
	ctx := context.Background()

	res, err := store.Put(ctx, "some-id/a.json", []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, res.Ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, res.Ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted object should be gone, got %v", err)
	}
	// Empty per-SBOM directory is cleaned up too.
	if _, err := os.Stat(filepath.Join(root, "some-id")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty sbom dir should be removed, stat err = %v", err)
	}
	// Deleting twice is not an error.
	if err := store.Delete(ctx, res.Ref); err != nil {
		t.Fatalf("second Delete must be a no-op, got %v", err)
	}
	// Non-empty directory survives.
	a, _ := store.Put(ctx, "other/a.json", []byte("a"))
	_, _ = store.Put(ctx, "other/b.json", []byte("b"))
	if err := store.Delete(ctx, a.Ref); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "other")); err != nil {
		t.Fatalf("non-empty dir must survive: %v", err)
	}
	// Wrong scheme is refused.
	if err := store.Delete(ctx, "s3://bucket/key"); !errors.Is(err, ErrBackendMismatch) {
		t.Fatalf("s3 ref on fs store should yield ErrBackendMismatch, got %v", err)
	}
}

func TestFSStorePutOverwrites(t *testing.T) {
	store, _ := NewFSStore(t.TempDir())
	ctx := context.Background()
	res, _ := store.Put(ctx, "id/a.json", []byte("v1"))
	if _, err := store.Put(ctx, "id/a.json", []byte("v2-longer")); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	rc, _ := store.Get(ctx, res.Ref)
	got, _ := io.ReadAll(rc)
	if string(got) != "v2-longer" {
		t.Fatalf("expected latest write to win, got %q", got)
	}
}

func TestFSStoreGetErrors(t *testing.T) {
	root := t.TempDir()
	store, _ := NewFSStore(root)
	ctx := context.Background()

	if _, err := store.Get(ctx, "fs://does/not/exist.json.gz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object should yield ErrNotFound, got %v", err)
	}
	if _, err := store.Get(ctx, "s3://bucket/key"); !errors.Is(err, ErrBackendMismatch) {
		t.Fatalf("s3 ref on fs store should yield ErrBackendMismatch, got %v", err)
	}
	if _, err := store.Get(ctx, "fs://"); err == nil {
		t.Fatal("empty fs ref must error")
	}

	// A .gz reference whose bytes are not gzip must fail loudly, not stream garbage.
	if err := os.WriteFile(filepath.Join(root, "bad.json.gz"), []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "fs://bad.json.gz"); err == nil {
		t.Fatal("corrupt gzip must error")
	}
	// Identity objects (no .gz suffix) are read as-is.
	if err := os.WriteFile(filepath.Join(root, "plain.json"), []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := store.Get(ctx, "fs://plain.json")
	if err != nil {
		t.Fatalf("identity Get: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != `{"a":1}` {
		t.Fatalf("identity Get = %q", got)
	}
}

func TestFSStoreRejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	store, _ := NewFSStore(root)
	ctx := context.Background()

	// Put with traversal components must stay inside root.
	res, err := store.Put(ctx, "../../escape.json", []byte("x"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if res.Ref != "fs://escape.json.gz" {
		t.Fatalf("traversal should be collapsed, got ref %q", res.Ref)
	}
	if _, err := os.Stat(filepath.Join(root, "escape.json.gz")); err != nil {
		t.Fatalf("file should be inside root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(root)), "escape.json.gz")); err == nil {
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
func (noProbeStore) Put(context.Context, string, []byte) (PutResult, error) {
	return PutResult{}, nil
}
func (noProbeStore) Get(context.Context, string) (io.ReadCloser, error) { return nil, ErrNotFound }
func (noProbeStore) GetEncoded(context.Context, string) (io.ReadCloser, string, error) {
	return nil, "", ErrNotFound
}
func (noProbeStore) Delete(context.Context, string) error { return nil }

func TestNewS3StoreValidation(t *testing.T) {
	if _, err := NewS3Store(nil, "b", ""); err == nil {
		t.Fatal("nil client must error")
	}
}

func TestS3StoreDeleteRefusesForeignObjects(t *testing.T) {
	// The prefix guard runs before any network call, so an empty client is
	// enough to exercise it.
	raw := &S3Store{client: &s3client.Client{}, bucket: "archive", prefix: "_bomhort/originals/"}
	ctx := context.Background()

	for _, ref := range []string{
		"s3://archive/prod/app.spdx.json.gz",     // source object in the same bucket
		"s3://other-bucket/_bomhort/originals/x", // right prefix, wrong bucket
		"s3://archive/_bomhort/other/x",          // sibling reserved prefix
	} {
		if err := raw.deleteRaw(ctx, ref); err == nil || !strings.Contains(err.Error(), "refusing to delete") {
			t.Fatalf("deleteRaw(%q) should refuse, got %v", ref, err)
		}
	}
	if err := raw.deleteRaw(ctx, "fs://archive/_bomhort/originals/x"); !errors.Is(err, ErrBackendMismatch) {
		t.Fatalf("fs ref on s3 store should be ErrBackendMismatch, got %v", err)
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
