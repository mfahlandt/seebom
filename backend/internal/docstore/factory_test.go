package docstore

import (
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

func TestFromConfigNone(t *testing.T) {
	cfg := &config.Config{OriginalStoreBackend: config.OriginalStoreNone}
	store, err := FromConfig(cfg, nil)
	if err != nil || store != nil {
		t.Fatalf("none backend should yield (nil,nil), got (%v,%v)", store, err)
	}
}

func TestFromConfigAutoResolvesToNoneWithoutSources(t *testing.T) {
	cfg := &config.Config{OriginalStoreBackend: config.OriginalStoreAuto}
	store, err := FromConfig(cfg, nil)
	if err != nil || store != nil {
		t.Fatalf("auto without S3/fs should be disabled, got (%v,%v)", store, err)
	}
}

func TestFromConfigAutoPrefersFSWhenPathSet(t *testing.T) {
	cfg := &config.Config{
		OriginalStoreBackend: config.OriginalStoreAuto,
		OriginalStoreFSPath:  t.TempDir(),
	}
	store, err := FromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("FromConfig: %v", err)
	}
	if store == nil || store.Backend() != BackendFS {
		t.Fatalf("expected fs store, got %#v", store)
	}
}

func TestFromConfigFSRequiresPath(t *testing.T) {
	cfg := &config.Config{OriginalStoreBackend: config.OriginalStoreFS}
	if _, err := FromConfig(cfg, nil); err == nil {
		t.Fatal("fs backend without path must error")
	}
}

func TestFromConfigS3RequiresClient(t *testing.T) {
	cfg := &config.Config{
		OriginalStoreBackend: config.OriginalStoreS3,
		S3Buckets:            []config.S3BucketConfig{{Name: "src"}},
	}
	if _, err := FromConfig(cfg, nil); err == nil {
		t.Fatal("s3 backend without client must error")
	}
}

func TestFromConfigS3AutoWithBucketsButNoClientErrors(t *testing.T) {
	// auto + S3 buckets configured resolves to s3; without a client that is a
	// misconfiguration the worker must not silently ignore.
	cfg := &config.Config{
		OriginalStoreBackend: config.OriginalStoreAuto,
		S3Buckets:            []config.S3BucketConfig{{Name: "src"}},
	}
	if _, err := FromConfig(cfg, nil); err == nil {
		t.Fatal("expected error when auto resolves to s3 but no client is available")
	}
}

func TestFromConfigRejectsUnknownBackend(t *testing.T) {
	cfg := &config.Config{OriginalStoreBackend: "tape"}
	if _, err := FromConfig(cfg, nil); err == nil {
		t.Fatal("unknown backend must error")
	}
}
