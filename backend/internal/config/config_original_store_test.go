package config

import (
	"testing"
)

func TestLoad_OriginalStore_Defaults(t *testing.T) {
	t.Setenv("ORIGINAL_STORE_BACKEND", "")
	t.Setenv("ORIGINAL_STORE_S3_BUCKET", "")
	t.Setenv("ORIGINAL_STORE_S3_PREFIX", "")
	t.Setenv("ORIGINAL_STORE_FS_PATH", "")
	t.Setenv("S3_BUCKETS", "")
	t.Setenv("S3_BUCKET", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OriginalStoreBackend != OriginalStoreAuto {
		t.Errorf("OriginalStoreBackend = %q, want %q", cfg.OriginalStoreBackend, OriginalStoreAuto)
	}
	if cfg.OriginalStoreS3Prefix != "_bomhort/originals/" {
		t.Errorf("OriginalStoreS3Prefix = %q, want default reserved prefix", cfg.OriginalStoreS3Prefix)
	}
	// auto + no S3 + no fs path → none
	if got := cfg.ResolvedOriginalStoreBackend(); got != OriginalStoreNone {
		t.Errorf("ResolvedOriginalStoreBackend() = %q, want %q", got, OriginalStoreNone)
	}
	if cfg.OriginalStoreBucket() != "" {
		t.Errorf("OriginalStoreBucket() should be empty without S3 buckets, got %q", cfg.OriginalStoreBucket())
	}
}

func TestLoad_OriginalStore_AutoPrefersS3(t *testing.T) {
	t.Setenv("ORIGINAL_STORE_BACKEND", "auto")
	t.Setenv("ORIGINAL_STORE_FS_PATH", "/data/originals")
	t.Setenv("S3_BUCKETS", `[{"name":"push","skipScan":true},{"name":"src"},{"name":"other"}]`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.ResolvedOriginalStoreBackend(); got != OriginalStoreS3 {
		t.Errorf("auto with S3 buckets should resolve to s3, got %q", got)
	}
	// Default bucket: first non-skipScan bucket, not the push bucket.
	if got := cfg.OriginalStoreBucket(); got != "src" {
		t.Errorf("OriginalStoreBucket() = %q, want \"src\" (first non-skipScan)", got)
	}
}

func TestLoad_OriginalStore_ExplicitBucketWins(t *testing.T) {
	t.Setenv("ORIGINAL_STORE_BACKEND", "s3")
	t.Setenv("ORIGINAL_STORE_S3_BUCKET", "archive")
	t.Setenv("S3_BUCKETS", `[{"name":"src"},{"name":"archive"}]`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.OriginalStoreBucket(); got != "archive" {
		t.Errorf("OriginalStoreBucket() = %q, want \"archive\"", got)
	}
}

func TestLoad_OriginalStore_OnlySkipScanBucketFallsBack(t *testing.T) {
	t.Setenv("ORIGINAL_STORE_BACKEND", "auto")
	t.Setenv("S3_BUCKETS", `[{"name":"push","skipScan":true}]`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.OriginalStoreBucket(); got != "push" {
		t.Errorf("with only a skipScan bucket, OriginalStoreBucket() should fall back to it, got %q", got)
	}
}

func TestLoad_OriginalStore_AutoFallsBackToFS(t *testing.T) {
	t.Setenv("ORIGINAL_STORE_BACKEND", "auto")
	t.Setenv("ORIGINAL_STORE_FS_PATH", "/data/originals")
	t.Setenv("S3_BUCKETS", "")
	t.Setenv("S3_BUCKET", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.ResolvedOriginalStoreBackend(); got != OriginalStoreFS {
		t.Errorf("auto with fs path and no S3 should resolve to fs, got %q", got)
	}
}

func TestLoad_OriginalStore_ExplicitOverridesAuto(t *testing.T) {
	t.Setenv("ORIGINAL_STORE_BACKEND", "NONE") // case-insensitive
	t.Setenv("S3_BUCKETS", `[{"name":"src"}]`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.ResolvedOriginalStoreBackend(); got != OriginalStoreNone {
		t.Errorf("explicit none must win over auto-detected S3, got %q", got)
	}
}

func TestLoad_OriginalStore_InvalidBackend(t *testing.T) {
	t.Setenv("ORIGINAL_STORE_BACKEND", "tape")
	if _, err := Load(); err == nil {
		t.Fatal("invalid ORIGINAL_STORE_BACKEND must fail Load()")
	}
}
