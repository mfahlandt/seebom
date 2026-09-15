// Package docstore persists the original bytes of ingested SBOM documents
// (Tier-2 fidelity capture, #256).
//
// ClickHouse is an analytical store: the dependency tree lives in parallel
// Array() columns and most document-level detail (copyright text, supplier,
// external references, formatting) is dropped on parse. To be able to hand
// the exact document back later — for download, enriched export or
// re-signing (#255) — the worker stores the raw bytes in a blob store at
// ingest time and records only a reference + sha256 in the document_store
// table.
//
// Two backends are provided: S3/MinIO (object storage, typically the source
// bucket under a reserved prefix) and a local filesystem directory (a PVC for
// filesystem-only or air-gapped deployments). Both are addressed through
// opaque references ("s3://bucket/key", "fs://relative/path") so that the API
// gateway can resolve a stored reference without knowing how it was produced.
package docstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
)

// Backend identifiers as persisted in document_store.storage_backend.
const (
	BackendS3 = "s3"
	BackendFS = "fs"
)

// ReservedS3Prefix is the default key prefix under which originals are stored
// when the S3 backend shares a bucket with SBOM sources. The ingestion watcher
// skips this prefix so stored originals are never re-ingested as new SBOMs.
const ReservedS3Prefix = s3client.ReservedPrefix + "originals/"

// ErrNotFound is returned by Get when the referenced object does not exist.
var ErrNotFound = errors.New("docstore: object not found")

// ErrBackendMismatch is returned by Get when the reference scheme does not
// match the store's backend (e.g. worker wrote to S3, gateway configured fs).
var ErrBackendMismatch = errors.New("docstore: reference scheme does not match configured backend")

// Store persists and retrieves original document bytes.
type Store interface {
	// Backend returns the backend identifier (BackendS3 or BackendFS).
	Backend() string
	// Put stores data under the given relative key and returns the opaque
	// reference to persist in document_store.storage_ref.
	Put(ctx context.Context, key string, data []byte) (ref string, err error)
	// Get opens the object addressed by a reference previously returned by Put.
	// The caller must close the returned reader.
	Get(ctx context.Context, ref string) (io.ReadCloser, error)
}

// writableChecker is implemented by backends that can cheaply verify write
// access up front (currently FSStore). S3 credentials are validated lazily
// on the first Put.
type writableChecker interface {
	CheckWritable() error
}

// CheckWritable runs the backend's startup write probe, if it has one.
// Read-only consumers (the API gateway) must not call this.
func CheckWritable(s Store) error {
	if wc, ok := s.(writableChecker); ok {
		return wc.CheckWritable()
	}
	return nil
}

// SHA256Hex returns the lowercase hex sha256 digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Key builds the relative storage key for an SBOM: "<sbom_id>/<basename>".
//
// The sbom_id gives a stable, collision-free directory; the sanitized base
// name of the source file is kept so the object is recognisable in the bucket
// and so the download can offer the original filename.
func Key(sbomID, sourceFile string) string {
	base := path.Base(strings.ReplaceAll(sourceFile, "\\", "/"))
	if base == "" || base == "." || base == "/" {
		return sbomID + "/document.json"
	}
	base = sanitizeName(base)
	if base == "" {
		base = "document.json"
	}
	return sbomID + "/" + base
}

// sanitizeName keeps a conservative character set for object keys / file
// names: letters, digits, '.', '-', '_' and '@' (for image references such as
// "app@sha256-…"). Everything else becomes '_'. Leading dots are stripped so a
// key can never start a hidden file or a path traversal segment.
func sanitizeName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == '@':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.TrimLeft(b.String(), ".")
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out
}

// splitRef separates "scheme://rest" and validates the scheme.
func splitRef(ref, wantScheme string) (string, error) {
	prefix := wantScheme + "://"
	if !strings.HasPrefix(ref, prefix) {
		return "", fmt.Errorf("%w: %q", ErrBackendMismatch, ref)
	}
	rest := strings.TrimPrefix(ref, prefix)
	if rest == "" {
		return "", fmt.Errorf("docstore: empty reference %q", ref)
	}
	return rest, nil
}
