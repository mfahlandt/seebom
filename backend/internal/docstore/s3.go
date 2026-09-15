package docstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
)

// S3Store persists originals as objects under bucket/prefix.
type S3Store struct {
	client *s3client.Client
	bucket string
	prefix string
}

// NewS3Store returns a Store writing to bucket under prefix. The client must
// already be configured for that bucket (it is looked up by name). An empty
// prefix falls back to ReservedS3Prefix.
func NewS3Store(client *s3client.Client, bucket, prefix string) (*S3Store, error) {
	if client == nil {
		return nil, errors.New("docstore: S3 client is nil")
	}
	if bucket == "" {
		return nil, errors.New("docstore: S3 bucket is required")
	}
	if prefix == "" {
		prefix = ReservedS3Prefix
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &S3Store{client: client, bucket: bucket, prefix: prefix}, nil
}

// Backend implements Store.
func (s *S3Store) Backend() string { return BackendS3 }

// Put implements Store.
func (s *S3Store) Put(ctx context.Context, key string, data []byte) (string, error) {
	objKey := s.prefix + strings.TrimPrefix(key, "/")
	if err := s.client.PutObject(ctx, s.bucket, objKey, bytes.NewReader(data), int64(len(data))); err != nil {
		return "", fmt.Errorf("docstore: put %s: %w", objKey, err)
	}
	return "s3://" + s.bucket + "/" + objKey, nil
}

// Get implements Store. Any "s3://" reference is accepted as long as the
// client knows the bucket, so a store can read originals written under a
// different prefix (e.g. after a prefix change).
func (s *S3Store) Get(ctx context.Context, ref string) (io.ReadCloser, error) {
	if _, err := splitRef(ref, "s3"); err != nil {
		return nil, err
	}
	bucket, key, err := s3client.ParseURI(ref)
	if err != nil {
		return nil, fmt.Errorf("docstore: %w", err)
	}
	rc, err := s.client.GetObject(ctx, bucket, key)
	if err != nil {
		return nil, fmt.Errorf("docstore: get %s: %w", ref, err)
	}
	return rc, nil
}
