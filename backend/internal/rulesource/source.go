// Package rulesource loads an operator-managed rules document — today the
// license exceptions — from a file, an HTTPS URL or an S3 object, and keeps
// it current while the process runs.
//
// The file source is what a mounted ConfigMap looks like to a pod, so all
// three are polled the same way: a ConfigMap edit, a commit behind a raw URL
// and an S3 upload all reach a running gateway and worker without a restart.
package rulesource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// MaxSize bounds a fetched document. The largest public exception registry
// is a few hundred KB; anything near this is not a rules file.
const MaxSize = 10 << 20

// ErrNotFound means the source has no document: none of the configured files
// exist. That is a valid state ("no exceptions"), distinct from a document
// that cannot be fetched. Remote sources never return it — a missing object
// behind a configured URL is an error, not an instruction to drop every
// exception.
var ErrNotFound = errors.New("rules document not found")

// errNotModified is returned by a fetcher whose source answered "unchanged"
// (HTTP 304), so the watcher keeps its current document.
var errNotModified = errors.New("not modified")

// Fetcher retrieves the raw bytes of a rules document.
type Fetcher interface {
	Fetch(ctx context.Context) ([]byte, error)
	// Describe names the source for logs; it never contains credentials.
	Describe() string
	// Remote reports whether the document lives outside the pod (URL, S3).
	Remote() bool
}

// ObjectGetter is the part of the S3 client a fetcher needs.
type ObjectGetter interface {
	GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}

// Options configures New.
type Options struct {
	// Source is "" (use Paths), an https:// URL or an s3://bucket/key URI.
	Source string
	// Paths are tried in order when Source is empty; the first that exists
	// wins, even if it turns out to be invalid.
	Paths []string
	// Token, if set, is sent as "Authorization: Bearer" to an HTTPS source.
	Token string
	// S3 resolves s3:// sources. The bucket must be one the client knows.
	S3 ObjectGetter
	// HTTPClient overrides the client for HTTPS sources (tests).
	HTTPClient *http.Client
}

// New returns the fetcher for opts.Source.
func New(opts Options) (Fetcher, error) {
	src := strings.TrimSpace(opts.Source)
	switch {
	case src == "":
		if len(opts.Paths) == 0 {
			return nil, errors.New("no rules source and no file paths configured")
		}
		return &fileFetcher{paths: opts.Paths}, nil
	case strings.HasPrefix(src, "s3://"):
		bucket, key, err := parseS3URI(src)
		if err != nil {
			return nil, err
		}
		if opts.S3 == nil {
			return nil, fmt.Errorf("rules source %s needs S3, but no S3 bucket is configured (add %q to S3_BUCKETS)", src, bucket)
		}
		return &s3Fetcher{s3: opts.S3, bucket: bucket, key: key}, nil
	default:
		u, err := url.Parse(src)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("rules source %q is neither an https:// URL nor an s3:// URI", redactURL(src))
		}
		if u.Scheme != "https" {
			// The document decides which licenses are approved. Plain HTTP
			// would let anyone on the path approve one.
			return nil, fmt.Errorf("rules source must use https, got %q", u.Scheme)
		}
		client := opts.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 30 * time.Second}
		}
		return &httpFetcher{url: u.String(), token: opts.Token, client: client}, nil
	}
}

func parseS3URI(uri string) (bucket, key string, err error) {
	rest := strings.TrimPrefix(uri, "s3://")
	i := strings.IndexByte(rest, '/')
	if i <= 0 || i == len(rest)-1 {
		return "", "", fmt.Errorf("invalid S3 rules source %q: want s3://bucket/key", uri)
	}
	return rest[:i], rest[i+1:], nil
}

type fileFetcher struct{ paths []string }

func (f *fileFetcher) Describe() string {
	named := make([]string, 0, len(f.paths))
	for _, p := range f.paths {
		if p != "" {
			named = append(named, p)
		}
	}
	return strings.Join(named, ", ")
}
func (f *fileFetcher) Remote() bool { return false }

func (f *fileFetcher) Fetch(context.Context) ([]byte, error) {
	for _, p := range f.paths {
		if p == "" {
			continue
		}
		data, err := readFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return data, err
	}
	return nil, ErrNotFound
}

func readFile(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return limitedRead(fh, path)
}

func limitedRead(r io.Reader, name string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, MaxSize)
	}
	return data, nil
}

type httpFetcher struct {
	url    string
	token  string
	client *http.Client
	etag   string
}

// versionForgetter is implemented by fetchers that send conditional
// requests: the watcher drops the remembered version of a document it
// rejected, so the next poll fetches it again instead of a 304.
type versionForgetter interface{ forgetVersion() }

func (h *httpFetcher) forgetVersion() { h.etag = "" }

func (h *httpFetcher) Describe() string { return redactURL(h.url) }
func (h *httpFetcher) Remote() bool     { return true }

func (h *httpFetcher) Fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, err
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	if h.etag != "" {
		req.Header.Set("If-None-Match", h.etag)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		// *url.Error repeats the full URL, query string included.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, fmt.Errorf("fetch %s: %w", h.Describe(), err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, errNotModified
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("fetch %s: HTTP %d", h.Describe(), resp.StatusCode)
	}
	data, err := limitedRead(resp.Body, h.Describe())
	if err != nil {
		return nil, err
	}
	h.etag = resp.Header.Get("ETag")
	return data, nil
}

// redactURL drops userinfo and the query string, either of which may carry
// a credential (e.g. a pre-signed URL).
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

type s3Fetcher struct {
	s3          ObjectGetter
	bucket, key string
}

func (s *s3Fetcher) Describe() string { return "s3://" + s.bucket + "/" + s.key }
func (s *s3Fetcher) Remote() bool     { return true }

func (s *s3Fetcher) Fetch(ctx context.Context) ([]byte, error) {
	rc, err := s.s3.GetObject(ctx, s.bucket, s.key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return limitedRead(rc, s.Describe())
}

// Digest is the SHA-256 of a document. A missing document hashes like an
// empty one, so "rules removed" is a change like any other.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
