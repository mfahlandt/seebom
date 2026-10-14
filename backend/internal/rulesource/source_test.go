package rulesource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewRejectsUnsafeOrIncompleteSources(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts Options
		want string
	}{
		{"nothing", Options{}, "no rules source"},
		{"plain http", Options{Source: "http://example.com/x.json"}, "https"},
		{"no scheme", Options{Source: "example.com/x.json"}, "neither"},
		{"s3 without client", Options{Source: "s3://rules/x.json"}, "S3_BUCKETS"},
		{"s3 without key", Options{Source: "s3://rules/", S3: fakeS3{}}, "want s3://bucket/key"},
		{"s3 without bucket", Options{Source: "s3:///x.json", S3: fakeS3{}}, "want s3://bucket/key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestNewRedactsCredentialsInErrors(t *testing.T) {
	_, err := New(Options{Source: "ftp://user:secret@host/x?token=secret"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestFileFetcherFallbackSemantics(t *testing.T) {
	dir := t.TempDir()
	primary, fallback := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	f, err := New(Options{Paths: []string{"", primary, fallback}})
	if err != nil {
		t.Fatal(err)
	}
	if f.Remote() {
		t.Fatal("a file is not remote")
	}

	if _, err := f.Fetch(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no files: err = %v, want ErrNotFound", err)
	}
	write(t, fallback, "fallback")
	if got := mustFetch(t, f); got != "fallback" {
		t.Fatalf("got %q", got)
	}
	// An existing primary wins even when it is broken: the parser rejects
	// it, the fallback must never step in for an invalid primary.
	write(t, primary, "{broken")
	if got := mustFetch(t, f); got != "{broken" {
		t.Fatalf("got %q", got)
	}
}

func TestFileFetcherRejectsOversizedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.json")
	write(t, path, strings.Repeat("x", MaxSize+1))
	f, _ := New(Options{Paths: []string{path}})
	if _, err := f.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPFetcherAuthETagAndErrors(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tkn" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` && status.Load() == http.StatusOK {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if s := int(status.Load()); s != http.StatusOK {
			w.WriteHeader(s)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, "rules")
	}))
	defer srv.Close()

	f, err := New(Options{Source: srv.URL + "/rules.json?sig=secret", Token: "tkn", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Remote() || strings.Contains(f.Describe(), "secret") {
		t.Fatalf("describe = %q", f.Describe())
	}
	if got := mustFetch(t, f); got != "rules" {
		t.Fatalf("got %q", got)
	}
	if _, err := f.Fetch(context.Background()); !errors.Is(err, errNotModified) {
		t.Fatalf("second fetch: err = %v, want not modified", err)
	}
	status.Store(http.StatusNotFound)
	_, err = f.Fetch(context.Background())
	if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("a missing remote document must be an error, not 'no rules': %v", err)
	}

	noToken, _ := New(Options{Source: srv.URL + "/rules.json", HTTPClient: srv.Client()})
	if _, err := noToken.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPFetcherTransportErrorHidesQuery(t *testing.T) {
	f, _ := New(Options{Source: "https://127.0.0.1:1/rules.json?sig=secret"})
	_, err := f.Fetch(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestS3Fetcher(t *testing.T) {
	f, err := New(Options{Source: "s3://rules/team/exceptions.json", S3: fakeS3{"rules/team/exceptions.json": "s3 rules"}})
	if err != nil {
		t.Fatal(err)
	}
	if f.Describe() != "s3://rules/team/exceptions.json" || !f.Remote() {
		t.Fatalf("describe = %q", f.Describe())
	}
	if got := mustFetch(t, f); got != "s3 rules" {
		t.Fatalf("got %q", got)
	}
	missing, _ := New(Options{Source: "s3://rules/other.json", S3: fakeS3{}})
	if _, err := missing.Fetch(context.Background()); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestWatcherLifecycle(t *testing.T) {
	src := &memFetcher{}
	parse := func(b []byte) (string, error) {
		if bytes.HasPrefix(b, []byte("bad")) {
			return "", errors.New("nope")
		}
		return string(b), nil
	}
	w := NewWatcher(src, parse)
	ctx := context.Background()

	if w.Current().Ready {
		t.Fatal("not ready before the first load")
	}

	src.set("v1", nil)
	if changed, err := w.Refresh(ctx); !changed || err != nil {
		t.Fatalf("first load: changed=%v err=%v", changed, err)
	}
	first := w.Current()
	if first.Value != "v1" || !first.Present || !first.Ready || first.Digest != Digest([]byte("v1")) {
		t.Fatalf("snapshot = %+v", first)
	}

	if changed, _ := w.Refresh(ctx); changed {
		t.Fatal("same content is not a change")
	}

	src.set("bad", nil)
	changed, err := w.Refresh(ctx)
	if changed || !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid: changed=%v err=%v", changed, err)
	}
	if s := w.Current(); s.Value != "v1" || s.Digest != first.Digest || !errors.Is(s.Err, ErrInvalid) {
		t.Fatalf("invalid content must keep the last good rules: %+v", s)
	}

	src.set("", errors.New("connection refused"))
	if _, err := w.Refresh(ctx); err == nil {
		t.Fatal("transport error must surface")
	}
	if s := w.Current(); s.Value != "v1" || errors.Is(s.Err, ErrInvalid) || s.Err == nil {
		t.Fatalf("unreachable source: %+v", s)
	}

	src.set("v1", nil)
	if changed, err := w.Refresh(ctx); changed || err != nil || w.Current().Err != nil {
		t.Fatalf("recovery to the same content clears the error without a change: %v %v", changed, err)
	}

	src.set("", ErrNotFound)
	if changed, _ := w.Refresh(ctx); !changed {
		t.Fatal("removing the document is a change")
	}
	if s := w.Current(); s.Present || s.Value != "" || s.Digest != Digest(nil) {
		t.Fatalf("removed: %+v", s)
	}

	src.set("", errNotModified)
	if changed, err := w.Refresh(ctx); changed || err != nil {
		t.Fatalf("not modified: %v %v", changed, err)
	}
}

func TestWatcherRunNotifiesChanges(t *testing.T) {
	src := &memFetcher{}
	src.set("v1", nil)
	w := NewWatcher(src, func(b []byte) (string, error) { return string(b), nil })
	if _, err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := make(chan string, 4)
	go w.Run(ctx, 5*time.Millisecond, func(s Snapshot[string]) { changes <- s.Value })

	src.set("v2", nil)
	select {
	case v := <-changes:
		if v != "v2" {
			t.Fatalf("got %q", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no change notification")
	}
}

func TestWatcherRunDisabled(t *testing.T) {
	w := NewWatcher(&memFetcher{}, func(b []byte) (string, error) { return string(b), nil })
	done := make(chan struct{})
	go func() { w.Run(context.Background(), 0, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("interval 0 must return immediately")
	}
}

type memFetcher struct {
	data atomic.Value // fetchResult
}

type fetchResult struct {
	data string
	err  error
}

func (m *memFetcher) set(data string, err error) { m.data.Store(fetchResult{data, err}) }
func (m *memFetcher) Describe() string           { return "memory" }
func (m *memFetcher) Remote() bool               { return true }
func (m *memFetcher) Fetch(context.Context) ([]byte, error) {
	r, _ := m.data.Load().(fetchResult)
	if r.err != nil {
		return nil, r.err
	}
	return []byte(r.data), nil
}

type fakeS3 map[string]string

func (f fakeS3) GetObject(_ context.Context, bucket, key string) (io.ReadCloser, error) {
	v, ok := f[bucket+"/"+key]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	return io.NopCloser(strings.NewReader(v)), nil
}

func mustFetch(t *testing.T, f Fetcher) string {
	t.Helper()
	b, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A broken document published behind an ETag stays reported as broken: the
// next poll must not get a 304 that reads as "unchanged and fine".
func TestWatcherKeepsReportingAnInvalidRemoteDocument(t *testing.T) {
	var body atomic.Value
	body.Store("good")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := body.Load().(string)
		etag := `"` + b + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		fmt.Fprint(w, b)
	}))
	defer srv.Close()

	f, err := New(Options{Source: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	w := NewWatcher(f, func(b []byte) (string, error) {
		if string(b) != "good" {
			return "", errors.New("broken")
		}
		return string(b), nil
	})
	ctx := context.Background()
	if _, err := w.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	body.Store("broken")
	for i := 0; i < 3; i++ {
		_, _ = w.Refresh(ctx)
		if s := w.Current(); !errors.Is(s.Err, ErrInvalid) || s.Value != "good" {
			t.Fatalf("poll %d: err = %v value = %q, want ErrInvalid with the last good value kept", i, s.Err, s.Value)
		}
	}
	body.Store("good")
	if _, err := w.Refresh(ctx); err != nil || w.Current().Err != nil {
		t.Fatalf("fixed document: refresh err = %v, snapshot err = %v", err, w.Current().Err)
	}
}

// An outage mid-run keeps the last good version current, does not fire
// onChange, and the first successful poll after it reports the new document.
func TestWatcherRunSurvivesOutage(t *testing.T) {
	src := &memFetcher{}
	src.set("v1", nil)
	w := NewWatcher(src, func(b []byte) (string, error) { return string(b), nil })
	if _, err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !w.Remote() || w.Current().Source != "memory" {
		t.Fatalf("watcher must report the fetcher's Remote/Describe, got remote=%v source=%q", w.Remote(), w.Current().Source)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := make(chan string, 4)
	go w.Run(ctx, 5*time.Millisecond, func(s Snapshot[string]) { changes <- s.Value })

	src.set("", errors.New("connection refused"))
	deadline := time.After(2 * time.Second)
	for w.Current().Err == nil {
		select {
		case v := <-changes:
			t.Fatalf("onChange fired during an outage with %q", v)
		case <-deadline:
			t.Fatal("outage never observed")
		case <-time.After(time.Millisecond):
		}
	}
	if cur := w.Current(); cur.Value != "v1" || !cur.Ready {
		t.Fatalf("outage must keep the last good version, got %+v", cur)
	}

	src.set("v2", nil)
	select {
	case v := <-changes:
		if v != "v2" {
			t.Fatalf("got %q after recovery", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no change notification after recovery")
	}
	if err := w.Current().Err; err != nil {
		t.Fatalf("Err must clear after recovery, got %v", err)
	}
}

func TestDescribeNamesTheConfiguredSource(t *testing.T) {
	for _, tc := range []struct {
		opts Options
		want string
	}{
		{Options{Paths: []string{"/a.json", "", "/b.json"}}, "/a.json, /b.json"},
		{Options{Source: "https://example.org/rules.json?sig=secret"}, "https://example.org/rules.json"},
		{Options{Source: "s3://bucket/path/rules.json", S3: fakeS3{}}, "s3://bucket/path/rules.json"},
	} {
		f, err := New(tc.opts)
		if err != nil {
			t.Fatalf("%+v: %v", tc.opts, err)
		}
		if got := f.Describe(); got != tc.want {
			t.Errorf("Describe(%+v) = %q, want %q", tc.opts, got, tc.want)
		}
	}
}
