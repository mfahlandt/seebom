package depsdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestExtractPackageVersion(t *testing.T) {
	tests := []struct {
		purl string
		want PackageVersion
		ok   bool
	}{
		{"pkg:maven/com.google.code.findbugs/jsr305@3.0.2", PackageVersion{"MAVEN", "com.google.code.findbugs:jsr305", "3.0.2"}, true},
		{"pkg:maven/com.google.code.findbugs/jsr305@3.0.2?classifier=sources#lib", PackageVersion{"MAVEN", "com.google.code.findbugs:jsr305", "3.0.2"}, true},
		{"pkg:npm/%40scope/name@1.2.3", PackageVersion{"NPM", "@scope/name", "1.2.3"}, true},
		{"pkg:npm/@scope/name@1.2.3", PackageVersion{"NPM", "@scope/name", "1.2.3"}, true},
		{"pkg:pypi/My_Pkg.Name@1.0.0", PackageVersion{"PYPI", "my-pkg-name", "1.0.0"}, true},
		{"pkg:golang/github.com/x/y@v1.2.3", PackageVersion{"GO", "github.com/x/y", "v1.2.3"}, true},
		{"pkg:cargo/unicode-ident@1.0.12", PackageVersion{"CARGO", "unicode-ident", "1.0.12"}, true},
		{"pkg:nuget/Newtonsoft.Json@13.0.3", PackageVersion{"NUGET", "newtonsoft.json", "13.0.3"}, true},
		{"pkg:composer/vendor/name@1.0.0", PackageVersion{}, false},
		{"pkg:maven/com.google.code.findbugs/jsr305", PackageVersion{}, false},
		{"pkg:cargo/foo@unknown", PackageVersion{}, false},
		{"pkg:cargo/foo@1.0,2.0", PackageVersion{}, false},
		{"pkg:cargo/foo@1.0 2.0", PackageVersion{}, false},
		{"pkg:npm/foo/bar@1.0.0", PackageVersion{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			got, ok := ExtractPackageVersion(tt.purl)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("ExtractPackageVersion(%q) = (%+v, %v), want (%+v, %v)", tt.purl, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNormalizeLicenses(t *testing.T) {
	tests := []struct {
		name     string
		licenses []string
		want     string
	}{
		{"single", []string{"Apache-2.0"}, "Apache-2.0"},
		{"compound single", []string{"Unicode-DFS-2016 AND (Apache-2.0 OR MIT)"}, "Unicode-DFS-2016 AND (Apache-2.0 OR MIT)"},
		{"multiple", []string{"MIT OR Apache-2.0", "BSD-3-Clause"}, "(MIT OR Apache-2.0) AND BSD-3-Clause"},
		{"non-standard", []string{"non-standard"}, ""},
		{"empty entries", []string{"", "  "}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeLicenses(tt.licenses); got != tt.want {
				t.Fatalf("NormalizeLicenses(%v) = %q, want %q", tt.licenses, got, tt.want)
			}
		})
	}
}

func TestResolveAndCache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/v3/systems/maven/packages/com.google.code.findbugs:jsr305/versions/3.0.2", "/v3/systems/maven/packages/com.google.code.findbugs%3Ajsr305/versions/3.0.2":
			_, _ = w.Write([]byte(`{"licenses":["Apache-2.0"]}`))
		case "/v3/systems/cargo/packages/private/versions/1.0.0":
			_, _ = w.Write([]byte(`{"licenses":["non-standard"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	ctx := context.Background()
	if got := r.Resolve(ctx, "pkg:maven/com.google.code.findbugs/jsr305@3.0.2"); got != "Apache-2.0" {
		t.Fatalf("maven resolve = %q, want Apache-2.0", got)
	}
	if got := r.Resolve(ctx, "pkg:cargo/private@1.0.0"); got != "" {
		t.Fatalf("non-standard resolve = %q, want empty", got)
	}
	if got := r.Resolve(ctx, "pkg:cargo/missing@1.0.0"); got != "" {
		t.Fatalf("missing resolve = %q, want empty", got)
	}
	before := calls
	r.Resolve(ctx, "pkg:maven/com.google.code.findbugs/jsr305@3.0.2")
	r.Resolve(ctx, "pkg:cargo/private@1.0.0")
	r.Resolve(ctx, "pkg:cargo/missing@1.0.0")
	if calls != before {
		t.Fatalf("expected cached positive and negative results, got %d extra calls", calls-before)
	}

	entries := r.CacheEntries()
	if entries["MAVEN:com.google.code.findbugs:jsr305@3.0.2"] != "Apache-2.0" {
		t.Fatalf("cache missing positive entry: %v", entries)
	}
	if v, ok := entries["CARGO:missing@1.0.0"]; !ok || v != "" {
		t.Fatalf("cache missing negative entry: %v", entries)
	}
}

func TestPreloadCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("deps.dev must not be called for preloaded entries: %s", r.URL.Path)
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	r.PreloadCache(map[string]string{"PYPI:requests@2.31.0": "Apache-2.0"})
	if got := r.Resolve(context.Background(), "pkg:pypi/requests@2.31.0"); got != "Apache-2.0" {
		t.Fatalf("preloaded resolve = %q, want Apache-2.0", got)
	}
}

func TestResolveBatch(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v3alpha/versionbatch" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"responses":[
				{"request":{"versionKey":{"system":"MAVEN","name":"com.google.code.findbugs:jsr305","version":"3.0.2"}},"version":{"licenses":["Apache-2.0"]}},
				{"request":{"versionKey":{"system":"CARGO","name":"unicode-ident","version":"1.0.12"}},"version":{"licenses":["Unicode-DFS-2016 AND (Apache-2.0 OR MIT)"]}},
				{"request":{"versionKey":{"system":"PYPI","name":"unknown","version":"1.0.0"}},"version":{"licenses":[]}}
			]
		}`))
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	purls := []string{
		"pkg:maven/com.google.code.findbugs/jsr305@3.0.2",
		"pkg:cargo/unicode-ident@1.0.12",
		"pkg:pypi/unknown@1.0.0",
		"pkg:composer/vendor/name@1.0.0",
	}
	got := r.ResolveBatch(context.Background(), purls)
	want := map[string]string{
		"pkg:maven/com.google.code.findbugs/jsr305@3.0.2": "Apache-2.0",
		"pkg:cargo/unicode-ident@1.0.12":                  "Unicode-DFS-2016 AND (Apache-2.0 OR MIT)",
		"pkg:pypi/unknown@1.0.0":                          "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveBatch() = %v, want %v", got, want)
	}
	before := calls
	got = r.ResolveBatch(context.Background(), purls)
	if calls != before {
		t.Fatalf("expected batch cache hits, got %d extra calls", calls-before)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cached ResolveBatch() = %v, want %v", got, want)
	}
}
