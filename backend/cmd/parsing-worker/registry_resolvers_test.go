package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// fakeResolver resolves purls with a given prefix from a static map.
type fakeResolver struct {
	prefix string
	known  map[string]string
	calls  int
	cache  map[string]string
}

func (f *fakeResolver) Resolve(_ context.Context, purl string) string {
	if !strings.HasPrefix(purl, f.prefix) {
		return ""
	}
	f.calls++
	return f.known[purl]
}

func (f *fakeResolver) PreloadCache(entries map[string]string) {
	if f.cache == nil {
		f.cache = map[string]string{}
	}
	for k, v := range entries {
		f.cache[k] = v
	}
}

func (f *fakeResolver) CacheEntries() map[string]string { return f.cache }

type fakeStore struct {
	inserted map[string]map[string]string
}

func (s *fakeStore) InsertRegistryLicenseCache(_ context.Context, registry string, entries map[string]string) error {
	if s.inserted == nil {
		s.inserted = map[string]map[string]string{}
	}
	s.inserted[registry] = entries
	return nil
}

func TestApplyRegistryResolvers(t *testing.T) {
	npm := &fakeResolver{prefix: "pkg:npm/", known: map[string]string{
		"pkg:npm/a@1": "MIT",
		"pkg:npm/b@1": "", // registry knows nothing
	}}
	nuget := &fakeResolver{prefix: "pkg:nuget/", known: map[string]string{
		"pkg:nuget/C@1": "Apache-2.0",
	}}
	resolvers := []registryResolver{{"npm", npm}, {"nuget", nuget}}

	purls := []string{"pkg:npm/a@1", "pkg:npm/b@1", "pkg:nuget/C@1", "pkg:golang/x@1", "", "pkg:nuget/D@1"}
	licenses := []string{"NOASSERTION", "", "NONE", "NOASSERTION", "NOASSERTION", "BSD-3-Clause"}

	counts := applyRegistryResolvers(context.Background(), resolvers, purls, licenses)

	want := []string{"MIT", "", "Apache-2.0", "NOASSERTION", "NOASSERTION", "BSD-3-Clause"}
	if !reflect.DeepEqual(licenses, want) {
		t.Errorf("licenses = %v, want %v", licenses, want)
	}
	if counts["npm"] != 1 || counts["nuget"] != 1 {
		t.Errorf("counts = %v, want npm=1 nuget=1", counts)
	}
	// Known licenses (index 5) must never be offered to a resolver.
	if nuget.calls != 1 {
		t.Errorf("nuget resolver called %d times, want 1 (only the unknown nuget purl)", nuget.calls)
	}
}

func TestApplyRegistryResolvers_LicensesShorterThanPURLs(t *testing.T) {
	r := &fakeResolver{prefix: "pkg:npm/", known: map[string]string{"pkg:npm/a@1": "MIT"}}
	purls := []string{"pkg:npm/a@1", "pkg:npm/b@1"}
	licenses := []string{"NOASSERTION"}
	applyRegistryResolvers(context.Background(), []registryResolver{{"npm", r}}, purls, licenses)
	if licenses[0] != "MIT" || len(licenses) != 1 {
		t.Errorf("got %v", licenses)
	}
}

func TestResolveViaRegistries_PersistsCaches(t *testing.T) {
	r := &fakeResolver{prefix: "pkg:npm/", known: map[string]string{"pkg:npm/a@1": "MIT"}}
	r.PreloadCache(map[string]string{"a@1": "MIT"})
	empty := &fakeResolver{prefix: "pkg:nuget/"}
	store := &fakeStore{}

	licenses := []string{"NOASSERTION"}
	resolveViaRegistries(context.Background(), store,
		[]registryResolver{{"npm", r}, {"nuget", empty}},
		[]string{"pkg:npm/a@1"}, licenses)

	if licenses[0] != "MIT" {
		t.Errorf("license not resolved: %v", licenses)
	}
	if got := store.inserted["npm"]; !reflect.DeepEqual(got, map[string]string{"a@1": "MIT"}) {
		t.Errorf("npm cache not persisted: %v", store.inserted)
	}
	if _, ok := store.inserted["nuget"]; ok {
		t.Errorf("empty cache must not be persisted: %v", store.inserted)
	}
}

func TestResolveViaRegistries_NilStore(t *testing.T) {
	r := &fakeResolver{prefix: "pkg:npm/", known: map[string]string{"pkg:npm/a@1": "MIT"}}
	licenses := []string{"NOASSERTION"}
	// Must not panic without a persistence backend.
	resolveViaRegistries(context.Background(), nil, []registryResolver{{"npm", r}}, []string{"pkg:npm/a@1"}, licenses)
	if licenses[0] != "MIT" {
		t.Errorf("got %v", licenses)
	}
}
