// Package depsdev resolves unknown package licenses via the deps.dev API.
//
// deps.dev (Google Open Source Insights) exposes normalized SPDX license
// expressions for public package versions across several ecosystems. BOMHort
// uses it as a broad fallback after ecosystem-native resolvers have had a
// chance to resolve licenses first.
package depsdev

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/ratelimit"
)

const (
	// DefaultBaseURL is the public deps.dev API root.
	DefaultBaseURL = "https://api.deps.dev"

	defaultRate     = 2.0
	defaultBurst    = 4
	maxBatchSize    = 5000
	batchAPIVersion = "v3alpha"
	getAPIVersion   = "v3"
)

// Resolver resolves package licenses via deps.dev.
type Resolver struct {
	baseURL    string
	httpClient *http.Client
	cache      sync.Map // map[string]string (cache key → SPDX expression or "")
	limiter    *ratelimit.TokenBucket
}

// PackageVersion is the normalized deps.dev lookup key extracted from a purl.
type PackageVersion struct {
	System  string
	Name    string
	Version string
}

// NewResolver creates a resolver against the public deps.dev API.
func NewResolver() *Resolver {
	return NewResolverWithBaseURL(DefaultBaseURL)
}

// NewResolverWithBaseURL creates a resolver against a custom deps.dev API root.
func NewResolverWithBaseURL(baseURL string) *Resolver {
	return &Resolver{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 20 * time.Second},
		limiter:    ratelimit.NewTokenBucket(defaultRate, defaultBurst),
	}
}

// CacheKey returns the cache key for a deps.dev package version.
func CacheKey(pv PackageVersion) string {
	return pv.System + ":" + pv.Name + "@" + pv.Version
}

// Resolve returns the SPDX license expression for purl, or "" if deps.dev does
// not support the ecosystem, the purl does not name an exact version, or the
// version has no standard SPDX license data. Results, including negatives, are
// cached in memory.
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
	pv, ok := ExtractPackageVersion(purl)
	if !ok {
		return ""
	}

	key := CacheKey(pv)
	if cached, found := r.cache.Load(key); found {
		return cached.(string)
	}

	if err := r.limiter.Wait(ctx); err != nil {
		return ""
	}

	lic := r.fetchLicense(ctx, pv)
	r.cache.Store(key, lic)
	if lic != "" {
		log.Printf("  deps.dev license resolved: %s → %s", key, lic)
	}
	return lic
}

// ResolveBatch returns SPDX license expressions for the provided purls. It uses
// deps.dev's v3alpha versionbatch endpoint for uncached package versions and
// falls back to per-version GETs if the batch request fails.
func (r *Resolver) ResolveBatch(ctx context.Context, purls []string) map[string]string {
	out := make(map[string]string, len(purls))
	pending := make(map[string]PackageVersion)
	purlsByKey := make(map[string][]string)

	for _, purl := range purls {
		pv, ok := ExtractPackageVersion(purl)
		if !ok {
			continue
		}
		key := CacheKey(pv)
		if cached, found := r.cache.Load(key); found {
			out[purl] = cached.(string)
			continue
		}
		if _, seen := pending[key]; !seen {
			pending[key] = pv
		}
		purlsByKey[key] = append(purlsByKey[key], purl)
	}
	if len(pending) == 0 {
		return out
	}

	items := make([]PackageVersion, 0, len(pending))
	for _, pv := range pending {
		items = append(items, pv)
	}

	resolved := make(map[string]string, len(pending))
	for start := 0; start < len(items); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(items) {
			end = len(items)
		}
		batch, ok := r.fetchLicenseBatch(ctx, items[start:end])
		if ok {
			for key, lic := range batch {
				resolved[key] = lic
			}
			continue
		}
		for _, pv := range items[start:end] {
			if err := r.limiter.Wait(ctx); err != nil {
				resolved[CacheKey(pv)] = ""
				continue
			}
			resolved[CacheKey(pv)] = r.fetchLicense(ctx, pv)
		}
	}

	for key, pv := range pending {
		lic, ok := resolved[key]
		if !ok {
			lic = ""
		}
		r.cache.Store(key, lic)
		if lic != "" {
			log.Printf("  deps.dev license resolved: %s → %s", key, lic)
		}
		for _, purl := range purlsByKey[CacheKey(pv)] {
			out[purl] = lic
		}
	}
	return out
}

// PreloadCache seeds the in-memory cache (e.g. from ClickHouse).
func (r *Resolver) PreloadCache(entries map[string]string) {
	for k, v := range entries {
		r.cache.Store(k, v)
	}
}

// CacheEntries exports the in-memory cache for persistence.
func (r *Resolver) CacheEntries() map[string]string {
	out := make(map[string]string)
	r.cache.Range(func(k, v any) bool {
		out[k.(string)] = v.(string)
		return true
	})
	return out
}

type versionResponse struct {
	Licenses []string `json:"licenses"`
}

type versionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type batchVersionRequest struct {
	VersionKey versionKey `json:"versionKey"`
}

type batchRequest struct {
	Requests  []batchVersionRequest `json:"requests"`
	PageToken string                `json:"pageToken,omitempty"`
}

type batchResponse struct {
	Responses []struct {
		Request struct {
			VersionKey versionKey `json:"versionKey"`
		} `json:"request"`
		Version versionResponse `json:"version"`
	} `json:"responses"`
	NextPageToken string `json:"nextPageToken"`
}

func (r *Resolver) fetchLicense(ctx context.Context, pv PackageVersion) string {
	u := fmt.Sprintf("%s/%s/systems/%s/packages/%s/versions/%s",
		r.baseURL, getAPIVersion, strings.ToLower(pv.System), url.PathEscape(pv.Name), url.PathEscape(pv.Version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-license-resolver")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("  deps.dev request failed for %s: %v", CacheKey(pv), err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var vr versionResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		return ""
	}
	return NormalizeLicenses(vr.Licenses)
}

func (r *Resolver) fetchLicenseBatch(ctx context.Context, versions []PackageVersion) (map[string]string, bool) {
	resolved := make(map[string]string, len(versions))
	for _, pv := range versions {
		resolved[CacheKey(pv)] = ""
	}

	pageToken := ""
	for {
		reqs := make([]batchVersionRequest, 0, len(versions))
		for _, pv := range versions {
			reqs = append(reqs, batchVersionRequest{VersionKey: versionKey{System: pv.System, Name: pv.Name, Version: pv.Version}})
		}
		body, err := json.Marshal(batchRequest{Requests: reqs, PageToken: pageToken})
		if err != nil {
			return nil, false
		}
		if err := r.limiter.Wait(ctx); err != nil {
			return resolved, true
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/"+batchAPIVersion+"/versionbatch", bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "bomhort-license-resolver")

		resp, err := r.httpClient.Do(req)
		if err != nil {
			log.Printf("  deps.dev batch request failed: %v", err)
			return nil, false
		}
		var br batchResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&br)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decodeErr != nil {
			return nil, false
		}
		for _, item := range br.Responses {
			pv := PackageVersion{System: item.Request.VersionKey.System, Name: item.Request.VersionKey.Name, Version: item.Request.VersionKey.Version}
			resolved[CacheKey(pv)] = NormalizeLicenses(item.Version.Licenses)
		}
		if br.NextPageToken == "" {
			return resolved, true
		}
		pageToken = br.NextPageToken
	}
}

// NormalizeLicenses converts deps.dev's licenses array into a single SPDX
// expression. Non-standard and empty values are treated as unresolved.
func NormalizeLicenses(licenses []string) string {
	parts := make([]string, 0, len(licenses))
	for _, lic := range licenses {
		lic = cleanLicense(lic)
		if lic == "" {
			return ""
		}
		parts = append(parts, lic)
	}
	if len(parts) > 1 {
		for i, lic := range parts {
			parts[i] = parenthesizeIfCompound(lic)
		}
	}
	return strings.Join(parts, " AND ")
}

func cleanLicense(lic string) string {
	lic = strings.TrimSpace(lic)
	if lic == "" {
		return ""
	}
	upper := strings.ToUpper(lic)
	if upper == "NON-STANDARD" || upper == "NOASSERTION" || upper == "NONE" {
		return ""
	}
	return lic
}

func parenthesizeIfCompound(lic string) string {
	if !containsOperator(lic) || (strings.HasPrefix(lic, "(") && strings.HasSuffix(lic, ")")) {
		return lic
	}
	return "(" + lic + ")"
}

func containsOperator(lic string) bool {
	for _, field := range strings.FieldsFunc(lic, func(r rune) bool {
		return unicode.IsSpace(r) || r == '(' || r == ')'
	}) {
		switch strings.ToUpper(field) {
		case "AND", "OR", "WITH":
			return true
		}
	}
	return false
}

// ExtractPackageVersion maps supported package URLs to deps.dev version keys.
func ExtractPackageVersion(purl string) (PackageVersion, bool) {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return PackageVersion{}, false
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 || slash == len(rest)-1 {
		return PackageVersion{}, false
	}
	typ := strings.ToLower(rest[:slash])
	packageAndVersion := rest[slash+1:]
	at := strings.LastIndex(packageAndVersion, "@")
	if at <= 0 || at == len(packageAndVersion)-1 {
		return PackageVersion{}, false
	}
	rawName, rawVersion := packageAndVersion[:at], packageAndVersion[at+1:]
	name, ok := decodePath(rawName)
	if !ok {
		return PackageVersion{}, false
	}
	version, ok := decodePath(rawVersion)
	if !ok || !validVersion(version) {
		return PackageVersion{}, false
	}

	var system string
	switch typ {
	case "maven":
		parts := strings.Split(name, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return PackageVersion{}, false
		}
		name = parts[0] + ":" + parts[1]
		system = "MAVEN"
	case "pypi":
		if strings.Contains(name, "/") {
			return PackageVersion{}, false
		}
		name = normalizePyPIName(name)
		system = "PYPI"
	case "npm":
		if !validNPMName(name) {
			return PackageVersion{}, false
		}
		system = "NPM"
	case "golang":
		if strings.ContainsAny(name, " \\") || name == "" {
			return PackageVersion{}, false
		}
		system = "GO"
	case "cargo":
		if strings.Contains(name, "/") || name == "" {
			return PackageVersion{}, false
		}
		system = "CARGO"
	case "nuget":
		if strings.Contains(name, "/") || name == "" {
			return PackageVersion{}, false
		}
		name = strings.ToLower(name)
		system = "NUGET"
	default:
		return PackageVersion{}, false
	}
	if strings.Contains(name, "..") {
		return PackageVersion{}, false
	}
	return PackageVersion{System: system, Name: strings.TrimSpace(name), Version: strings.TrimSpace(version)}, true
}

func decodePath(s string) (string, bool) {
	decoded, err := url.PathUnescape(s)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(decoded), true
}

func validVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" || strings.EqualFold(version, "unknown") {
		return false
	}
	return !strings.ContainsAny(version, " \t\r\n,")
}

func validNPMName(name string) bool {
	if name == "" || strings.Contains(name, "..") {
		return false
	}
	if strings.HasPrefix(name, "@") {
		return strings.Count(name, "/") == 1
	}
	return !strings.Contains(name, "/")
}

func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	return b.String()
}
