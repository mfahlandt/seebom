package main

import (
	"context"
	"log"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	gh "github.com/seebom-labs/bomhort/backend/internal/github"
	"github.com/seebom-labs/bomhort/backend/internal/npm"
	"github.com/seebom-labs/bomhort/backend/internal/nuget"
)

// licenseResolver is implemented by the package-registry resolvers (npm, NuGet).
type licenseResolver interface {
	Resolve(ctx context.Context, purl string) string
	PreloadCache(entries map[string]string)
	CacheEntries() map[string]string
}

// registryResolver couples a resolver with its cache namespace in registry_license_cache.
type registryResolver struct {
	name     string
	resolver licenseResolver
}

// newRegistryResolvers builds the enabled registry resolvers and preloads their
// caches from ClickHouse. ghResolver may be nil; when present, the NuGet
// resolver uses it to derive licenses of legacy packages from their GitHub repo.
func newRegistryResolvers(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, ghResolver *gh.Resolver) []registryResolver {
	var out []registryResolver

	if !cfg.SkipNPMResolve {
		out = append(out, registryResolver{name: "npm", resolver: npm.NewResolver()})
		log.Println("npm license resolver enabled (registry.npmjs.org)")
	} else {
		log.Println("npm license resolver disabled (SKIP_NPM_RESOLVE=true)")
	}

	if !cfg.SkipNuGetResolve {
		var repo nuget.RepoResolver
		if ghResolver != nil {
			repo = ghResolver
		}
		out = append(out, registryResolver{name: "nuget", resolver: nuget.NewResolver(repo)})
		log.Println("NuGet license resolver enabled (api.nuget.org)")
	} else {
		log.Println("NuGet license resolver disabled (SKIP_NUGET_RESOLVE=true)")
	}

	for _, rr := range out {
		if cached, err := chClient.QueryRegistryLicenseCache(ctx, rr.name); err == nil && len(cached) > 0 {
			rr.resolver.PreloadCache(cached)
			log.Printf("Preloaded %d %s license cache entries", len(cached), rr.name)
		}
	}
	return out
}

// cachePersister is the subset of *clickhouse.Client used to persist resolver caches.
type cachePersister interface {
	InsertRegistryLicenseCache(ctx context.Context, registry string, entries map[string]string) error
}

// resolveViaRegistries fills in licenses that are still unknown after the GitHub
// pass by asking each registry resolver, then persists the resolver caches.
func resolveViaRegistries(ctx context.Context, store cachePersister, resolvers []registryResolver, purls, licenses []string) {
	for name, n := range applyRegistryResolvers(ctx, resolvers, purls, licenses) {
		if n > 0 {
			log.Printf("  Resolved %d unknown licenses via %s registry", n, name)
		}
	}
	if store == nil {
		return
	}
	for _, rr := range resolvers {
		if entries := rr.resolver.CacheEntries(); len(entries) > 0 {
			_ = store.InsertRegistryLicenseCache(ctx, rr.name, entries)
		}
	}
}

// applyRegistryResolvers offers every package with an unknown license to each
// resolver in order and writes resolved expressions back into licenses.
// Resolvers ignore purls of other ecosystems, so all packages can be offered to
// all resolvers. Returns the number of packages resolved per resolver name.
func applyRegistryResolvers(ctx context.Context, resolvers []registryResolver, purls, licenses []string) map[string]int {
	counts := make(map[string]int, len(resolvers))
	for _, rr := range resolvers {
		for i, lic := range licenses {
			if !isUnknownLicense(lic) {
				continue
			}
			if i >= len(purls) || purls[i] == "" {
				continue
			}
			if spdx := rr.resolver.Resolve(ctx, purls[i]); spdx != "" {
				licenses[i] = spdx
				counts[rr.name]++
			}
		}
	}
	return counts
}

func isUnknownLicense(lic string) bool {
	return lic == "" || lic == "NOASSERTION" || lic == "NONE"
}
