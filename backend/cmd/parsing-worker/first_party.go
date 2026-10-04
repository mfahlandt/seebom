package main

import "strings"

// yarnWorkspaceVersion is the version Yarn Berry gives packages of the
// project's own workspace in its lockfile, and SBOM generators copy it.
const yarnWorkspaceVersion = "0.0.0-use.local"

// licenseCheckSkips returns the package indices that are excluded from the
// license compliance check: the SBOM's root package(s) and the project's own
// Yarn workspace packages. Both are first-party code, not dependencies — no
// registry knows their license, so checking them only adds NOASSERTION noise.
// They stay in sbom_packages; only the compliance rows ignore them.
func licenseCheckSkips(roots []uint32, purls []string) []uint32 {
	skips := append([]uint32(nil), roots...)
	for i, purl := range purls {
		if isYarnWorkspacePURL(purl) {
			skips = append(skips, uint32(i))
		}
	}
	return skips
}

func isYarnWorkspacePURL(purl string) bool {
	if !strings.HasPrefix(purl, "pkg:npm/") {
		return false
	}
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	return strings.HasSuffix(purl, "@"+yarnWorkspaceVersion)
}
