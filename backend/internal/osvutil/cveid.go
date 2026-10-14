package osvutil

import (
	"regexp"
	"strings"
)

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// IsCVE reports whether id is a CVE identifier (CVE-YYYY-NNNN…).
func IsCVE(id string) bool {
	return cvePattern.MatchString(id)
}

// CVEID returns the CVE identifier of a finding (#412): vulnID itself when it
// is a CVE, otherwise the first CVE among its OSV aliases, otherwise "".
// For Go, npm, PyPI and most other ecosystems OSV's primary id is GHSA-…,
// GO-… or PYSEC-… and the CVE — the id customers and auditors search for —
// is only an alias.
//
// Several CVE aliases are rare but possible (a merged advisory); the
// lexicographically smallest one wins so the answer does not depend on the
// order OSV happened to list them in.
func CVEID(vulnID string, aliases []string) string {
	if IsCVE(vulnID) {
		return vulnID
	}
	best := ""
	for _, a := range aliases {
		a = strings.TrimSpace(a)
		if IsCVE(a) && (best == "" || a < best) {
			best = a
		}
	}
	return best
}
