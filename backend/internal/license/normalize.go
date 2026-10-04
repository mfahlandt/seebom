package license

import (
	"regexp"
	"strings"
)

// spdxAliases maps common free-text license spellings, as found in npm
// package.json files, Maven POMs and hand-written SBOMs, onto SPDX IDs. Keys
// are lower-case with collapsed whitespace.
//
// Only unambiguous spellings belong here. "BSD" (which clause count?) and
// "Public Domain" (no SPDX ID) are deliberately absent: guessing would turn an
// unapproved license into an approved one without anyone having decided so.
var spdxAliases = map[string]string{
	"apache 2":                                 "Apache-2.0",
	"apache 2.0":                               "Apache-2.0",
	"apache-2":                                 "Apache-2.0",
	"apache2":                                  "Apache-2.0",
	"apache license 2.0":                       "Apache-2.0",
	"apache license, version 2.0":              "Apache-2.0",
	"apache license version 2.0":               "Apache-2.0",
	"apache software license 2.0":              "Apache-2.0",
	"the apache license, version 2.0":          "Apache-2.0",
	"the apache software license, version 2.0": "Apache-2.0",
	"asl 2.0":                                  "Apache-2.0",
	"mit license":                              "MIT",
	"the mit license":                          "MIT",
	"isc license":                              "ISC",
	"bsd 2-clause":                             "BSD-2-Clause",
	"bsd 2-clause license":                     "BSD-2-Clause",
	"2-clause bsd license":                     "BSD-2-Clause",
	"simplified bsd license":                   "BSD-2-Clause",
	"bsd 3-clause":                             "BSD-3-Clause",
	"bsd 3-clause license":                     "BSD-3-Clause",
	"3-clause bsd license":                     "BSD-3-Clause",
	"new bsd license":                          "BSD-3-Clause",
	"modified bsd license":                     "BSD-3-Clause",
	"mpl 2.0":                                  "MPL-2.0",
	"mpl-2":                                    "MPL-2.0",
	"mozilla public license 2.0":               "MPL-2.0",
	"mozilla public license, version 2.0":      "MPL-2.0",
	"epl 1.0":                                  "EPL-1.0",
	"eclipse public license 1.0":               "EPL-1.0",
	"eclipse public license - v 1.0":           "EPL-1.0",
	"epl 2.0":                                  "EPL-2.0",
	"eclipse public license 2.0":               "EPL-2.0",
	"eclipse public license - v 2.0":           "EPL-2.0",
	"gplv2":                                    "GPL-2.0-only",
	"gplv3":                                    "GPL-3.0-only",
	"lgplv2.1":                                 "LGPL-2.1-only",
	"lgplv3":                                   "LGPL-3.0-only",
	"agplv3":                                   "AGPL-3.0-only",
	"the unlicense":                            "Unlicense",
	"cc0":                                      "CC0-1.0",
	"cc0 1.0":                                  "CC0-1.0",
	"cc0 1.0 universal":                        "CC0-1.0",
}

// ccPattern matches Creative Commons spellings such as "CC BY-SA 4.0" or
// "CC BY 3.0"; the SPDX form joins every part with '-'.
var ccPattern = regexp.MustCompile(`(?i)^cc[ -]by((?:[ -](?:sa|nc|nd))*)[ -](\d\.\d)$`)

// exprSeparator splits an SPDX expression into leaves while keeping the
// operators and parentheses, so they can be reassembled untouched.
var exprSeparator = regexp.MustCompile(`(?i)\s+(?:AND|OR)\s+|[()]`)

var withSeparator = regexp.MustCompile(`(?i)\s+WITH\s+`)

// Normalize rewrites free-text license spellings inside a license string or
// SPDX expression to SPDX IDs ("MPL 2.0" → "MPL-2.0",
// "CC BY-SA 4.0 AND MIT" → "CC-BY-SA-4.0 AND MIT"). Anything it does not
// recognise, including valid SPDX IDs, is returned unchanged.
func Normalize(expr string) string {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return expr
	}
	if spdx, ok := normalizeLeaf(trimmed); ok {
		return spdx
	}

	var b strings.Builder
	changed := false
	last := 0
	for _, loc := range exprSeparator.FindAllStringIndex(trimmed, -1) {
		changed = writeLeaf(&b, trimmed[last:loc[0]]) || changed
		b.WriteString(trimmed[loc[0]:loc[1]])
		last = loc[1]
	}
	changed = writeLeaf(&b, trimmed[last:]) || changed
	if !changed {
		return expr
	}
	return b.String()
}

// writeLeaf writes one expression leaf, normalised if possible, preserving its
// surrounding whitespace. It reports whether the leaf was rewritten.
func writeLeaf(b *strings.Builder, leaf string) bool {
	core := strings.TrimSpace(leaf)
	if core == "" {
		b.WriteString(leaf)
		return false
	}
	start := strings.Index(leaf, core)
	b.WriteString(leaf[:start])
	spdx, ok := normalizeLeaf(core)
	if !ok {
		spdx = core
	}
	b.WriteString(spdx)
	b.WriteString(leaf[start+len(core):])
	return ok
}

// normalizeLeaf maps a single license (optionally "X WITH exception") to its
// SPDX ID.
func normalizeLeaf(leaf string) (string, bool) {
	base, exception, hasWith := leaf, "", false
	if loc := withSeparator.FindStringIndex(leaf); loc != nil {
		base, exception, hasWith = leaf[:loc[0]], leaf[loc[1]:], true
	}
	key := strings.ToLower(strings.Join(strings.Fields(base), " "))
	spdx, ok := spdxAliases[key]
	if !ok {
		m := ccPattern.FindStringSubmatch(key)
		if m == nil {
			return "", false
		}
		spdx = "CC-BY" + strings.ToUpper(strings.NewReplacer(" ", "-").Replace(m[1])) + "-" + m[2]
	}
	if hasWith {
		spdx += " WITH " + strings.TrimSpace(exception)
	}
	return spdx, true
}
