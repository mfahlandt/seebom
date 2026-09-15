// Package licensetext provides a best-effort classifier for license texts.
//
// It is used when a forge (e.g. GitHub) reports a license file as "Other"
// because of a custom preamble, reformatted whitespace, or an unusual
// copyright line. The classifier matches distinctive phrases of common OSS
// licenses and returns an SPDX identifier, or "" if nothing matches. It is
// intentionally permissive: a slightly reworded MIT text is still MIT.
package licensetext

import (
	"regexp"
	"sort"
	"strings"
)

var (
	nonWordRe    = regexp.MustCompile(`[^a-z0-9.]+`)
	multiSpaceRe = regexp.MustCompile(`\s+`)
)

// normalize lower-cases the text, strips punctuation (except dots for
// version numbers) and collapses whitespace so phrase matching is robust to
// line wrapping and formatting differences.
func normalize(text string) string {
	t := strings.ToLower(text)
	t = strings.ReplaceAll(t, "\u201c", " ")
	t = strings.ReplaceAll(t, "\u201d", " ")
	t = nonWordRe.ReplaceAllString(t, " ")
	t = multiSpaceRe.ReplaceAllString(t, " ")
	return strings.TrimSpace(t)
}

// Detect returns the SPDX identifier for a license text, or "" if the text
// does not match any known license. If the text contains several distinct
// licenses (dual licensing), they are joined with " OR ".
func Detect(text string) string {
	t := normalize(text)
	if len(t) < 40 {
		return ""
	}

	var found []string
	add := func(id string) {
		for _, f := range found {
			if f == id {
				return
			}
		}
		found = append(found, id)
	}

	// --- Permissive -------------------------------------------------------

	if has(t, "apache license") && (has(t, "version 2.0") || has(t, "version 2 0")) {
		add("Apache-2.0")
	}

	if has(t, "redistribution and use in source and binary forms") {
		switch {
		case has(t, "all advertising materials mentioning features or use of this software"):
			add("BSD-4-Clause")
		case has(t, "neither the name") || has(t, "endorse or promote products"):
			add("BSD-3-Clause")
		default:
			add("BSD-2-Clause")
		}
	}

	if has(t, "permission is hereby granted free of charge to any person obtaining a copy") &&
		has(t, "without restriction") {
		add("MIT")
	}

	if has(t, "permission to use copy modify and or distribute this software for any purpose with or without fee is hereby granted") {
		if has(t, "provided that the above copyright notice and this permission notice appear in all copies") {
			add("ISC")
		} else {
			add("0BSD")
		}
	}

	if has(t, "this software is provided as is without any express or implied warranty") &&
		has(t, "altered source versions must be plainly marked as such") {
		add("Zlib")
	}

	if has(t, "boost software license") && has(t, "version 1.0") {
		add("BSL-1.0")
	}

	if has(t, "this is free and unencumbered software released into the public domain") {
		add("Unlicense")
	}

	if has(t, "cc0 1.0 universal") || has(t, "creative commons legal code cc0") {
		add("CC0-1.0")
	}

	if has(t, "postgresql license") ||
		(has(t, "permission to use copy modify and distribute this software and its documentation for any purpose without fee and without a written agreement is hereby granted")) {
		add("PostgreSQL")
	}

	// --- Weak copyleft ----------------------------------------------------

	if has(t, "mozilla public license") {
		switch {
		case has(t, "version 2.0") || has(t, "version 2 0"):
			add("MPL-2.0")
		case has(t, "version 1.1"):
			add("MPL-1.1")
		}
	}

	if has(t, "eclipse public license") {
		switch {
		case has(t, "v 2.0") || has(t, "version 2.0"):
			add("EPL-2.0")
		case has(t, "v 1.0") || has(t, "version 1.0"):
			add("EPL-1.0")
		}
	}

	// --- GNU family --------------------------------------------------------
	// Order matters: AGPL and LGPL texts also contain the words "general public license".

	later := has(t, "any later version")
	switch {
	case has(t, "gnu affero general public license"):
		if has(t, "version 3") {
			add(orLater("AGPL-3.0", later))
		}
	case has(t, "gnu lesser general public license"):
		switch {
		case has(t, "version 3"):
			add(orLater("LGPL-3.0", later))
		case has(t, "version 2.1"):
			add(orLater("LGPL-2.1", later))
		}
	case has(t, "gnu library general public license"):
		if has(t, "version 2") {
			add(orLater("LGPL-2.0", later))
		}
	case has(t, "gnu general public license"):
		switch {
		case has(t, "version 3"):
			add(orLater("GPL-3.0", later))
		case has(t, "version 2"):
			add(orLater("GPL-2.0", later))
		}
	}

	sort.Strings(found)
	return strings.Join(found, " OR ")
}

func has(t, phrase string) bool {
	return strings.Contains(t, phrase)
}

func orLater(base string, later bool) string {
	if later {
		return base + "-or-later"
	}
	return base + "-only"
}
