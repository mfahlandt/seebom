package license

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		// Free-text spellings seen in real SBOMs.
		{"MPL 2.0", "MPL-2.0"},
		{"CC BY-SA 4.0", "CC-BY-SA-4.0"},
		{"CC BY 3.0", "CC-BY-3.0"},
		{"cc by-nc-nd 4.0", "CC-BY-NC-ND-4.0"},
		{"Apache License, Version 2.0", "Apache-2.0"},
		{"The  MIT  License", "MIT"},
		{"New BSD License", "BSD-3-Clause"},
		{"GPLv2", "GPL-2.0-only"},
		{"Apache 2.0 WITH LLVM-exception", "Apache-2.0 WITH LLVM-exception"},
		// Inside expressions, operators and parentheses survive.
		{"MIT AND CC BY-SA 4.0", "MIT AND CC-BY-SA-4.0"},
		{"(MPL 2.0 OR Apache 2.0) AND MIT", "(MPL-2.0 OR Apache-2.0) AND MIT"},
		{"mit and mpl 2.0", "mit and MPL-2.0"},
		{"Apache 2.0 with LLVM-exception", "Apache-2.0 WITH LLVM-exception"},
		// Valid SPDX and anything unrecognised is untouched.
		{"Apache-2.0", "Apache-2.0"},
		{"MIT OR Apache-2.0", "MIT OR Apache-2.0"},
		{"NOASSERTION", "NOASSERTION"},
		{"", ""},
		// Ambiguous spellings are deliberately not guessed.
		{"BSD", "BSD"},
		{"Public Domain", "Public Domain"},
		{"Remix Icon License 1.0", "Remix Icon License 1.0"},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCategorize_NormalizesFreeTextSpellings(t *testing.T) {
	if got := Categorize("MPL 2.0"); got != CategoryCopyleft {
		t.Errorf("Categorize(MPL 2.0) = %q, want copyleft", got)
	}
	if got := Categorize("Apache License, Version 2.0"); got != CategoryPermissive {
		t.Errorf("Categorize(Apache License, Version 2.0) = %q, want permissive", got)
	}
	if got := Categorize("BSD"); got != CategoryUnapproved {
		t.Errorf("Categorize(BSD) = %q, want unapproved", got)
	}
}
