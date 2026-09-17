package sourcerepo

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantRepo string
		wantRef  string
	}{
		// The SPDX downloadLocation zoo.
		{"spdx git+https with ref", "git+https://github.com/x/y.git@v1.2.3", "https://github.com/x/y", "v1.2.3"},
		{"spdx git+https no ref", "git+https://github.com/x/y.git", "https://github.com/x/y", ""},
		{"spdx git+ssh", "git+ssh://git@github.com/x/y.git", "https://github.com/x/y", ""},
		{"git scheme", "git://github.com/x/y.git", "https://github.com/x/y", ""},
		{"plain https", "https://github.com/x/y", "https://github.com/x/y", ""},
		{"plain https .git", "https://github.com/x/y.git", "https://github.com/x/y", ""},
		{"https with @ref", "https://github.com/x/y@abc1234", "https://github.com/x/y", "abc1234"},
		{"ssh scheme with user", "ssh://git@github.com/x/y", "https://github.com/x/y", ""},
		{"scp-like", "git@github.com:x/y.git", "https://github.com/x/y", ""},
		{"http kept as https host", "http://internal.git.corp/x/y", "https://internal.git.corp/x/y", ""},

		// Forge browse URLs.
		{"github tree", "https://github.com/x/y/tree/main", "https://github.com/x/y", "main"},
		{"gitlab dash tree", "https://gitlab.com/x/y/-/tree/v2.0", "https://gitlab.com/x/y", "v2.0"},
		{"gitea src branch", "https://gitea.io/x/y/src/branch/dev", "https://gitea.io/x/y", "dev"},

		// Ref via fragment (fallback only).
		{"fragment ref", "https://github.com/x/y#v1.0.0", "https://github.com/x/y", "v1.0.0"},
		{"at-ref outranks fragment", "https://github.com/x/y@sha1#v9", "https://github.com/x/y", "sha1"},

		// Monorepo-ish deep path is preserved: guessing the repo boundary
		// wrong would send tooling to clone the wrong thing.
		{"deep path preserved", "https://gitlab.com/group/sub/repo.git", "https://gitlab.com/group/sub/repo", ""},

		// Everything that must map to unknown.
		{"empty", "", "", ""},
		{"whitespace", "   ", "", ""},
		{"noassertion", "NOASSERTION", "", ""},
		{"noassertion lower", "noassertion", "", ""},
		{"none", "NONE", "", ""},
		{"bare word", "local", "", ""},
		{"file path", "/home/build/src", "", ""},
		{"file scheme", "file:///src/app", "", ""},
		{"oci image", "oci://registry.io/img:tag", "", ""},
		{"purl is not a repo", "pkg:golang/github.com/x/y@v1.0.0", "", ""},
		{"bare host", "https://github.com", "", ""},
		{"bare host slash", "https://github.com/", "", ""},

		// Credentials must never survive into the stored value.
		{"userinfo stripped", "https://token:secret@github.com/x/y", "https://github.com/x/y", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, ref := Normalize(tt.in)
			if repo != tt.wantRepo || ref != tt.wantRef {
				t.Errorf("Normalize(%q) = (%q, %q), want (%q, %q)",
					tt.in, repo, ref, tt.wantRepo, tt.wantRef)
			}
		})
	}
}

// The stored form must be stable: normalising an already-normalised value has
// to be a no-op, otherwise a PATCH round-trip (read, write back) would mutate
// data.
func TestNormalizeIsIdempotent(t *testing.T) {
	inputs := []string{
		"git+https://github.com/x/y.git@v1.2.3",
		"git@gitlab.com:group/repo.git",
		"https://github.com/x/y/tree/main",
	}
	for _, in := range inputs {
		repo1, _ := Normalize(in)
		repo2, ref2 := Normalize(repo1)
		if repo2 != repo1 || ref2 != "" {
			t.Errorf("Normalize is not idempotent for %q: %q -> (%q, %q)", in, repo1, repo2, ref2)
		}
	}
}

func TestIsValidRepoURL(t *testing.T) {
	valid := []string{
		"https://github.com/x/y",
		"http://git.corp.internal/team/svc",
		"https://gitlab.com/group/sub/repo",
	}
	for _, s := range valid {
		if !IsValidRepoURL(s) {
			t.Errorf("IsValidRepoURL(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"github.com/x/y",                   // no scheme
		"git@github.com:x/y.git",           // scp form is for extraction, not explicit input
		"ssh://git@github.com/x/y",         // non-http scheme
		"https://github.com",               // no path
		"https://github.com/",              // empty path
		"https://user:pass@github.com/x/y", // credentials
		"file:///etc/passwd",               // local path
		"javascript:alert(1)",              // not even close
		"pkg:golang/github.com/x/y@v1.0.0", // purl
	}
	for _, s := range invalid {
		if IsValidRepoURL(s) {
			t.Errorf("IsValidRepoURL(%q) = true, want false", s)
		}
	}
}

func TestIsValidRef(t *testing.T) {
	valid := []string{
		"main", "v1.2.3", "abc1234", "feature/foo-bar",
		"7f3a9c2e8b1d4f6a0c5e9b2d7a4f1c8e3b6d9a0f", // full SHA
	}
	for _, s := range valid {
		if !IsValidRef(s) {
			t.Errorf("IsValidRef(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"has space",
		"tab\tchar",
		"new\nline",
		string(make([]byte, 300)), // over length cap (NUL bytes also invalid)
	}
	for _, s := range invalid {
		if IsValidRef(s) {
			t.Errorf("IsValidRef(%q) = true, want false", s)
		}
	}
}
