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

		// #355: release / tag / commit URLs — the shapes real SPDX
		// documentNamespaces take on the CNCF corpus.
		{"github release tag", "https://github.com/argoproj/argo-cd/releases/tag/v3.1.15", "https://github.com/argoproj/argo-cd", "v3.1.15"},
		{"github release tag no v", "https://github.com/aeraki-mesh/aeraki/releases/tag/1.1.3", "https://github.com/aeraki-mesh/aeraki", "1.1.3"},
		{"github release tag with slash", "https://github.com/x/y/releases/tag/release/v1", "https://github.com/x/y", "release/v1"},
		{"github release tag trailing slash", "https://github.com/backstage/backstage/releases/tag/v1.48.0/", "https://github.com/backstage/backstage", "v1.48.0"},
		{"github release download", "https://github.com/x/y/releases/download/v1.2.3/y_1.2.3_linux_amd64.tar.gz", "https://github.com/x/y", "v1.2.3"},
		{"github releases listing", "https://github.com/x/y/releases", "https://github.com/x/y", ""},
		{"github tags listing", "https://github.com/x/y/tags", "https://github.com/x/y", ""},
		{"github commit", "https://github.com/x/y/commit/7f3a9c2e8b1d4f6a0c5e9b2d7a4f1c8e3b6d9a0f", "https://github.com/x/y", "7f3a9c2e8b1d4f6a0c5e9b2d7a4f1c8e3b6d9a0f"},
		{"github commits on branch", "https://github.com/x/y/commits/main", "https://github.com/x/y", "main"},
		{"gitlab dash tags", "https://gitlab.com/g/sub/y/-/tags/v2.0", "https://gitlab.com/g/sub/y", "v2.0"},
		{"gitlab dash releases", "https://gitlab.com/g/y/-/releases/v2.0", "https://gitlab.com/g/y", "v2.0"},
		{"gitlab dash commit", "https://gitlab.com/g/y/-/commit/abc1234", "https://gitlab.com/g/y", "abc1234"},
		{"gitea src tag", "https://codeberg.org/x/y/src/tag/v1.0", "https://codeberg.org/x/y", "v1.0"},
		{"host lowercased", "https://GitHub.com/x/y", "https://github.com/x/y", ""},

		// A repo that happens to be *named* like a marker must not be cut.
		{"repo named releases", "https://gitlab.com/releases/foo", "https://gitlab.com/releases/foo", ""},

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
		"https://github.com/argoproj/argo-cd/releases/tag/v3.1.15",
		"https://gitlab.com/g/y/-/commit/abc1234",
	}
	for _, in := range inputs {
		repo1, _ := Normalize(in)
		repo2, ref2 := Normalize(repo1)
		if repo2 != repo1 || ref2 != "" {
			t.Errorf("Normalize is not idempotent for %q: %q -> (%q, %q)", in, repo1, repo2, ref2)
		}
	}
}

// #355: NormalizeStrict is the gate for documentNamespace. It must accept
// what real CNCF SBOMs carry there and reject every generator-default
// namespace, because a wrong repo is worse than none.
func TestNormalizeStrict(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantRepo string
		wantRef  string
	}{
		// Real documentNamespace values from the CNCF corpus.
		{"argo-cd", "https://github.com/argoproj/argo-cd/releases/tag/v3.1.15", "https://github.com/argoproj/argo-cd", "v3.1.15"},
		{"aeraki", "https://github.com/aeraki-mesh/aeraki/releases/tag/1.1.3", "https://github.com/aeraki-mesh/aeraki", "1.1.3"},
		{"backstage", "https://github.com/backstage/backstage/releases/tag/v1.48.0", "https://github.com/backstage/backstage", "v1.48.0"},
		// Known forge host: a bare owner/repo path is enough.
		{"github bare repo", "https://github.com/x/y", "https://github.com/x/y", ""},
		{"gitlab group path", "https://gitlab.com/g/sub/y", "https://gitlab.com/g/sub/y", ""},
		// Unknown host, but structurally a repo.
		{"self-hosted .git", "https://git.corp.example/team/svc.git", "https://git.corp.example/team/svc", ""},
		{"self-hosted gitlab release", "https://gitlab.corp.example/g/y/-/releases/v1", "https://gitlab.corp.example/g/y", "v1"},
		{"self-hosted scp", "git@git.corp.example:team/svc.git", "https://git.corp.example/team/svc", ""},
		{"self-hosted git+https", "git+https://git.corp.example/team/svc@v2", "https://git.corp.example/team/svc", "v2"},

		// Generator-default namespaces: must yield nothing.
		{"syft dir", "https://anchore.com/syft/dir/argo-cd-3b1f0e5a-8c2d-4e9f-a1b2-c3d4e5f6a7b8", "", ""},
		{"syft image", "https://anchore.com/syft/image/ghcr.io/org/img-9e1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8", "", ""},
		{"spdx.org spdxdocs", "https://spdx.org/spdxdocs/example-app-0.1.0-9e1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8", "", ""},
		{"trivy", "https://aquasecurity.github.io/trivy/0.50.0/9e1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8", "", ""},
		{"bom (k8s)", "https://spdx.org/spdxdocs/k8s-releng-bom-9e1a2b3c", "", ""},
		{"kusari mikebom", "https://mikebom.kusari.dev/spdx/2E2NYV7S7OGESAEMK3ETQ3I5T2TNR3JF", "", ""},
		{"operator-chosen namespace", "https://bomhort.example.com/sbom/catalogue/graduated/prometheus-2.51.0", "", ""},
		{"urn uuid", "urn:uuid:9e1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8", "", ""},
		{"cdx serial", "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", "", ""},
		{"vendor site", "https://example.com/products/app", "", ""},
		{"registry tarball", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "", ""},
		{"empty", "", "", ""},
		{"noassertion", "NOASSERTION", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, ref := NormalizeStrict(tt.in)
			if repo != tt.wantRepo || ref != tt.wantRef {
				t.Errorf("NormalizeStrict(%q) = (%q, %q), want (%q, %q)",
					tt.in, repo, ref, tt.wantRepo, tt.wantRef)
			}
		})
	}
}

// Whatever NormalizeStrict accepts, Normalize must accept identically — the
// strict variant only ever narrows, never rewrites.
func TestNormalizeStrictIsSubsetOfNormalize(t *testing.T) {
	inputs := []string{
		"https://github.com/argoproj/argo-cd/releases/tag/v3.1.15",
		"https://anchore.com/syft/dir/foo-uuid",
		"git+https://git.corp.example/team/svc@v2",
		"https://example.com/products/app",
	}
	for _, in := range inputs {
		sr, sf := NormalizeStrict(in)
		if sr == "" {
			continue
		}
		r, f := Normalize(in)
		if r != sr || f != sf {
			t.Errorf("NormalizeStrict(%q) = (%q, %q) but Normalize = (%q, %q)", in, sr, sf, r, f)
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
