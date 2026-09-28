package spdx

import (
	"strings"
	"testing"
)

// #332: source_repo/source_ref extraction from the described root package.

func parseSourceDoc(t *testing.T, doc string) (repo, ref string) {
	t.Helper()
	res, err := Parse(strings.NewReader(doc), "test.spdx.json", "hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return res.SBOM.SourceRepo, res.SBOM.SourceRef
}

func TestSourceRepoFromRootDownloadLocation(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "example-app",
		"documentDescribes": ["SPDXRef-Package-example-app"],
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-example-app",
				"name": "example-app",
				"downloadLocation": "git+https://github.com/example-org/example-app.git@v1.2.3"
			},
			{
				"SPDXID": "SPDXRef-Package-dep",
				"name": "some-dep",
				"downloadLocation": "https://github.com/other/dependency"
			}
		]
	}`)

	if repo != "https://github.com/example-org/example-app" || ref != "v1.2.3" {
		t.Errorf("got (%q, %q), want (https://github.com/example-org/example-app, v1.2.3)", repo, ref)
	}
}

// A dependency's repo must never be attributed to the product: triage tooling
// would clone and analyse the wrong codebase.
func TestSourceRepoIgnoresDependencies(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"documentDescribes": ["SPDXRef-Package-app"],
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-app",
				"name": "app",
				"downloadLocation": "NOASSERTION"
			},
			{
				"SPDXID": "SPDXRef-Package-dep",
				"name": "tempting-dep",
				"downloadLocation": "https://github.com/wrong/repo"
			}
		]
	}`)

	if repo != "" || ref != "" {
		t.Errorf("dependency repo leaked into product: (%q, %q)", repo, ref)
	}
}

func TestSourceRepoFromDescribesRelationship(t *testing.T) {
	// Roots defined via DESCRIBES relationship instead of documentDescribes.
	repo, _ := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-app",
				"name": "app",
				"downloadLocation": "git://github.com/org/app.git"
			}
		],
		"relationships": [
			{
				"spdxElementId": "SPDXRef-DOCUMENT",
				"relationshipType": "DESCRIBES",
				"relatedSpdxElement": "SPDXRef-Package-app"
			}
		]
	}`)

	if repo != "https://github.com/org/app" {
		t.Errorf("repo = %q, want https://github.com/org/app", repo)
	}
}

func TestSourceRepoFromExternalRefFallback(t *testing.T) {
	// downloadLocation useless, but an OTHER external ref carries a vcs URL.
	repo, ref := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"documentDescribes": ["SPDXRef-Package-app"],
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-app",
				"name": "app",
				"downloadLocation": "NOASSERTION",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:golang/github.com/org/app@v1.0.0"
					},
					{
						"referenceCategory": "OTHER",
						"referenceType": "vcs",
						"referenceLocator": "https://github.com/org/app/tree/main"
					}
				]
			}
		]
	}`)

	if repo != "https://github.com/org/app" || ref != "main" {
		t.Errorf("got (%q, %q), want (https://github.com/org/app, main)", repo, ref)
	}
}

// A purl is a package identity, not a clonable repository — it must not be
// misread as one even when it is the only external ref present.
func TestSourceRepoPURLIsNotARepo(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"documentDescribes": ["SPDXRef-Package-app"],
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-app",
				"name": "app",
				"downloadLocation": "NOASSERTION",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:golang/github.com/org/app@v1.0.0"
					}
				]
			}
		]
	}`)

	if repo != "" || ref != "" {
		t.Errorf("purl was misread as repo: (%q, %q)", repo, ref)
	}
}

func TestSourceRepoNoRoots(t *testing.T) {
	// Document without documentDescribes or DESCRIBES and without a usable
	// documentNamespace: nothing is the product, so nothing may be guessed —
	// in particular not from packages[0].
	repo, ref := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"documentNamespace": "https://anchore.com/syft/dir/app-3b1f0e5a-8c2d-4e9f-a1b2-c3d4e5f6a7b8",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-a",
				"name": "a",
				"downloadLocation": "https://github.com/org/a"
			}
		]
	}`)

	if repo != "" || ref != "" {
		t.Errorf("guessed a repo without any described root: (%q, %q)", repo, ref)
	}
}

// #355: the shape of every one of the 500 CNCF SBOMs surveyed — no DESCRIBES,
// no documentDescribes, packages[0] is a dependency, and the repo + release
// tag sit in documentNamespace.
func TestSourceRepoFromDocumentNamespaceFallback(t *testing.T) {
	cases := []struct {
		namespace string
		wantRepo  string
		wantRef   string
	}{
		{"https://github.com/aeraki-mesh/aeraki/releases/tag/1.1.3", "https://github.com/aeraki-mesh/aeraki", "1.1.3"},
		{"https://github.com/argoproj/argo-cd/releases/tag/v3.1.15", "https://github.com/argoproj/argo-cd", "v3.1.15"},
		{"https://github.com/backstage/backstage/releases/tag/v1.48.0", "https://github.com/backstage/backstage", "v1.48.0"},
	}
	for _, tc := range cases {
		t.Run(tc.namespace, func(t *testing.T) {
			repo, ref := parseSourceDoc(t, `{
				"spdxVersion": "SPDX-2.3",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "release-sbom",
				"documentNamespace": "`+tc.namespace+`",
				"packages": [
					{
						"SPDXID": "SPDXRef-Package-backoff",
						"name": "github.com/cenkalti/backoff/v4",
						"versionInfo": "v4.2.1",
						"downloadLocation": "https://github.com/cenkalti/backoff"
					},
					{
						"SPDXID": "SPDXRef-Package-cobra",
						"name": "github.com/spf13/cobra",
						"downloadLocation": "NOASSERTION"
					}
				]
			}`)
			if repo != tc.wantRepo || ref != tc.wantRef {
				t.Errorf("got (%q, %q), want (%q, %q)", repo, ref, tc.wantRepo, tc.wantRef)
			}
		})
	}
}

// The namespace is a *last* resort: a root package's downloadLocation is a
// statement about the product and must win even when the namespace would
// also normalise.
func TestSourceRepoRootBeatsDocumentNamespace(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"documentNamespace": "https://github.com/mirror-org/app/releases/tag/v9.9.9",
		"documentDescribes": ["SPDXRef-Package-app"],
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-app",
				"name": "app",
				"downloadLocation": "git+https://github.com/real-org/app.git@v1.2.3"
			}
		]
	}`)

	if repo != "https://github.com/real-org/app" || ref != "v1.2.3" {
		t.Errorf("namespace outranked root downloadLocation: (%q, %q)", repo, ref)
	}
}

// A declared root that carries no usable locator does not block the
// namespace fallback — the root is not *wrong*, it is silent.
func TestSourceRepoNamespaceWhenRootIsSilent(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"documentNamespace": "https://github.com/org/app/releases/tag/v2.0.0",
		"documentDescribes": ["SPDXRef-Package-app"],
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-app",
				"name": "app",
				"downloadLocation": "NOASSERTION"
			}
		]
	}`)

	if repo != "https://github.com/org/app" || ref != "v2.0.0" {
		t.Errorf("got (%q, %q), want (https://github.com/org/app, v2.0.0)", repo, ref)
	}
}

// Generator-default namespaces are opaque identifiers, not repositories.
// Storing them would put dead links in the UI and send VEXViper to clone a
// non-existent repo.
func TestSourceRepoIgnoresOpaqueDocumentNamespace(t *testing.T) {
	for _, ns := range []string{
		"https://anchore.com/syft/image/ghcr.io/org/img-9e1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8",
		"https://spdx.org/spdxdocs/example-app-0.1.0-9e1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8",
		"https://aquasecurity.github.io/trivy/0.50.0/9e1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8",
		"urn:uuid:9e1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8",
		"",
	} {
		t.Run(ns, func(t *testing.T) {
			repo, ref := parseSourceDoc(t, `{
				"spdxVersion": "SPDX-2.3",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "app",
				"documentNamespace": "`+ns+`",
				"packages": [{"SPDXID": "SPDXRef-Package-a", "name": "a", "downloadLocation": "NOASSERTION"}]
			}`)
			if repo != "" || ref != "" {
				t.Errorf("opaque namespace %q was stored as repo: (%q, %q)", ns, repo, ref)
			}
		})
	}
}
