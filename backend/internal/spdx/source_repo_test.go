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
	// Document without documentDescribes or DESCRIBES: nothing is the product,
	// so nothing may be guessed.
	repo, ref := parseSourceDoc(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
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
