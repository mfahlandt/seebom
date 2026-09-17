package cyclonedx

import "testing"

// #332: source_repo/source_ref extraction from metadata.component.

func parseSourceDoc(t *testing.T, doc string) (repo, ref string) {
	t.Helper()
	res, err := Parse([]byte(doc), "test.cdx.json", "hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return res.SBOM.SourceRepo, res.SBOM.SourceRef
}

func TestSourceRepoFromMetadataVCS(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"type": "application",
				"name": "example-app",
				"externalReferences": [
					{"type": "website", "url": "https://example-app.dev"},
					{"type": "vcs", "url": "https://github.com/example-org/example-app"}
				]
			}
		},
		"components": []
	}`)

	if repo != "https://github.com/example-org/example-app" || ref != "" {
		t.Errorf("got (%q, %q), want (https://github.com/example-org/example-app, )", repo, ref)
	}
}

func TestSourceRepoRefFromPedigree(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"type": "application",
				"name": "app",
				"externalReferences": [
					{"type": "vcs", "url": "git+https://github.com/org/app.git"}
				],
				"pedigree": {
					"commits": [
						{"uid": "7f3a9c2e8b1d4f6a0c5e9b2d7a4f1c8e3b6d9a0f"},
						{"uid": "older-commit-must-not-win"}
					]
				}
			}
		},
		"components": []
	}`)

	if repo != "https://github.com/org/app" {
		t.Errorf("repo = %q, want https://github.com/org/app", repo)
	}
	if ref != "7f3a9c2e8b1d4f6a0c5e9b2d7a4f1c8e3b6d9a0f" {
		t.Errorf("ref = %q, want the first pedigree commit", ref)
	}
}

// A ref carried inline in the vcs URL outranks pedigree: the URL states what
// the reference *is*, pedigree only lists commits that contributed.
func TestSourceRepoInlineRefBeatsPedigree(t *testing.T) {
	_, ref := parseSourceDoc(t, `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"type": "application",
				"name": "app",
				"externalReferences": [
					{"type": "vcs", "url": "git+https://github.com/org/app.git@v2.0.0"}
				],
				"pedigree": {"commits": [{"uid": "abc1234"}]}
			}
		},
		"components": []
	}`)

	if ref != "v2.0.0" {
		t.Errorf("ref = %q, want v2.0.0 (inline URL ref must outrank pedigree)", ref)
	}
}

// vcs references on list components belong to dependencies, not the product.
func TestSourceRepoIgnoresComponentVCS(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {"type": "application", "name": "app"}
		},
		"components": [
			{
				"type": "library",
				"name": "dep",
				"externalReferences": [
					{"type": "vcs", "url": "https://github.com/wrong/repo"}
				]
			}
		]
	}`)

	if repo != "" || ref != "" {
		t.Errorf("dependency vcs leaked into product: (%q, %q)", repo, ref)
	}
}

func TestSourceRepoNoMetadataComponent(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {},
		"components": [{"type": "library", "name": "dep"}]
	}`)

	if repo != "" || ref != "" {
		t.Errorf("got (%q, %q) without a metadata.component", repo, ref)
	}
}

// Pedigree alone (no vcs reference) yields nothing: a commit without a
// repository is not actionable, and guessing the repo from elsewhere risks
// pairing the ref with the wrong codebase.
func TestSourceRepoPedigreeWithoutVCSYieldsNothing(t *testing.T) {
	repo, ref := parseSourceDoc(t, `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"type": "application",
				"name": "app",
				"pedigree": {"commits": [{"uid": "abc1234"}]}
			}
		},
		"components": []
	}`)

	if repo != "" || ref != "" {
		t.Errorf("got (%q, %q), want empty — a ref without a repo is not actionable", repo, ref)
	}
}
