package projectgroup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnerFromRepo(t *testing.T) {
	cases := map[string]string{
		"https://github.com/argoproj/argo-cd":                    "argoproj",
		"https://gitlab.example.com/payments/core/ledger":        "payments/core",
		"https://dev.azure.com/acme/Payments/_git/ledger":        "acme/Payments",
		"https://acme.visualstudio.com/Payments/_git/ledger":     "acme/Payments",
		"https://bitbucket.acme.local/scm/PAY/ledger":            "PAY",
		"https://bitbucket.acme.local/projects/PAY/repos/ledger": "PAY",
		"https://github.com/argoproj":                            "",
		"":                                                       "",
		"not a url":                                              "",
	}
	for in, want := range cases {
		if got := ownerFromRepo(in); got != want {
			t.Errorf("ownerFromRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOwnerFromDocumentName(t *testing.T) {
	cases := map[string]string{
		"argoproj/argo-workflows v3.7.16": "argoproj",
		"aeraki-mesh/meta-protocol-proxy": "aeraki-mesh",
		"ghcr.io/argoproj/argocd v3.4.7":  "argoproj",
		"group/sub/repo 1.0":              "group/sub",
		"ledger 2.0.1":                    "",
		"https://example.com/app 1.0":     "",
		"":                                "",
	}
	for in, want := range cases {
		if got := ownerFromDocumentName(in); got != want {
			t.Errorf("ownerFromDocumentName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOwnerFromPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:maven/com.acme.payments/ledger@2.0.1":                         "com.acme.payments",
		"pkg:npm/%40acme/ui@1.0.0":                                         "acme",
		"pkg:npm/@acme/ui@1.0.0":                                           "acme",
		"pkg:npm/left-pad@1.3.0":                                           "",
		"pkg:golang/github.com/argoproj/argo-cd/v3@v3.4.7":                 "argoproj",
		"pkg:golang/github.com/argoproj/argo-cd@v2.0.0":                    "argoproj",
		"pkg:github/argoproj/argo-cd@v3.4.7":                               "argoproj",
		"pkg:oci/argocd@sha256:abc?repository_url=quay.io/argoproj/argocd": "argoproj",
		"pkg:docker/argoproj/argocd@v3":                                    "argoproj",
		"pkg:generic/firmware@1.0":                                         "",
		"pkg:pypi/requests@2.31.0":                                         "",
		"not-a-purl":                                                       "",
	}
	for in, want := range cases {
		if got := ownerFromPURL(in); got != want {
			t.Errorf("ownerFromPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOwnerKeyOrder(t *testing.T) {
	s := Signals{
		SourceRepo:   "https://github.com/argoproj/argo-cd",
		DocumentName: "other/thing 1.0",
		RootPURL:     "pkg:maven/com.acme/x@1",
		Supplier:     "ACME",
	}
	if o, src := ownerKey(s); o != "argoproj" || src != SourceRepo {
		t.Errorf("repo must win: (%q, %q)", o, src)
	}
	s.SourceRepo = ""
	if o, src := ownerKey(s); o != "other" || src != SourceDocument {
		t.Errorf("document second: (%q, %q)", o, src)
	}
	s.DocumentName = "plain 1.0"
	if o, src := ownerKey(s); o != "com.acme" || src != SourcePURL {
		t.Errorf("purl third: (%q, %q)", o, src)
	}
	s.RootPURL = ""
	if o, src := ownerKey(s); o != "ACME" || src != SourceSupplier {
		t.Errorf("supplier last: (%q, %q)", o, src)
	}
}

// The CNCF corpus as ingested locally from cncf-project-sboms and
// cncf-subproject-sboms: the folder names differ (argo/ vs argo-cd/,
// aeraki-mesh/ vs aeraki/), the repository owner does not.
func cncfSignals() []Signals {
	repo := func(project, r string) Signals {
		return Signals{Project: project, SourceRepo: "https://github.com/" + r}
	}
	return []Signals{
		repo("argo", "argoproj/argo-cd"),
		repo("argo-cd/argo-workflows", "argoproj/argo-workflows"),
		repo("argo-cd/argo-rollouts", "argoproj/argo-rollouts"),
		repo("aeraki-mesh", "aeraki-mesh/aeraki"),
		repo("aeraki/meta-protocol-proxy", "aeraki-mesh/meta-protocol-proxy"),
		repo("antrea", "antrea-io/antrea"),
		repo("antrea/theia", "antrea-io/theia"),
		repo("akri", "project-akri/akri"),
		repo("akri/examples", "project-akri/examples"),
		repo("agones", "agones-dev/agones"),
		repo("apicurio-registry", "Apicurio/apicurio-registry"),
	}
}

func TestResolveCNCF(t *testing.T) {
	got := Resolve(cncfSignals(), nil)

	want := map[string]string{
		"argo-cd/argo-workflows":     "argo",
		"argo-cd/argo-rollouts":      "argo",
		"aeraki/meta-protocol-proxy": "aeraki-mesh",
		"antrea/theia":               "antrea",
		"akri/examples":              "akri",
	}
	if len(got) != len(want) {
		t.Errorf("got %d assignments, want %d: %+v", len(got), len(want), got)
	}
	for project, parent := range want {
		a, ok := got[project]
		if !ok || a.Parent != parent {
			t.Errorf("%s → %+v, want parent %s", project, a, parent)
			continue
		}
		if a.Source != SourceRepo {
			t.Errorf("%s source = %q, want repo", project, a.Source)
		}
	}
	for _, standalone := range []string{"argo", "agones", "apicurio-registry", "antrea"} {
		if a, ok := got[standalone]; ok {
			t.Errorf("%s must have no parent, got %+v", standalone, a)
		}
	}
}

// Several top-level projects with the same owner: a shared org. Nothing is
// grouped automatically, not even the subproject.
func TestResolveAmbiguousOwnerGroupsNothing(t *testing.T) {
	got := Resolve([]Signals{
		{Project: "cluster-api", SourceRepo: "https://github.com/kubernetes-sigs/cluster-api"},
		{Project: "kind", SourceRepo: "https://github.com/kubernetes-sigs/kind"},
		{Project: "kind/node-image", SourceRepo: "https://github.com/kubernetes-sigs/kind-node"},
	}, nil)
	if len(got) != 0 {
		t.Errorf("ambiguous owner must group nothing, got %+v", got)
	}
}

// No top-level project: the family is grouped under the owner, but only from
// two members on.
func TestResolveFamilyWithoutHead(t *testing.T) {
	got := Resolve([]Signals{
		{Project: "payments/ledger", RootPURL: "pkg:maven/com.acme.payments/ledger@2.0"},
		{Project: "payments/api", RootPURL: "pkg:maven/com.acme.payments/api@1.4"},
		{Project: "lonely/thing", RootPURL: "pkg:maven/com.acme.lonely/thing@1"},
	}, nil)
	for _, p := range []string{"payments/ledger", "payments/api"} {
		if a := got[p]; a.Parent != "com.acme.payments" || a.Source != SourcePURL {
			t.Errorf("%s → %+v, want com.acme.payments via purl", p, a)
		}
	}
	if a, ok := got["lonely/thing"]; ok {
		t.Errorf("a group of one is not a group: %+v", a)
	}
}

// Industry SBOMs without any repository: supplier groups a family with a head.
func TestResolveBySupplier(t *testing.T) {
	got := Resolve([]Signals{
		{Project: "firmware", Supplier: "ACME Corp"},
		{Project: "firmware/bootloader", Supplier: "acme corp"},
	}, nil)
	if a := got["firmware/bootloader"]; a.Parent != "firmware" || a.Source != SourceSupplier {
		t.Errorf("supplier family → %+v, want firmware via supplier (case-insensitive)", a)
	}
}

func TestResolvePrecedence(t *testing.T) {
	rules := mustRules(t, `{"groups": [
		{"parent": "From Config", "match": {"projects": ["argo-cd/argo-rollouts"]}},
		{"standalone": true, "match": {"projects": ["argo-cd/pkg"]}}
	]}`)
	signals := append(cncfSignals(),
		// explicit beats tag and owner
		Signals{Project: "argo-cd/argo-events", SourceRepo: "https://github.com/argoproj/argo-events", ExplicitParent: "Argo Suite", Tags: []string{"argo"}},
		// tag beats owner
		Signals{Project: "argo-cd/argo-ui", SourceRepo: "https://github.com/argoproj/argo-ui", Tags: []string{"antrea", "unrelated"}},
		// standalone opts out of the automatic family
		Signals{Project: "argo-cd/pkg", SourceRepo: "https://github.com/argoproj/pkg"},
	)
	got := Resolve(signals, rules)

	check := func(project, parent string, src Source) {
		t.Helper()
		a, ok := got[project]
		if !ok || a.Parent != parent || a.Source != src {
			t.Errorf("%s → %+v (ok=%v), want %s via %s", project, a, ok, parent, src)
		}
	}
	check("argo-cd/argo-rollouts", "From Config", SourceConfig)
	check("argo-cd/argo-events", "Argo Suite", SourceExplicit)
	check("argo-cd/argo-ui", "antrea", SourceTag)
	check("argo-cd/argo-workflows", "argo", SourceRepo)
	if a, ok := got["argo-cd/pkg"]; ok {
		t.Errorf("standalone rule ignored: %+v", a)
	}
}

// A project never becomes its own parent, whatever the source says.
func TestResolveNoSelfParent(t *testing.T) {
	rules := mustRules(t, `{"groups": [{"parent": "argo", "match": {"projects": ["argo*"]}}]}`)
	got := Resolve([]Signals{
		{Project: "argo"},
		{Project: "argo-cd/x"},
		{Project: "self", ExplicitParent: "self", Tags: []string{"self"}},
	}, rules)
	if _, ok := got["argo"]; ok {
		t.Error("argo assigned to itself through the config rule")
	}
	if got["argo-cd/x"].Parent != "argo" {
		t.Errorf("argo-cd/x → %+v, want argo", got["argo-cd/x"])
	}
	if _, ok := got["self"]; ok {
		t.Error("explicit/tag self-parent must be ignored")
	}
}

func TestRulesMatchOwnersAndSuppliers(t *testing.T) {
	rules := mustRules(t, `{"groups": [
		{"parent": "Payments", "match": {"owners": ["COM.ACME.PAYMENTS"]}},
		{"parent": "Vendor", "match": {"suppliers": ["Initech"]}},
		{"parent": "GitLab Core", "match": {"repos": ["https://gitlab.example.com/core/*"]}}
	]}`)
	got := Resolve([]Signals{
		{Project: "ledger", RootPURL: "pkg:maven/com.acme.payments/ledger@1"},
		{Project: "printer", Supplier: "initech"},
		{Project: "api", SourceRepo: "https://gitlab.example.com/core/sub/api"},
	}, rules)
	for project, parent := range map[string]string{"ledger": "Payments", "printer": "Vendor", "api": "GitLab Core"} {
		if a := got[project]; a.Parent != parent || a.Source != SourceConfig {
			t.Errorf("%s → %+v, want %s via config", project, a, parent)
		}
	}
}

func TestParseRulesValidation(t *testing.T) {
	bad := map[string]string{
		"not json":            `{`,
		"no parent":           `{"groups": [{"match": {"projects": ["x"]}}]}`,
		"parent + standalone": `{"groups": [{"parent": "p", "standalone": true, "match": {"projects": ["x"]}}]}`,
		"empty match":         `{"groups": [{"parent": "p", "match": {}}]}`,
	}
	for name, doc := range bad {
		if _, err := ParseRules([]byte(doc)); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	if r, err := ParseRules([]byte(`{"version": "1.0.0", "groups": []}`)); err != nil || r.Len() != 0 {
		t.Errorf("empty file: (%v, %v)", r, err)
	}
}

func TestLoadRules(t *testing.T) {
	if r, err := LoadRules(filepath.Join(t.TempDir(), "missing.json")); r != nil || err != nil {
		t.Errorf("a missing file means no rules, got (%v, %v)", r, err)
	}
	path := filepath.Join(t.TempDir(), "project-groups.json")
	if err := os.WriteFile(path, []byte(`{"groups": [{"parent": "p", "match": {"projects": ["x"]}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRules(path)
	if err != nil || r.Len() != 1 {
		t.Errorf("LoadRules = (%v, %v)", r, err)
	}
	if err := os.WriteFile(path, []byte(`{"groups": [{}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(path); err == nil || !strings.Contains(err.Error(), "groups[0]") {
		t.Errorf("an invalid file must fail with its position, got %v", err)
	}
}

func TestGlob(t *testing.T) {
	re := globRegexp("argo-cd/*")
	for s, want := range map[string]bool{"argo-cd/x": true, "ARGO-CD/a/b": true, "argo-cd": false, "xargo-cd/y": false} {
		if re.MatchString(s) != want {
			t.Errorf("argo-cd/* vs %q = %v, want %v", s, !want, want)
		}
	}
	if !globRegexp("a?c.d").MatchString("abc.d") || globRegexp("a?c.d").MatchString("abcxd") {
		t.Error("? matches one character, . is literal")
	}
}

func mustRules(t *testing.T, doc string) *Rules {
	t.Helper()
	r, err := ParseRules([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
