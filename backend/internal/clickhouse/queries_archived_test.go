package clickhouse

import "testing"

// The read path must map purls exactly like the resolver that writes
// github_repo_metadata. It now calls the same function; this pins the cases
// the former SQL re-implementation existed for, on cleaned (lowercase,
// version-stripped) purls as queryArchivedPurls produces them.
func TestArchivedRepoFor(t *testing.T) {
	archived := map[string]struct{}{
		"go-yaml/yaml":         {},
		"kubernetes/api":       {},
		"pkg/errors":           {},
		"oras-project/oras-go": {},
		"golang/protobuf":      {},
	}
	cases := []struct {
		purl string
		want string
	}{
		{"pkg:golang/github.com/pkg/errors", "pkg/errors"},
		{"pkg:golang/github.com/pkg/errors/sub/pkg", "pkg/errors"},
		{"pkg:github/pkg/errors", "pkg/errors"},
		{"pkg:golang/gopkg.in/yaml.v3", "go-yaml/yaml"},
		{"pkg:golang/k8s.io/api", "kubernetes/api"},
		{"pkg:golang/k8s.io/api/core/v1", "kubernetes/api"},
		{"pkg:golang/oras.land/oras-go/v2", "oras-project/oras-go"},
		{"pkg:golang/github.com/stretchr/testify", ""},
		{"pkg:npm/left-pad", ""},
		{"pkg:golang/example.com/unknown", ""},
	}
	for _, tc := range cases {
		got, ok := archivedRepoFor(tc.purl, archived)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("archivedRepoFor(%q) = %q, %v; want %q", tc.purl, got, ok, tc.want)
		}
	}
}
