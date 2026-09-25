package ingestpath

import (
	"reflect"
	"testing"
)

// equal compares Attributes treating nil and empty Tags as the same — a
// derived result with no tags must match a literal Attributes{} in tests.
func equal(a, b Attributes) bool {
	if len(a.Tags) == 0 && len(b.Tags) == 0 {
		a.Tags, b.Tags = nil, nil
	}
	return reflect.DeepEqual(a, b)
}

func TestParseLayout_Empty(t *testing.T) {
	for _, spec := range []string{"", "   ", "/", "//"} {
		l, err := ParseLayout(spec)
		if err != nil {
			t.Fatalf("ParseLayout(%q) returned error: %v", spec, err)
		}
		if l.Enabled() {
			t.Errorf("ParseLayout(%q) should be disabled", spec)
		}
		if got := l.Derive("a/b/c/f.json"); !equal(got, Attributes{}) {
			t.Errorf("disabled layout derived %+v, want zero", got)
		}
	}
}

func TestParseLayout_Valid(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"cluster/namespace/project", "cluster/namespace/project"},
		{"CLUSTER/Namespace", "cluster/namespace"},
		{" cluster / namespace ", "cluster/namespace"},
		{"/cluster/namespace/", "cluster/namespace"},
		{"namespace", "namespace"},
		{"_/project", "_/project"},
		{"_/_/cluster", "_/_/cluster"},
		{"tag/project", "tag/project"},
		{"tag/_/tag/file", "tag/_/tag/file"},
		{"file", "file"},
		{"cluster/tag/tag/project", "cluster/tag/tag/project"},
	}
	for _, tt := range tests {
		l, err := ParseLayout(tt.spec)
		if err != nil {
			t.Fatalf("ParseLayout(%q): unexpected error %v", tt.spec, err)
		}
		if !l.Enabled() {
			t.Errorf("ParseLayout(%q) should be enabled", tt.spec)
		}
		if l.String() != tt.want {
			t.Errorf("ParseLayout(%q).String() = %q, want %q", tt.spec, l.String(), tt.want)
		}
	}
}

func TestParseLayout_Invalid(t *testing.T) {
	for _, spec := range []string{
		"cluster/bogus",
		"team",
		"cluster/cluster",
		"namespace/project/namespace",
		"cluster//namespace",
		// file must be last: everything before it is a directory.
		"file/project",
		"tag/file/tag",
		// file and project both set project.
		"project/file",
		"file/project",
	} {
		if _, err := ParseLayout(spec); err == nil {
			t.Errorf("ParseLayout(%q) should have failed", spec)
		}
	}
}

func TestDerive_FullLayout(t *testing.T) {
	l, err := ParseLayout("cluster/namespace/project")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  string
		want Attributes
	}{
		{
			name: "exact depth",
			key:  "prod-eu/payments/payment-service/sbom.spdx.json",
			want: Attributes{Cluster: "prod-eu", Namespace: "payments", Project: "payment-service"},
		},
		{
			name: "deeper path matches from the left",
			key:  "prod-eu/payments/payment-service/v1.7.2/sbom.spdx.json",
			want: Attributes{Cluster: "prod-eu", Namespace: "payments", Project: "payment-service"},
		},
		{
			name: "shallow path fills what it can",
			key:  "prod-eu/payments/sbom.spdx.json",
			want: Attributes{Cluster: "prod-eu", Namespace: "payments"},
		},
		{
			name: "single directory",
			key:  "prod-eu/sbom.spdx.json",
			want: Attributes{Cluster: "prod-eu"},
		},
		{
			name: "file at the root yields nothing",
			key:  "sbom.spdx.json",
			want: Attributes{},
		},
		{
			name: "leading slash is ignored",
			key:  "/prod-eu/payments/payment-service/sbom.spdx.json",
			want: Attributes{Cluster: "prod-eu", Namespace: "payments", Project: "payment-service"},
		},
		{
			name: "doubled separators are collapsed",
			key:  "prod-eu//payments///payment-service/sbom.spdx.json",
			want: Attributes{Cluster: "prod-eu", Namespace: "payments", Project: "payment-service"},
		},
		{
			name: "dot segments are dropped",
			key:  "./prod-eu/payments/payment-service/sbom.spdx.json",
			want: Attributes{Cluster: "prod-eu", Namespace: "payments", Project: "payment-service"},
		},
		{
			name: "backslashes normalise like separators",
			key:  `prod-eu\payments\payment-service\sbom.spdx.json`,
			want: Attributes{Cluster: "prod-eu", Namespace: "payments", Project: "payment-service"},
		},
		{
			name: "empty key",
			key:  "",
			want: Attributes{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := l.Derive(tt.key); !equal(got, tt.want) {
				t.Errorf("Derive(%q) = %+v, want %+v", tt.key, got, tt.want)
			}
		})
	}
}

func TestDerive_SkipToken(t *testing.T) {
	l, err := ParseLayout("cluster/_/project")
	if err != nil {
		t.Fatal(err)
	}
	got := l.Derive("prod-eu/ignore-me/payment-service/sbom.spdx.json")
	want := Attributes{Cluster: "prod-eu", Project: "payment-service"}
	if !equal(got, want) {
		t.Errorf("Derive() = %+v, want %+v", got, want)
	}
	if got.Namespace != "" {
		t.Errorf("skip token must not populate namespace, got %q", got.Namespace)
	}
}

func TestDerive_ReorderedLayout(t *testing.T) {
	// The layout is positional, not a fixed hierarchy: operators whose
	// buckets are organised project-first must get project-first results.
	l, err := ParseLayout("project/cluster")
	if err != nil {
		t.Fatal(err)
	}
	got := l.Derive("payment-service/prod-eu/sbom.spdx.json")
	want := Attributes{Cluster: "prod-eu", Project: "payment-service"}
	if !equal(got, want) {
		t.Errorf("Derive() = %+v, want %+v", got, want)
	}
}

// TestDerive_TagToken is the #398 parent/sub-project case: the CNCF
// sub-project bucket is laid out {parent}/{subproject}/{version}/file, and the
// parent must survive as a grouping label instead of being thrown away.
func TestDerive_TagToken(t *testing.T) {
	l, err := ParseLayout("tag/project")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  string
		want Attributes
	}{
		{
			name: "parent becomes a tag, subproject stays the identity",
			key:  "podman/kubernetes-mcp-server/0.0.57/podman_kubernetes-mcp-server_0_0_57_spdx.json",
			want: Attributes{Project: "kubernetes-mcp-server", Tags: []string{"podman"}},
		},
		{
			name: "shallow path yields the tag only",
			key:  "podman/sbom.spdx.json",
			want: Attributes{Tags: []string{"podman"}},
		},
		{
			name: "root file yields nothing",
			key:  "sbom.spdx.json",
			want: Attributes{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := l.Derive(tt.key); !equal(got, tt.want) {
				t.Errorf("Derive(%q) = %+v, want %+v", tt.key, got, tt.want)
			}
		})
	}
}

func TestDerive_RepeatedTagToken(t *testing.T) {
	l, err := ParseLayout("cluster/tag/tag/project")
	if err != nil {
		t.Fatal(err)
	}
	got := l.Derive("prod-eu/team-a/tier-1/svc/sbom.json")
	want := Attributes{Cluster: "prod-eu", Project: "svc", Tags: []string{"team-a", "tier-1"}}
	if !equal(got, want) {
		t.Errorf("Derive() = %+v, want %+v", got, want)
	}
}

// TestDerive_FileToken is the #398 sandbox-review case: the file is named
// after the project and the directories carry review metadata, so the org
// level must be a tag rather than the project identity.
func TestDerive_FileToken(t *testing.T) {
	l, err := ParseLayout("tag/_/tag/file")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  string
		want Attributes
	}{
		{
			name: "org is a tag, filename stem is the project",
			key:  "sandbox-applications/501/siemens-healthineers/k2s.spdx.json",
			want: Attributes{Project: "k2s", Tags: []string{"sandbox-applications", "siemens-healthineers"}},
		},
		{
			name: "stacked extensions are all stripped",
			key:  "sandbox-applications/527/azure/unbounded.cdx.json",
			want: Attributes{Project: "unbounded", Tags: []string{"sandbox-applications", "azure"}},
		},
		{
			name: "no extension is fine",
			key:  "sandbox-applications/527/azure/unbounded",
			want: Attributes{Project: "unbounded", Tags: []string{"sandbox-applications", "azure"}},
		},
		{
			name: "shallow path still takes the file",
			key:  "sandbox-applications/k2s.spdx.json",
			want: Attributes{Project: "k2s", Tags: []string{"sandbox-applications"}},
		},
		{
			name: "root file yields only the project",
			key:  "k2s.spdx.json",
			want: Attributes{Project: "k2s"},
		},
		{
			name: "dotfile yields no project rather than a nonsense one",
			key:  "sandbox-applications/1/org/.json",
			want: Attributes{Tags: []string{"sandbox-applications", "org"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := l.Derive(tt.key); !equal(got, tt.want) {
				t.Errorf("Derive(%q) = %+v, want %+v", tt.key, got, tt.want)
			}
		})
	}
}

func TestDerive_FileTokenAlone(t *testing.T) {
	l, err := ParseLayout("file")
	if err != nil {
		t.Fatal(err)
	}
	got := l.Derive("deep/ignored/dirs/payment-service.spdx.json")
	want := Attributes{Project: "payment-service"}
	if !equal(got, want) {
		t.Errorf("Derive() = %+v, want %+v", got, want)
	}
}

func TestApply_ExplicitValuesWin(t *testing.T) {
	derived := Attributes{Cluster: "derived-c", Namespace: "derived-n", Project: "derived-p"}

	cluster, namespace, project := "explicit-c", "", "explicit-p"
	Apply(derived, &cluster, &namespace, &project)

	if cluster != "explicit-c" {
		t.Errorf("cluster = %q, want explicit-c (explicit config must outrank the path)", cluster)
	}
	if namespace != "derived-n" {
		t.Errorf("namespace = %q, want derived-n (empty value must be filled)", namespace)
	}
	if project != "explicit-p" {
		t.Errorf("project = %q, want explicit-p", project)
	}
}

func TestApply_NothingDerived(t *testing.T) {
	cluster, namespace, project := "c", "", ""
	Apply(Attributes{}, &cluster, &namespace, &project)

	if cluster != "c" || namespace != "" || project != "" {
		t.Errorf("Apply with zero attributes changed values: %q %q %q", cluster, namespace, project)
	}
}
