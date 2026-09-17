package ingestpath

import "testing"

func TestParseLayout_Empty(t *testing.T) {
	for _, spec := range []string{"", "   ", "/", "//"} {
		l, err := ParseLayout(spec)
		if err != nil {
			t.Fatalf("ParseLayout(%q) returned error: %v", spec, err)
		}
		if l.Enabled() {
			t.Errorf("ParseLayout(%q) should be disabled", spec)
		}
		if got := l.Derive("a/b/c/f.json"); got != (Attributes{}) {
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
			if got := l.Derive(tt.key); got != tt.want {
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
	if got != want {
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
	if got != want {
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
