package s3

import "testing"

func TestIsReservedKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"_bomhort/originals/abc/app.spdx.json", true},
		{"prod/_bomhort/originals/abc/app.spdx.json", true}, // behind a bucket Prefix
		{"prod/eu/_bomhort/x.json", true},
		{"_bomhort/", true},
		{"prod/app.spdx.json", false},
		{"bomhort/originals/app.spdx.json", false},    // no leading underscore
		{"prod/my_bomhort/app.spdx.json", false},      // substring, not a path segment
		{"prod/_bomhort_backup/app.spdx.json", false}, // different segment
		{"", false},
	}
	for _, tc := range tests {
		if got := IsReservedKey(tc.key); got != tc.want {
			t.Errorf("IsReservedKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

// Stored originals keep their SBOM-looking filename, so ClassifyKey alone
// would happily re-ingest them. The reserved-prefix guard must fire first.
func TestReservedKeyLooksLikeSBOM(t *testing.T) {
	key := ReservedPrefix + "originals/0000/app.spdx.json"
	if ClassifyKey(key) != "sbom" {
		t.Fatalf("precondition: %q should classify as sbom", key)
	}
	if !IsReservedKey(key) {
		t.Fatalf("%q must be reserved so it is skipped before classification", key)
	}
}
