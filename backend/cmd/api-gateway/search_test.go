package main

import "testing"

func TestClampSearchLimit(t *testing.T) {
	tests := []struct {
		name string
		in   uint64
		want uint64
	}{
		{"zero defaults to 5", 0, 5},
		{"within bounds unchanged", 10, 10},
		{"max boundary unchanged", 50, 50},
		{"above max clamped", 500, 50},
		{"one unchanged", 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clampSearchLimit(tt.in); got != tt.want {
				t.Errorf("clampSearchLimit(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeSearchTermForGlobalSearch(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain term unchanged", "grpc", "grpc"},
		{"trims whitespace", "  grpc  ", "grpc"},
		{"strips injection chars", `gr<p>c;'"&\`, "grpc"},
		{"cve id preserved", "CVE-2024-1234", "CVE-2024-1234"},
		{"license id preserved", "Apache-2.0", "Apache-2.0"},
		{"slash preserved for project keys", "grpc/grpc-go", "grpc/grpc-go"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeSearchTerm(tt.in); got != tt.want {
				t.Errorf("sanitizeSearchTerm(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMinSearchQueryLen(t *testing.T) {
	if len(sanitizeSearchTerm("a")) >= minSearchQueryLen {
		t.Error("single char should fail the min length check")
	}
	if len(sanitizeSearchTerm("ab")) < minSearchQueryLen {
		t.Error("two chars should pass the min length check")
	}
}
