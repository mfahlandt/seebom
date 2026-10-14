package osvutil

import "testing"

func TestCVEID(t *testing.T) {
	tests := []struct {
		name    string
		vulnID  string
		aliases []string
		want    string
	}{
		{"vuln id is the CVE", "CVE-2024-45338", []string{"GHSA-w32m-9786-jp63"}, "CVE-2024-45338"},
		{"CVE only in aliases", "GO-2024-3333", []string{"GHSA-w32m-9786-jp63", "CVE-2024-45338"}, "CVE-2024-45338"},
		{"no CVE at all", "GHSA-xxxx-yyyy-zzzz", []string{"PYSEC-2024-1"}, ""},
		{"no aliases", "GO-2024-1", nil, ""},
		{"several CVEs: smallest wins, order-independent", "GHSA-a", []string{"CVE-2024-9999", "CVE-2023-10001"}, "CVE-2023-10001"},
		{"five-digit sequence", "GHSA-a", []string{"CVE-2021-44228"}, "CVE-2021-44228"},
		{"lookalikes are not CVEs", "GHSA-a", []string{"CVE-24-1", "cve-2024-1234", "CVE-2024-123", "XCVE-2024-1234"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CVEID(tt.vulnID, tt.aliases); got != tt.want {
				t.Errorf("CVEID(%q, %v) = %q, want %q", tt.vulnID, tt.aliases, got, tt.want)
			}
		})
	}
}
