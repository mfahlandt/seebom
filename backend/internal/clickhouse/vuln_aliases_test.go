package clickhouse

import (
	"reflect"
	"testing"
)

func TestNormalizeAliases(t *testing.T) {
	got := normalizeAliases("GO-2024-3333", []string{"CVE-2024-45338", "GHSA-w32m-9786-jp63", "CVE-2024-45338", "", "GO-2024-3333"})
	want := []string{"CVE-2024-45338", "GHSA-w32m-9786-jp63"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeAliases = %v, want %v", got, want)
	}
	if got := normalizeAliases("X", []string{"X"}); got != nil {
		t.Errorf("only self: got %v, want nil", got)
	}
}

func TestIdentify(t *testing.T) {
	aliases, cve := identify("GO-2024-3333", []string{"GHSA-w32m-9786-jp63", "CVE-2024-45338"})
	if cve != "CVE-2024-45338" {
		t.Errorf("cve = %q", cve)
	}
	if !reflect.DeepEqual(aliases, []string{"CVE-2024-45338", "GHSA-w32m-9786-jp63"}) {
		t.Errorf("aliases = %v", aliases)
	}
}

func TestAliasGroups(t *testing.T) {
	findings := map[string][]string{
		"GO-2024-3333":        {"CVE-2024-45338", "GHSA-w32m-9786-jp63"},
		"GHSA-w32m-9786-jp63": {"CVE-2024-45338"},
		"GHSA-other":          {"CVE-2023-0001"},
	}
	got := aliasGroups([]string{"CVE-2024-45338", "GO-2024-3333", "GHSA-unknown"}, findings)
	want := map[string][]string{
		// Requested by alias: every finding listing it contributes.
		"CVE-2024-45338": {"GHSA-w32m-9786-jp63", "GO-2024-3333"},
		// Requested by stored id: its own aliases.
		"GO-2024-3333": {"CVE-2024-45338", "GHSA-w32m-9786-jp63"},
		// Unknown ids are absent, and unrelated findings never leak in.
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("aliasGroups = %v, want %v", got, want)
	}
}
