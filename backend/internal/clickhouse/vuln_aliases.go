package clickhouse

import (
	"context"
	"fmt"
	"sort"

	"github.com/seebom-labs/bomhort/backend/internal/osvutil"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// Vulnerability identities (#412). OSV stores a finding under one id
// (GHSA-…, GO-…, PYSEC-…, CVE-…) and lists the other names of the same flaw
// in aliases (migration 019). Users, VEX authors and auditors use whichever
// name they read about, so every lookup by id has to accept all of them.

// normalizeAliases sorts and de-duplicates aliases and drops vulnID itself,
// so the API returns the same list however OSV ordered it.
func normalizeAliases(vulnID string, aliases []string) []string {
	if len(aliases) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(aliases))
	out := make([]string, 0, len(aliases))
	for _, a := range aliases {
		if a == "" || a == vulnID {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// identify returns the normalized aliases and the CVE id of a finding.
func identify(vulnID string, aliases []string) ([]string, string) {
	norm := normalizeAliases(vulnID, aliases)
	return norm, osvutil.CVEID(vulnID, norm)
}

// aliasGroups maps each requested id to every other name of the same flaw,
// given the stored findings (vuln_id -> aliases) that match any of them.
// An id matches a finding when it is the finding's vuln_id or one of its
// aliases; the result is the union over all matching findings.
func aliasGroups(requested []string, findings map[string][]string) map[string][]string {
	want := make(map[string]struct{}, len(requested))
	for _, id := range requested {
		want[id] = struct{}{}
	}
	union := make(map[string]map[string]struct{})
	for vulnID, aliases := range findings {
		group := append([]string{vulnID}, aliases...)
		for _, id := range group {
			if _, ok := want[id]; !ok {
				continue
			}
			if union[id] == nil {
				union[id] = make(map[string]struct{})
			}
			for _, other := range group {
				union[id][other] = struct{}{}
			}
		}
	}
	out := make(map[string][]string, len(union))
	for id, set := range union {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		if norm := normalizeAliases(id, names); norm != nil {
			out[id] = norm
		}
	}
	return out
}

// lookupAliases returns, for each id, every other known name of the same
// flaw according to the stored findings. Ids without a finding are absent.
func (c *Client) lookupAliases(ctx context.Context, ids []string) (map[string][]string, error) {
	if len(ids) == 0 {
		return map[string][]string{}, nil
	}
	rows, err := c.Conn.Query(ctx, `
		SELECT vuln_id, groupUniqArrayArray(aliases)
		FROM vulnerabilities FINAL
		WHERE vuln_id IN (?) OR hasAny(aliases, ?)
		GROUP BY vuln_id
	`, ids, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to look up vulnerability aliases: %w", err)
	}
	defer rows.Close()
	findings := make(map[string][]string)
	for rows.Next() {
		var vulnID string
		var aliases []string
		if err := rows.Scan(&vulnID, &aliases); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability aliases: %w", err)
		}
		findings[vulnID] = aliases
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return aliasGroups(ids, findings), nil
}

// resolveVulnIDs returns the stored vuln_ids a requested id refers to: the
// id itself when findings are stored under it, plus every finding that
// lists it as an alias. /vulnerabilities/CVE-2024-45338/affected-projects
// must find the findings stored as GO-2024-3333.
func (c *Client) resolveVulnIDs(ctx context.Context, id string) ([]string, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT DISTINCT vuln_id
		FROM vulnerabilities FINAL
		WHERE vuln_id = ? OR has(aliases, ?)
	`, id, id)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vulnerability id %s: %w", id, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability id: %w", err)
		}
		ids = append(ids, v)
	}
	sort.Strings(ids)
	return ids, rows.Err()
}

// attachVEXAliases sets CVEID and Aliases on VEX statements. A statement
// keeps the id its author used; the other names come from the findings it
// can match. A statement written against a CVE keeps that CVE as its CVEID
// even when no finding is known for it.
func (c *Client) attachVEXAliases(ctx context.Context, items []dto.VEXStatementItem) error {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	ids := make([]string, 0, len(items))
	for _, it := range items {
		if _, dup := seen[it.VulnID]; !dup && it.VulnID != "" {
			seen[it.VulnID] = struct{}{}
			ids = append(ids, it.VulnID)
		}
	}
	groups, err := c.lookupAliases(ctx, ids)
	if err != nil {
		return err
	}
	for i := range items {
		items[i].Aliases = groups[items[i].VulnID]
		items[i].CVEID = osvutil.CVEID(items[i].VulnID, items[i].Aliases)
	}
	return nil
}
