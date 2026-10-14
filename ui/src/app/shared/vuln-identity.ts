/**
 * Vulnerability identity (#412). OSV stores most findings under a GHSA-,
 * GO- or PYSEC- id; the CVE people search for is only an alias. The API
 * returns `cve_id` (when one exists) and `aliases`; these helpers decide
 * what a row shows first and what it lists as other names.
 */
export interface VulnIdentity {
  vuln_id: string;
  cve_id?: string;
  aliases?: string[];
}

/** The id a row leads with: the CVE when known, else OSV's id. */
export function primaryVulnId(v: VulnIdentity): string {
  return v.cve_id || v.vuln_id;
}

/** Every other name of the same flaw: OSV's id first (when it is not the primary), then the remaining aliases. */
export function secondaryVulnIds(v: VulnIdentity): string[] {
  const primary = primaryVulnId(v);
  const out: string[] = [];
  const add = (id: string | undefined) => {
    if (id && id !== primary && !out.includes(id)) out.push(id);
  };
  add(v.vuln_id);
  (v.aliases ?? []).forEach(add);
  return out;
}

/** True when `term` names this flaw by any of its ids (case-insensitive substring). */
export function vulnMatches(v: VulnIdentity, term: string): boolean {
  const t = term.trim().toLowerCase();
  if (!t) return true;
  return [v.vuln_id, v.cve_id, ...(v.aliases ?? [])].some((id) => !!id && id.toLowerCase().includes(t));
}
