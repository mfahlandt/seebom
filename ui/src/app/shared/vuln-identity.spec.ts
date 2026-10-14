import { describe, expect, it } from 'vitest';
import { primaryVulnId, secondaryVulnIds, vulnMatches } from './vuln-identity';

const goFinding = {
  vuln_id: 'GO-2024-3333',
  cve_id: 'CVE-2024-45338',
  aliases: ['CVE-2024-45338', 'GHSA-w32m-9786-jp63'],
};

describe('vuln identity (#412)', () => {
  it('leads with the CVE when the finding has one', () => {
    expect(primaryVulnId(goFinding)).toBe('CVE-2024-45338');
    expect(secondaryVulnIds(goFinding)).toEqual(['GO-2024-3333', 'GHSA-w32m-9786-jp63']);
  });

  it('falls back to the OSV id without a CVE', () => {
    const f = { vuln_id: 'GHSA-xxxx-yyyy-zzzz', aliases: ['PYSEC-2024-1'] };
    expect(primaryVulnId(f)).toBe('GHSA-xxxx-yyyy-zzzz');
    expect(secondaryVulnIds(f)).toEqual(['PYSEC-2024-1']);
  });

  it('shows nothing extra for a plain CVE finding from older APIs', () => {
    expect(primaryVulnId({ vuln_id: 'CVE-2021-44228' })).toBe('CVE-2021-44228');
    expect(secondaryVulnIds({ vuln_id: 'CVE-2021-44228' })).toEqual([]);
  });

  it('matches a search term against every name', () => {
    expect(vulnMatches(goFinding, 'ghsa-w32m')).toBe(true);
    expect(vulnMatches(goFinding, '45338')).toBe(true);
    expect(vulnMatches(goFinding, 'GO-2024')).toBe(true);
    expect(vulnMatches(goFinding, 'CVE-2023')).toBe(false);
    expect(vulnMatches(goFinding, '  ')).toBe(true);
  });
});
