import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { VulnAliasesComponent } from './vuln-aliases.component';

function render(vuln: { vuln_id: string; cve_id?: string; aliases?: string[] }, max?: number): HTMLElement {
  const fixture = TestBed.createComponent(VulnAliasesComponent);
  fixture.componentRef.setInput('vuln', vuln);
  if (max !== undefined) fixture.componentRef.setInput('max', max);
  fixture.detectChanges();
  return fixture.nativeElement as HTMLElement;
}

describe('VulnAliasesComponent', () => {
  it('lists the OSV id and other aliases next to a CVE-led row', () => {
    const el = render({ vuln_id: 'GO-2024-3333', cve_id: 'CVE-2024-45338', aliases: ['CVE-2024-45338', 'GHSA-w32m-9786-jp63'] });
    const chips = Array.from(el.querySelectorAll('.alias')).map((c) => c.textContent?.trim());
    expect(chips).toEqual(['GO-2024-3333', 'GHSA-w32m-9786-jp63']);
  });

  it('caps the chips and summarises the rest', () => {
    const el = render({ vuln_id: 'GHSA-a', cve_id: 'CVE-2024-0001', aliases: ['CVE-2024-0001', 'GO-1', 'PYSEC-1', 'OSV-1'] }, 2);
    const chips = Array.from(el.querySelectorAll('.alias')).map((c) => c.textContent?.trim());
    expect(chips).toEqual(['GHSA-a', 'GO-1', '+2']);
    expect(el.querySelector('.aliases')?.getAttribute('title')).toBe('Also known as: GHSA-a, GO-1, PYSEC-1, OSV-1');
  });

  it('renders nothing without other names', () => {
    expect(render({ vuln_id: 'CVE-2021-44228' }).querySelector('.aliases')).toBeNull();
  });
});
