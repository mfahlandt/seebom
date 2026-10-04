import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { LicenseOverviewComponent } from './license-overview.component';

describe('LicenseOverviewComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LicenseOverviewComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(LicenseOverviewComponent);
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });

  it('should show category cards', () => {
    const fixture = TestBed.createComponent(LicenseOverviewComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    const cards = compiled.querySelectorAll('.category-card');
    // permissive, copyleft, not approved, unknown, exempted
    expect(cards.length).toBe(5);
    expect(compiled.querySelector('.category-card.unapproved h3')?.textContent).toContain('Not Approved');
  });

  it('splits license sources into resolved and unknown', () => {
    const fixture = TestBed.createComponent(LicenseOverviewComponent);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/licenses/compliance').flush([]);
    http.expectOne('/api/v1/licenses/sources').flush([
      { source: 'declared', origin: 'declared', modifiers: [], resolved: true, package_count: 10, sbom_count: 2, examples: ['a'] },
      { source: 'pypi+latest', origin: 'pypi', modifiers: ['latest'], resolved: true, package_count: 3, sbom_count: 1, examples: ['b'] },
      { source: 'not-published', origin: 'not-published', modifiers: [], resolved: false, package_count: 4, sbom_count: 1, examples: ['c'] },
    ]);
    const c = fixture.componentInstance;
    expect(c.resolvedTotal).toBe(13);
    expect(c.unresolvedTotal).toBe(4);

    c.toggleResolution();
    fixture.detectChanges();
    const rows = (fixture.nativeElement as HTMLElement).querySelectorAll('.source-row.unresolved .source-label');
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain('Not published');
  });
});
