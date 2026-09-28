import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ProjectGroupListComponent } from './project-group-list.component';

describe('ProjectGroupListComponent (#58)', () => {
  let httpMock: HttpTestingController;
  let fixture: ComponentFixture<ProjectGroupListComponent>;
  let component: ProjectGroupListComponent;

  const project = (over: Record<string, unknown> = {}) => ({
    project_name: 'payment-service',
    sbom_count: 11,
    package_count: 420,
    vuln_count: 7,
    latest_ingested: '2026-09-01T12:00:00Z',
    latest_sbom_id: 'latest-id',
    tags: [],
    ...over,
  }) as any;

  const version = (id: string, over: Record<string, unknown> = {}) => ({
    sbom_id: id,
    source_file: `${id}.spdx.json`,
    document_name: 'payment-service',
    spdx_version: 'SPDX-2.3',
    package_count: 400,
    vuln_count: 5,
    ingested_at: '2026-09-01T12:00:00Z',
    ...over,
  }) as any;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProjectGroupListComponent],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ProjectGroupListComponent);
    component = fixture.componentInstance;
  });

  function expectVersionRequest() {
    return httpMock.expectOne((r) => r.url.endsWith('/projects/payment-service/sboms'));
  }

  it('renders one row per project', () => {
    component.projects = [project(), project({ project_name: 'checkout', sbom_count: 1 })];
    fixture.detectChanges();

    const rows = (fixture.nativeElement as HTMLElement).querySelectorAll('.project-row');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('payment-service');
    expect(rows[0].textContent).toContain('11 versions');
    // Singular for a single version — "1 versions" is the kind of detail that
    // makes a list look generated.
    expect(rows[1].textContent).toContain('1 version');
    expect(rows[1].textContent).not.toContain('1 versions');
  });

  /**
   * The point of #58, and the trap it inherits from #398: the row's numbers
   * are the project's de-duplicated numbers, not the sum of the versions below
   * it. Here the two versions list 400 + 380 packages and 5 + 6 findings,
   * while the project has 420 distinct components and 7 distinct findings.
   */
  it('shows de-duplicated project counts, not the sum of the versions', () => {
    component.projects = [project()];
    fixture.detectChanges();

    component.toggleProject('payment-service');
    expectVersionRequest().flush({
      data: [
        version('v2', { document_version: '2.3.0', package_count: 400, vuln_count: 5 }),
        version('v1', { document_version: '2.2.0', package_count: 380, vuln_count: 6 }),
      ],
      total: 2, page: 1, page_size: 50,
    });
    fixture.detectChanges();

    const headerRow = (fixture.nativeElement as HTMLElement).querySelector('.project-row')!;
    expect(headerRow.textContent).toContain('420 packages');
    expect(headerRow.textContent).not.toContain('780');
    expect(headerRow.textContent).toContain('7 vulns');
    expect(headerRow.textContent).not.toContain('11 vulns');

    const versionRows = (fixture.nativeElement as HTMLElement).querySelectorAll('.version-row');
    expect(versionRows.length).toBe(2);
    expect(versionRows[0].textContent).toContain('2.3.0');
  });

  /**
   * Grouping must not be computed from whatever a document list happens to
   * hold: that is one page of documents, so a project's versions may live on
   * pages nobody loaded. Expanding therefore asks the project endpoint.
   */
  it('fetches versions from the project endpoint, once per project', () => {
    component.projects = [project()];
    fixture.detectChanges();

    component.toggleProject('payment-service');
    const req = expectVersionRequest();
    expect(req.request.params.get('page_size')).toBe('50');
    req.flush({ data: [version('v1')], total: 1, page: 1, page_size: 50 });

    // Collapse and expand again: the cached versions are reused. Re-fetching
    // on every toggle turns an idle list into a request storm on an instance
    // with thousands of projects.
    component.toggleProject('payment-service');
    expect(component.isExpanded('payment-service')).toBe(false);
    component.toggleProject('payment-service');
    expect(component.isExpanded('payment-service')).toBe(true);
    httpMock.expectNone((r) => r.url.endsWith('/projects/payment-service/sboms'));
    expect(component.versionsOf('payment-service').length).toBe(1);
  });

  it('percent-encodes an org/project name on the way to the endpoint', () => {
    component.projects = [project({ project_name: 'cncf/bomhort' })];
    fixture.detectChanges();

    component.toggleProject('cncf/bomhort');
    httpMock
      .expectOne((r) => r.url.endsWith('/projects/cncf%2Fbomhort/sboms'))
      .flush({ data: [], total: 0, page: 1, page_size: 50 });

    expect(component.isExpanded('cncf/bomhort')).toBe(true);
  });

  it('offers a way to the full version list when one page is not all of them', () => {
    component.projects = [project({ sbom_count: 120 })];
    fixture.detectChanges();

    component.toggleProject('payment-service');
    expectVersionRequest().flush({ data: [version('v1')], total: 120, page: 1, page_size: 50 });
    fixture.detectChanges();

    expect(component.hasMoreVersions('payment-service')).toBe(true);
    const link = (fixture.nativeElement as HTMLElement).querySelector('.all-versions-link');
    expect(link).toBeTruthy();
    expect(link!.textContent).toContain('120');
  });

  it('shows no truncation link when the page holds every version', () => {
    component.projects = [project({ sbom_count: 2 })];
    fixture.detectChanges();

    component.toggleProject('payment-service');
    expectVersionRequest().flush({ data: [version('v1'), version('v2')], total: 2, page: 1, page_size: 50 });
    fixture.detectChanges();

    expect(component.hasMoreVersions('payment-service')).toBe(false);
    expect((fixture.nativeElement as HTMLElement).querySelector('.all-versions-link')).toBeFalsy();
  });

  it('keeps the row expanded but empty when the version request fails', () => {
    component.projects = [project()];
    fixture.detectChanges();

    component.toggleProject('payment-service');
    expectVersionRequest().flush('boom', { status: 500, statusText: 'Server Error' });

    expect(component.isExpanded('payment-service')).toBe(true);
    expect(component.isLoadingVersions('payment-service')).toBe(false);
    expect(component.versionsOf('payment-service')).toEqual([]);
    expect(() => fixture.detectChanges()).not.toThrow();
  });

  it('drops expansion state on reset', () => {
    component.projects = [project()];
    fixture.detectChanges();

    component.toggleProject('payment-service');
    expectVersionRequest().flush({ data: [version('v1')], total: 1, page: 1, page_size: 50 });
    expect(component.isExpanded('payment-service')).toBe(true);

    // A new listing invalidates the panels: keeping one open would leave it
    // attached to a project that is no longer on the page.
    component.reset();
    expect(component.isExpanded('payment-service')).toBe(false);
    expect(component.versionsOf('payment-service')).toEqual([]);
  });

  it('marks the expander for assistive technology', () => {
    component.projects = [project()];
    fixture.detectChanges();

    const expander = (fixture.nativeElement as HTMLElement).querySelector('.expander')!;
    expect(expander.getAttribute('aria-expanded')).toBe('false');
    expect(expander.getAttribute('aria-label')).toContain('Expand');

    component.toggleProject('payment-service');
    expectVersionRequest().flush({ data: [], total: 0, page: 1, page_size: 50 });
    fixture.detectChanges();

    expect(expander.getAttribute('aria-expanded')).toBe('true');
    expect(expander.getAttribute('aria-label')).toContain('Collapse');
  });
});

