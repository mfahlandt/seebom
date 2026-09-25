import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { provideLocationMocks } from '@angular/common/testing';
import { ProjectDetailComponent } from './project-detail.component';
import { ProjectDetail } from '../../core/api.models';

describe('ProjectDetailComponent', () => {
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    TestBed.resetTestingModule();
    await TestBed.configureTestingModule({
      imports: [ProjectDetailComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([{ path: 'projects/:name', component: ProjectDetailComponent }]),
        provideLocationMocks(),
      ],
    }).compileComponents();
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  const open = async (name: string) => {
    const harness = await RouterTestingHarness.create('/projects/' + encodeURIComponent(name));
    const component = harness.routeDebugElement!.componentInstance as ProjectDetailComponent;
    return { harness, component };
  };

  const detail = (over: Partial<ProjectDetail> = {}): ProjectDetail => ({
    project_name: 'kubernetes-mcp-server',
    tags: ['podman', 'subprojects'],
    parents: ['podman'],
    related_project_count: 0,
    sbom_count: 11,
    package_count: 3,
    vuln_count: 2,
    critical_vulns: 1,
    high_vulns: 0,
    medium_vulns: 1,
    low_vulns: 0,
    latest_ingested: '2026-09-20T10:00:00Z',
    latest_version: '0.0.60',
    latest_sbom_id: 'sbom-60',
    source_repo: 'https://github.com/containers/kubernetes-mcp-server',
    clusters: [],
    namespaces: [],
    license_breakdown: {},
    ...over,
  });

  /** Answers the three requests the page issues on load. */
  const flushInitial = (name: string, d: ProjectDetail = detail()) => {
    const enc = encodeURIComponent(name);
    httpMock.expectOne((r) => r.url === `/api/v1/projects/${enc}`).flush(d);
    httpMock.expectOne((r) => r.url === `/api/v1/projects/${enc}/sboms`).flush({
      data: [], total: d.sbom_count, page: 1, page_size: 100,
    });
    httpMock.expectOne((r) => r.url === `/api/v1/projects/${enc}/vulnerabilities`).flush([]);
  };

  it('should load the project by its route param and encode the name', async () => {
    const { component, harness } = await open('cncf/kubernetes');
    // The slash is encoded on the wire — unencoded it would be a different
    // API path that does not exist.
    flushInitial('cncf/kubernetes', detail({ project_name: 'cncf/kubernetes', parents: [], tags: [] }));
    harness.detectChanges();

    expect(component.detail?.project_name).toBe('cncf/kubernetes');
    expect(component.notFound).toBe(false);
  });

  it('should show the parent as a link up and the plain groupings as filters', async () => {
    const { harness, component } = await open('kubernetes-mcp-server');
    flushInitial('kubernetes-mcp-server');
    harness.detectChanges();

    const parent = harness.routeNativeElement!.querySelector('a.ctx-chip.parent') as HTMLAnchorElement;
    expect(parent).toBeTruthy();
    expect(parent.getAttribute('href')).toBe('/projects/podman');

    // "podman" is a parent, so it is not repeated among the plain groupings.
    expect(component.otherTags).toEqual(['subprojects']);
    const grouping = harness.routeNativeElement!.querySelector('a.ctx-chip:not(.parent):not(.children)') as HTMLAnchorElement;
    expect(grouping.getAttribute('href')).toBe('/projects?tag=subprojects');
  });

  it('should offer the sub-project list when other projects carry this name as a tag', async () => {
    const { harness } = await open('podman');
    flushInitial('podman', detail({
      project_name: 'podman', tags: [], parents: [], related_project_count: 6,
    }));
    harness.detectChanges();

    const children = harness.routeNativeElement!.querySelector('a.ctx-chip.children') as HTMLAnchorElement;
    expect(children).toBeTruthy();
    // Sub-projects are the existing tag listing, not a new endpoint.
    expect(children.getAttribute('href')).toBe('/projects?tag=podman');

    const tabs = Array.from(harness.routeNativeElement!.querySelectorAll('.tabs button')).map((b) => b.textContent?.trim());
    expect(tabs.some((t) => t?.startsWith('Sub-projects (6)'))).toBe(true);
  });

  it('should not render a sub-projects tab for a leaf project', async () => {
    const { harness } = await open('kubernetes-mcp-server');
    flushInitial('kubernetes-mcp-server');
    harness.detectChanges();

    const tabs = Array.from(harness.routeNativeElement!.querySelectorAll('.tabs button')).map((b) => b.textContent?.trim());
    expect(tabs.some((t) => t?.startsWith('Sub-projects'))).toBe(false);
  });

  it('should load packages lazily on first tab open, then not again', async () => {
    const { harness, component } = await open('kubernetes-mcp-server');
    flushInitial('kubernetes-mcp-server');
    harness.detectChanges();

    // Header already knows the total without the list.
    expect(component.packagesTotal).toBe(3);

    component.selectPackages();
    httpMock.expectOne((r) => r.url.includes('/packages')).flush({
      data: [{ name: 'libcurl', version: '7.0', purl: 'pkg:generic/libcurl@7.0', sbom_count: 11, vuln_count: 1 }],
      total: 1, page: 1, page_size: 100,
    });
    expect(component.packages.length).toBe(1);

    // Switching away and back must not refetch.
    component.activeTab = 'versions';
    component.selectPackages();
    httpMock.expectNone((r) => r.url.includes('/packages'));
  });

  it('should render not-found when the detail call fails', async () => {
    const { harness, component } = await open('nope');
    httpMock.expectOne((r) => r.url === '/api/v1/projects/nope')
      .flush({ error: 'Project not found' }, { status: 404, statusText: 'Not Found' });
    // forkJoin fails as a whole and unsubscribes the siblings; the testing
    // controller still tracks them as open, so they are acknowledged here
    // rather than flushed (a cancelled request cannot be flushed).
    httpMock.match((r) => r.url.includes('/sboms') || r.url.includes('/vulnerabilities'));
    harness.detectChanges();

    expect(component.notFound).toBe(true);
    expect(component.detail).toBeNull();
    expect(harness.routeNativeElement!.querySelector('.not-found')).toBeTruthy();
  });

  it('should open on the overview and derive its KPIs from the read model and the vuln rows', async () => {
    const { harness, component } = await open('kubernetes-mcp-server');
    const enc = 'kubernetes-mcp-server';
    httpMock.expectOne((r) => r.url === `/api/v1/projects/${enc}`).flush(detail({
      sbom_count: 3,
      license_breakdown: { permissive: 40, copyleft: 2, unknown: 1 },
    }));
    httpMock.expectOne((r) => r.url === `/api/v1/projects/${enc}/sboms`).flush({ data: [], total: 3, page: 1, page_size: 100 });
    const vuln = (id: string, over: object = {}) => ({
      vuln_id: id, severity: 'HIGH', purl: 'pkg:golang/x@1', summary: '', fixed_version: '',
      source_file: '', discovered_at: '', affected_sboms: 1, ...over,
    });
    httpMock.expectOne((r) => r.url === `/api/v1/projects/${enc}/vulnerabilities`).flush([
      vuln('CVE-1', { affected_sboms: 3 }),
      vuln('CVE-2', { vex_status: 'not_affected' }),
      vuln('CVE-3', { vex_status: 'affected', affected_sboms: 3 }),
    ]);
    harness.detectChanges();

    expect(component.activeTab).toBe('overview');
    // Only not_affected suppresses; an explicit "affected" statement does not.
    expect(component.suppressedVulns).toBe(1);
    expect(component.effectiveVulns).toBe(2);
    expect(component.inEveryVersion).toBe(2);
    // Findings = everything that is not permissive.
    expect(component.licenseViolations).toBe(3);
    expect(component.licenseSegments.map((s) => s.value)).toEqual([40, 2, 1]);
    expect(component.vexSegments.length).toBe(2);

    const el = harness.routeNativeElement!;
    expect(el.querySelectorAll('.kpi-card').length).toBeGreaterThanOrEqual(5);
    expect(el.querySelectorAll('app-donut-chart').length).toBe(3);
  });
});




