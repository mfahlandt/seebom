import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ParentGroupListComponent } from './parent-group-list.component';
import { ProjectGroupItem, ProjectListItem } from '../../core/api.models';

describe('ParentGroupListComponent', () => {
  let httpMock: HttpTestingController;
  let fixture: ComponentFixture<ParentGroupListComponent>;
  let component: ParentGroupListComponent;

  const project = (name: string, over: Partial<ProjectListItem> = {}): ProjectListItem => ({
    project_name: name,
    sbom_count: 10,
    package_count: 400,
    vuln_count: 20,
    latest_ingested: '2026-09-01T12:00:00Z',
    latest_sbom_id: name + '-latest',
    tags: [],
    ...over,
  });

  // The CNCF shape: argo has its own SBOMs and two subprojects whose folder
  // is "argo-cd/", grouped through the repository owner.
  const argo: ProjectGroupItem = {
    name: 'argo',
    is_project: true,
    project_count: 3,
    sbom_count: 32,
    package_count: 900,
    vuln_count: 1500,
    latest_ingested: '2026-09-01T12:00:00Z',
    tags: [],
    sources: ['repo'],
    owner: 'argoproj',
    members: [
      project('argo'),
      project('argo-cd/argo-rollouts', { parent: 'argo', parent_source: 'repo' }),
      project('argo-cd/argo-workflows', { parent: 'argo', parent_source: 'repo' }),
    ],
  };

  const agones: ProjectGroupItem = {
    name: 'agones',
    is_project: true,
    project_count: 1,
    sbom_count: 10,
    package_count: 400,
    vuln_count: 619,
    latest_ingested: '2026-09-01T12:00:00Z',
    tags: [],
    sources: [],
    members: [project('agones')],
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ParentGroupListComponent],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ParentGroupListComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => httpMock.verify());

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  it('renders a parent as a collapsed group row and a parentless project as a plain row', () => {
    component.groups = [agones, argo];
    fixture.detectChanges();

    const groupRows = el().querySelectorAll('.group-row');
    expect(groupRows.length).toBe(1);
    expect(groupRows[0].textContent).toContain('argo');
    expect(groupRows[0].textContent).toContain('3 projects');

    // agones is no group of itself: it is the project row.
    const projectRows = el().querySelectorAll('.project-row');
    expect(projectRows.length).toBe(1);
    expect(projectRows[0].textContent).toContain('agones');

    // Collapsed: the members are not rendered yet.
    expect(el().textContent).not.toContain('argo-cd/argo-workflows');
  });

  it('says why the members were grouped', () => {
    component.groups = [argo];
    fixture.detectChanges();

    expect(el().querySelector('.hint')?.textContent).toContain('Grouped by repository owner "argoproj"');
  });

  it('expands a group into its member projects, parent first', () => {
    component.groups = [argo];
    fixture.detectChanges();

    (el().querySelector('.group-row .expander') as HTMLButtonElement).click();
    fixture.detectChanges();

    const members = Array.from(el().querySelectorAll('.members .project-row')).map((r) => r.textContent ?? '');
    expect(members.length).toBe(3);
    expect(members[0]).toContain('argo');
    expect(members[1]).toContain('argo-cd/argo-rollouts');
    expect(members[2]).toContain('argo-cd/argo-workflows');

    // A member expands to its versions exactly like a top-level project.
    (el().querySelectorAll('.members .project-row .expander')[2] as HTMLButtonElement).click();
    httpMock.expectOne((r) => r.url.endsWith('/projects/' + encodeURIComponent('argo-cd/argo-workflows') + '/sboms')
      || r.url.endsWith('/projects/argo-cd/argo-workflows/sboms'))
      .flush({ data: [], total: 0, page: 1, page_size: 50 });
  });

  it('shows the de-duplicated group counts, not the sum of the members', () => {
    component.groups = [argo];
    fixture.detectChanges();

    const row = el().querySelector('.group-row')!.textContent ?? '';
    // 3 × 400 packages would be 1,200; the group knows they overlap.
    expect(row).toContain('900 packages');
    expect(row).not.toContain('1,200');
  });

  it('marks a parent that is only a label, not a project', () => {
    component.groups = [{ ...argo, name: 'argoproj', is_project: false, members: argo.members.slice(1) }];
    fixture.detectChanges();

    expect(el().querySelector('.group-row a.name')).toBeFalsy();
    expect(el().querySelector('.group-row .name.label')?.textContent).toContain('argoproj');
  });

  it('collapses everything on reset', () => {
    component.groups = [argo];
    fixture.detectChanges();
    component.toggle('argo');
    expect(component.isExpanded('argo')).toBe(true);

    component.reset();
    expect(component.isExpanded('argo')).toBe(false);
  });
});

