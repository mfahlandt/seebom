import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PackageSearchComponent } from './package-search.component';

describe('PackageSearchComponent', () => {
  let component: PackageSearchComponent;
  let fixture: ComponentFixture<PackageSearchComponent>;
  let httpMock: HttpTestingController;

  const response = (query: string, total: number) => ({
    total_results: total,
    page: 1,
    page_size: 20,
    query,
    items: []
  });

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PackageSearchComponent],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
    }).compileComponents();

    fixture = TestBed.createComponent(PackageSearchComponent);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    vi.useFakeTimers();
  });

  afterEach(() => {
    httpMock.verify();
    vi.useRealTimers();
  });

  it('should cancel the in-flight request when the query changes (#488)', () => {
    component.onSearchChange('kube');
    vi.advanceTimersByTime(300);
    const first = httpMock.expectOne('/api/v1/packages/search?q=kube&page=1&page_size=20');

    component.onSearchChange('kubernetes');
    vi.advanceTimersByTime(300);
    expect(first.cancelled).toBe(true);

    const second = httpMock.expectOne('/api/v1/packages/search?q=kubernetes&page=1&page_size=20');
    second.flush(response('kubernetes', 7));

    expect(component.data!.query).toBe('kubernetes');
    expect(component.data!.total_results).toBe(7);
    expect(component.loading).toBe(false);
  });

  it('should page through the same stream', () => {
    component.searchQuery = 'kube';
    component.onSearchChange('kube');
    vi.advanceTimersByTime(300);
    httpMock.expectOne('/api/v1/packages/search?q=kube&page=1&page_size=20').flush(response('kube', 45));

    component.goToPage(2);
    httpMock.expectOne('/api/v1/packages/search?q=kube&page=2&page_size=20').flush({ ...response('kube', 45), page: 2 });
    expect(component.currentPage).toBe(2);
    expect(component.data!.page).toBe(2);
  });

  it('should clear data and stop loading on error', () => {
    component.onSearchChange('kube');
    vi.advanceTimersByTime(300);
    httpMock.expectOne('/api/v1/packages/search?q=kube&page=1&page_size=20').flush('boom', { status: 500, statusText: 'err' });
    expect(component.loading).toBe(false);

    component.onSearchChange('k');
    vi.advanceTimersByTime(300);
    expect(component.data).toBeNull();
  });
});
