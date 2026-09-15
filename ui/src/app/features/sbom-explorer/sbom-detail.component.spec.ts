import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ActivatedRoute } from '@angular/router';
import { SbomDetailComponent } from './sbom-detail.component';

describe('SbomDetailComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SbomDetailComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              paramMap: {
                get: (key: string) => key === 'id' ? 'test-sbom-123' : null,
              },
            },
          },
        },
      ],
    }).compileComponents();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });

  it('should show loading initially', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.loading')?.textContent).toContain('Loading');
  });

  it('should default to vulns tab', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    expect(component.activeTab).toBe('vulns');
  });

  it('should detect copyleft licenses', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    expect(component.isCopyleft('GPL-3.0-only')).toBe(true);
    expect(component.isCopyleft('AGPL-3.0')).toBe(true);
    expect(component.isCopyleft('MIT')).toBe(false);
    expect(component.isCopyleft('Apache-2.0')).toBe(false);
  });

  it('should render every package of an expanded license as a non-shrinking row', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    const packages = Array.from({ length: 85 }, (_, i) => `pkg-${i}`);

    component.detail = {
      sbom_id: 'test-sbom-123',
      source_file: 'test.spdx.json',
      document_name: 'test',
    } as any;
    component.licenses = [
      { license_id: 'NOASSERTION', category: 'unknown', package_count: packages.length, packages },
    ];
    component.activeTab = 'licenses';
    component.expandedLicense = 'NOASSERTION';
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    const items = compiled.querySelectorAll<HTMLElement>('.lic-pkg-item');
    expect(items.length).toBe(85);

    // The list is a column flex container with max-height + overflow-y: auto.
    // Items must not shrink, otherwise all rows get squashed into the
    // container height instead of scrolling (regression: overlapping rows).
    const style = getComputedStyle(items[0]);
    expect(style.flexShrink).toBe('0');
  });
});

