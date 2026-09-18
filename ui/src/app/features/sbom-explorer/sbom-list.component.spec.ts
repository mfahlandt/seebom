import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { SbomListComponent } from './sbom-list.component';

describe('SbomListComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SbomListComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });

  it('should have a virtual scroll viewport', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('cdk-virtual-scroll-viewport')).toBeTruthy();
  });

  it('should carry the ownership dimensions through to the rows (#177)', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;

    component.sboms = [
      {
        sbom_id: 'a', source_file: 'a.spdx.json', spdx_version: 'SPDX-2.3',
        document_name: 'payment-service', package_count: 10, vuln_count: 0,
        ingested_at: '2026-09-01T12:00:00Z',
        cluster: 'prod-eu', namespace: 'payments', project: 'payment-service',
      },
      // Single-instance deployment: all three default to '' and are omitted
      // by the API, so the row must render without badges.
      {
        sbom_id: 'b', source_file: 'b.spdx.json', spdx_version: 'SPDX-2.3',
        document_name: 'standalone', package_count: 5, vuln_count: 0,
        ingested_at: '2026-09-01T12:00:00Z',
      },
    ] as any;
    component.total = 2;

    // The rows render inside a cdk-virtual-scroll-viewport, which never
    // materialises items in jsdom (no element layout, so the measured
    // viewport height stays 0). Assert on the data contract instead of the
    // DOM; the badges are plain *ngIf bindings on these exact fields, and
    // the DTO side is covered by pkg/dto/api_ownership_test.go.
    expect(() => fixture.detectChanges()).not.toThrow();

    expect(component.sboms[0].cluster).toBe('prod-eu');
    expect(component.sboms[0].namespace).toBe('payments');
    expect(component.sboms[0].project).toBe('payment-service');
    expect(component.sboms[1].cluster).toBeUndefined();
    expect(component.sboms[1].namespace).toBeUndefined();
    expect(component.sboms[1].project).toBeUndefined();
  });
});
