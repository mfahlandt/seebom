import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ScopeMatrixComponent } from './scope-matrix.component';

describe('ScopeMatrixComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [ScopeMatrixComponent], providers: [provideRouter([])] });
  });

  it('renders one card per non-empty scope, direct first, with a scoped list link', () => {
    const fixture = TestBed.createComponent(ScopeMatrixComponent);
    fixture.componentRef.setInput('breakdown', {
      transitive: { total: 10, critical: 1, high: 2, medium: 3, low: 4 },
      direct: { total: 2, critical: 0, high: 2, medium: 0, low: 0 },
      unknown: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    });
    fixture.componentRef.setInput('vulnLink', '/vulnerabilities');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const cards = el.querySelectorAll('.scope-card');
    expect(cards.length).toBe(2);
    expect(cards[0].textContent).toContain('DIRECT');
    expect(cards[1].textContent).toContain('TRANSITIVE');
    expect(cards[1].querySelector('.sev-critical td')?.textContent?.trim()).toBe('1');
    expect(cards[0].querySelector('a.scope-link')?.getAttribute('href')).toBe('/vulnerabilities?scope=direct');
  });

  it('shows the empty message without a breakdown', () => {
    const fixture = TestBed.createComponent(ScopeMatrixComponent);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('No vulnerabilities.');
  });
});
