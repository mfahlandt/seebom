import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LoadingService } from '../../core/loading.service';
import { LoadingBarComponent } from './loading-bar.component';

describe('LoadingBarComponent', () => {
  let loading: LoadingService;

  beforeEach(async () => {
    vi.useFakeTimers();
    await TestBed.configureTestingModule({ imports: [LoadingBarComponent] }).compileComponents();
    loading = TestBed.inject(LoadingService);
  });

  afterEach(() => vi.useRealTimers());

  const render = () => {
    const fixture = TestBed.createComponent(LoadingBarComponent);
    fixture.detectChanges();
    return fixture;
  };

  it('is hidden while nothing is loading', () => {
    const fixture = render();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.bar')?.classList.contains('on')).toBe(false);
    expect(el.querySelector('.bar')?.getAttribute('aria-hidden')).toBe('true');
    expect(el.querySelector('.slow-hint')).toBeNull();
  });

  it('shows the bar after the delay and hides it when loading ends', () => {
    const fixture = render();
    const el = fixture.nativeElement as HTMLElement;

    loading.begin();
    vi.advanceTimersByTime(LoadingService.SHOW_DELAY_MS);
    fixture.detectChanges();
    expect(el.querySelector('.bar')?.classList.contains('on')).toBe(true);
    expect(el.querySelector('.bar')?.getAttribute('aria-busy')).toBe('true');
    expect(el.querySelector('.slow-hint')).toBeNull();

    loading.end();
    fixture.detectChanges();
    expect(el.querySelector('.bar')?.classList.contains('on')).toBe(false);
  });

  it('shows the slow hint for long requests and removes it afterwards', () => {
    const fixture = render();
    const el = fixture.nativeElement as HTMLElement;

    loading.begin();
    vi.advanceTimersByTime(LoadingService.SLOW_AFTER_MS);
    fixture.detectChanges();
    const hint = el.querySelector('.slow-hint');
    expect(hint?.textContent).toContain('Still loading');
    expect(hint?.getAttribute('role')).toBe('status');

    loading.end();
    fixture.detectChanges();
    expect(el.querySelector('.slow-hint')).toBeNull();
  });
});

