import { TestBed } from '@angular/core/testing';
import { HttpClient, HttpContext, provideHttpClient, withInterceptors } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LoadingService } from './loading.service';
import { SKIP_GLOBAL_LOADING, loadingInterceptor } from './loading.interceptor';

describe('LoadingService', () => {
  let service: LoadingService;

  beforeEach(() => {
    vi.useFakeTimers();
    service = TestBed.inject(LoadingService);
  });

  afterEach(() => vi.useRealTimers());

  it('does not show the bar for fast requests', () => {
    service.begin();
    expect(service.active()).toBe(true);
    vi.advanceTimersByTime(LoadingService.SHOW_DELAY_MS - 1);
    service.end();
    vi.advanceTimersByTime(LoadingService.SLOW_AFTER_MS);
    expect(service.visible()).toBe(false);
    expect(service.slow()).toBe(false);
  });

  it('shows the bar after the delay and the slow hint later', () => {
    service.begin();
    vi.advanceTimersByTime(LoadingService.SHOW_DELAY_MS);
    expect(service.visible()).toBe(true);
    expect(service.slow()).toBe(false);
    vi.advanceTimersByTime(LoadingService.SLOW_AFTER_MS);
    expect(service.slow()).toBe(true);
    service.end();
    expect(service.visible()).toBe(false);
    expect(service.slow()).toBe(false);
  });

  it('stays visible until the last of several requests ends', () => {
    service.begin();
    service.begin();
    vi.advanceTimersByTime(LoadingService.SHOW_DELAY_MS);
    service.end();
    expect(service.pending()).toBe(1);
    expect(service.visible()).toBe(true);
    service.end();
    expect(service.visible()).toBe(false);
  });

  it('never goes below zero on an unbalanced end()', () => {
    service.end();
    expect(service.pending()).toBe(0);
    service.begin();
    expect(service.pending()).toBe(1);
  });
});

describe('loadingInterceptor', () => {
  let http: HttpClient;
  let httpMock: HttpTestingController;
  let loading: LoadingService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withInterceptors([loadingInterceptor])), provideHttpClientTesting()],
    });
    http = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
    loading = TestBed.inject(LoadingService);
  });

  afterEach(() => httpMock.verify());

  it('counts a request until it completes', () => {
    http.get('/api/v1/stats/dashboard').subscribe();
    expect(loading.pending()).toBe(1);
    httpMock.expectOne('/api/v1/stats/dashboard').flush({});
    expect(loading.pending()).toBe(0);
  });

  it('releases the count on error', () => {
    http.get('/api/v1/x').subscribe({ error: () => undefined });
    httpMock.expectOne('/api/v1/x').flush('nope', { status: 500, statusText: 'Server Error' });
    expect(loading.pending()).toBe(0);
  });

  it('releases the count when the caller unsubscribes', () => {
    const sub = http.get('/api/v1/slow').subscribe();
    expect(loading.pending()).toBe(1);
    sub.unsubscribe();
    expect(loading.pending()).toBe(0);
    httpMock.expectOne('/api/v1/slow');
  });

  it('ignores requests marked SKIP_GLOBAL_LOADING', () => {
    http.get('/api/v1/bg', { context: new HttpContext().set(SKIP_GLOBAL_LOADING, true) }).subscribe();
    expect(loading.pending()).toBe(0);
    httpMock.expectOne('/api/v1/bg').flush({});
  });
});

