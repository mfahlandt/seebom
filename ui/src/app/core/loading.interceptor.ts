import { HttpContextToken, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { finalize } from 'rxjs';
import { LoadingService } from './loading.service';

/**
 * Set to true on a request's HttpContext to keep it out of the global
 * loading bar (e.g. background requests the user did not trigger).
 */
export const SKIP_GLOBAL_LOADING = new HttpContextToken<boolean>(() => false);

/** Tracks every in-flight HTTP request in LoadingService. */
export const loadingInterceptor: HttpInterceptorFn = (req, next) => {
  if (req.context.get(SKIP_GLOBAL_LOADING)) {
    return next(req);
  }
  const loading = inject(LoadingService);
  loading.begin();
  // finalize also runs on error and on unsubscribe (e.g. switchMap cancelling
  // a stale search), so the counter can never leak.
  return next(req).pipe(finalize(() => loading.end()));
};

