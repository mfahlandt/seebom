import { Injectable, computed, signal } from '@angular/core';

/**
 * App-wide "something is loading" state.
 *
 * Every HTTP request (via loadingInterceptor) and every router navigation
 * calls begin()/end(). The global loading bar reads `visible` and `slow`.
 *
 * - `visible` turns on only after SHOW_DELAY_MS, so fast responses do not
 *   make the bar flicker.
 * - `slow` turns on after SLOW_AFTER_MS. Some aggregate queries take many
 *   seconds on large instances; without a hint, a page that has not finished
 *   loading looks the same as an empty or broken one.
 */
@Injectable({ providedIn: 'root' })
export class LoadingService {
  static readonly SHOW_DELAY_MS = 150;
  static readonly SLOW_AFTER_MS = 4000;

  private readonly pendingCount = signal(0);
  private readonly shown = signal(false);
  private readonly slowFlag = signal(false);

  private showTimer: ReturnType<typeof setTimeout> | null = null;
  private slowTimer: ReturnType<typeof setTimeout> | null = null;

  /** Number of requests/navigations currently in flight. */
  readonly pending = this.pendingCount.asReadonly();
  /** True while anything is in flight, without the display delay. */
  readonly active = computed(() => this.pendingCount() > 0);
  /** True once something has been in flight for longer than SHOW_DELAY_MS. */
  readonly visible = this.shown.asReadonly();
  /** True once something has been in flight for longer than SLOW_AFTER_MS. */
  readonly slow = this.slowFlag.asReadonly();

  begin(): void {
    const next = this.pendingCount() + 1;
    this.pendingCount.set(next);
    if (next === 1) {
      this.showTimer = setTimeout(() => this.shown.set(true), LoadingService.SHOW_DELAY_MS);
      this.slowTimer = setTimeout(() => this.slowFlag.set(true), LoadingService.SLOW_AFTER_MS);
    }
  }

  end(): void {
    const next = Math.max(0, this.pendingCount() - 1);
    this.pendingCount.set(next);
    if (next === 0) {
      this.clearTimers();
      this.shown.set(false);
      this.slowFlag.set(false);
    }
  }

  private clearTimers(): void {
    if (this.showTimer !== null) {
      clearTimeout(this.showTimer);
      this.showTimer = null;
    }
    if (this.slowTimer !== null) {
      clearTimeout(this.slowTimer);
      this.slowTimer = null;
    }
  }
}

