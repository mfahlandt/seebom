import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { LoadingService } from '../../core/loading.service';

/**
 * Thin indeterminate progress bar under the navbar, plus a "still loading"
 * hint when a request takes unusually long.
 */
@Component({
  selector: 'app-loading-bar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="bar" [class.on]="loading.visible()" role="progressbar"
         aria-label="Loading" [attr.aria-hidden]="!loading.visible()" [attr.aria-busy]="loading.visible()">
      <div class="indicator"></div>
    </div>
    @if (loading.slow()) {
      <div class="slow-hint" role="status" aria-live="polite">
        <span class="spinner" aria-hidden="true"></span>
        Still loading… large queries can take a while.
      </div>
    }
  `,
  styles: [`
    :host { position: relative; display: block; height: 0; z-index: 1000; }
    .bar {
      position: absolute; top: 0; left: 0; right: 0; height: 3px;
      overflow: hidden; opacity: 0; transition: opacity 0.2s;
      background: color-mix(in srgb, var(--loading-bar, var(--accent)) 20%, transparent);
      pointer-events: none;
    }
    .bar.on { opacity: 1; }
    .indicator {
      position: absolute; top: 0; bottom: 0; left: -40%; width: 40%;
      background: var(--loading-bar, var(--accent));
      animation: slide 1.1s ease-in-out infinite;
    }
    .bar:not(.on) .indicator { animation-play-state: paused; }
    @keyframes slide {
      0% { left: -40%; width: 40%; }
      50% { width: 30%; }
      100% { left: 100%; width: 40%; }
    }
    .slow-hint {
      position: absolute; top: 12px; right: 20px;
      display: flex; align-items: center; gap: 8px;
      padding: 6px 12px; border-radius: 4px;
      background: var(--surface); color: var(--text-secondary);
      border: 1px solid var(--border);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.12);
      font-size: 0.75rem;
    }
    .spinner {
      width: 12px; height: 12px; border-radius: 50%;
      border: 2px solid var(--border); border-top-color: var(--loading-bar, var(--accent));
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    @media (prefers-reduced-motion: reduce) {
      .indicator { animation: none; left: 0; width: 100%; opacity: 0.6; }
      .spinner { animation: none; }
    }
  `],
})
export class LoadingBarComponent {
  readonly loading = inject(LoadingService);
}

