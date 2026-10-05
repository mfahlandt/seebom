import { TestBed } from '@angular/core/testing';
import { describe, expect, it, beforeEach } from 'vitest';
import { ScopeBadgeComponent } from './scope-badge.component';

describe('ScopeBadgeComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [ScopeBadgeComponent] }).compileComponents();
  });

  it('renders the scope label and class', () => {
    const fixture = TestBed.createComponent(ScopeBadgeComponent);
    fixture.componentInstance.scope = 'transitive';
    fixture.componentInstance.depth = 4;
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement.querySelector('.scope-badge');
    expect(el.textContent?.trim()).toBe('TRANSITIVE');
    expect(el.classList.contains('scope-transitive')).toBe(true);
    expect(el.title).toContain('depth 4');
  });

  it('falls back to unknown when no scope is given', () => {
    const fixture = TestBed.createComponent(ScopeBadgeComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement.querySelector('.scope-badge');
    expect(el.textContent?.trim()).toBe('UNKNOWN');
    expect(el.classList.contains('scope-unknown')).toBe(true);
  });
});
