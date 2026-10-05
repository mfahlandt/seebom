import { describe, expect, it } from 'vitest';
import { scopeClass, scopeLabel, scopeOf, scopeTitle } from './dependency-scope';

describe('dependency-scope', () => {
  it('labels every scope and falls back to unknown', () => {
    expect(scopeLabel('direct')).toBe('DIRECT');
    expect(scopeLabel('transitive')).toBe('TRANSITIVE');
    expect(scopeLabel('root')).toBe('ROOT');
    expect(scopeLabel(undefined)).toBe('UNKNOWN');
  });

  it('adds the depth to transitive titles only', () => {
    expect(scopeTitle('transitive', 3)).toContain('depth 3');
    expect(scopeTitle('direct', 1)).not.toContain('depth');
  });

  it('maps a package name through package_scopes', () => {
    expect(scopeOf({ a: 'direct' }, 'a')).toBe('direct');
    expect(scopeOf({ a: 'direct' }, 'b')).toBe('unknown');
    expect(scopeOf(undefined, 'a')).toBe('unknown');
  });

  it('derives a css class', () => {
    expect(scopeClass('direct')).toBe('scope-direct');
    expect(scopeClass(undefined)).toBe('scope-unknown');
  });
});
