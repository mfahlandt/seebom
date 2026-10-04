/**
 * Human-readable labels for package license provenance (`license_source`).
 *
 * The vocabulary is defined in backend/internal/license/source.go and
 * documented on the "License Resolution" docs page; keep all three in sync.
 */

const ORIGIN_LABELS: Record<string, string> = {
  declared: 'Declared in the SBOM',
  github: 'GitHub repository license',
  npm: 'npm registry',
  nuget: 'NuGet registry',
  depsdev: 'deps.dev',
  packagist: 'Packagist',
  pypi: 'PyPI',
};

const REASON_LABELS: Record<string, string> = {
  'first-party': 'First-party component (the project itself or one of its own modules)',
  'not-published': 'Not published on a public registry (private or internal package)',
  'no-license-upstream': 'The registry has the package, but no license is declared upstream',
  'no-purl': 'No package URL, so there is nothing to look up',
  'unsupported-ecosystem': 'No license resolver exists for this ecosystem',
  unresolved: 'All lookups failed or returned no result',
  unrecorded: 'Ingested before BOMHort recorded license sources; re-scan to fill in',
};

const MODIFIER_LABELS: Record<string, string> = {
  latest: 'taken from the latest release, not the exact version',
  normalized: 'normalized to an SPDX identifier',
};

export interface LicenseSourceInfo {
  origin: string;
  modifiers: string[];
  resolved: boolean;
  label: string;
}

export function describeLicenseSource(source?: string | null): LicenseSourceInfo | null {
  if (!source) {
    return null;
  }
  const [origin, ...modifiers] = source.split('+');
  const resolved = !(origin in REASON_LABELS);
  const base = ORIGIN_LABELS[origin] ?? REASON_LABELS[origin] ?? origin;
  const extras = modifiers.map((m) => MODIFIER_LABELS[m] ?? m);
  const label = extras.length ? `${base} (${extras.join('; ')})` : base;
  return { origin, modifiers, resolved, label };
}

/** Tooltip text for a dependency's license cell; empty when nothing was recorded. */
export function licenseSourceTooltip(source?: string | null): string {
  const info = describeLicenseSource(source);
  if (!info) {
    return '';
  }
  return info.resolved ? `Source: ${info.label}` : `Unknown: ${info.label}`;
}
