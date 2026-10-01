import { ParentSource } from '../core/api.models';

/**
 * Says how a project's parent was resolved, for tooltips and hints.
 *
 * The automatic sources name the owner they grouped by, so a reader who
 * disagrees can see why and knows what to put into the mapping file.
 */
export function parentSourceLabel(source?: ParentSource | string, owner?: string): string {
  const by = owner ? ` "${owner}"` : '';
  switch (source) {
    case 'config':
      return 'Grouped by the project groups mapping file';
    case 'explicit':
      return 'Assigned at ingest (bucket, path layout or upload)';
    case 'tag':
      return 'Grouped by a tag naming the parent project';
    case 'repo':
      return `Grouped by repository owner${by}`;
    case 'document':
      return `Grouped by the owner in the SBOM document name${by}`;
    case 'purl':
      return `Grouped by package namespace${by}`;
    case 'supplier':
      return `Grouped by supplier${by}`;
    default:
      return '';
  }
}

