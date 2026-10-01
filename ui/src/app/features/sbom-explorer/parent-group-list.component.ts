import { Component, Input, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ProjectGroupItem } from '../../core/api.models';
import { ProjectGroupListComponent } from './project-group-list.component';
import { parentSourceLabel } from '../../shared/parent-source';

/**
 * The top level of the SBOM Explorer's "By project" view: parents (products)
 * with their member projects, each of which expands to its versions.
 *
 * Three levels: parent → project → version. The lower two are
 * ProjectGroupListComponent, embedded, so expanding a project inside a group
 * behaves exactly like expanding it at the top level.
 *
 * A project without a parent is a group of one and is rendered as that
 * plain project row, not as a group containing itself.
 */
@Component({
  selector: 'app-parent-group-list',
  standalone: true,
  imports: [CommonModule, RouterModule, ProjectGroupListComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="group-list">
      <ng-container *ngFor="let g of groups; trackBy: trackByGroup">
        <app-project-group-list *ngIf="isSingle(g)" [projects]="g.members" [embedded]="true" />

        <div *ngIf="!isSingle(g)" class="group">
          <div class="group-row">
            <button
              type="button"
              class="expander"
              [attr.aria-expanded]="isExpanded(g.name)"
              [attr.aria-label]="(isExpanded(g.name) ? 'Collapse ' : 'Expand ') + g.name"
              (click)="toggle(g.name)"
            >{{ isExpanded(g.name) ? '▾' : '▸' }}</button>
            <div class="main">
              <a *ngIf="g.is_project" [routerLink]="['/projects', g.name]" class="name">{{ g.name }}</a>
              <span *ngIf="!g.is_project" class="name label" title="Parent without SBOMs of its own">{{ g.name }}</span>
              <span class="badge" [title]="g.project_count + ' projects in this group'">{{ g.project_count | number }} projects</span>
              <span class="hint" *ngIf="hint(g) as h" [title]="h">{{ h }}</span>
            </div>
            <!--
              De-duplicated across every version of every member, like the
              project rows below — so not the sum of them, and the tooltips
              say so.
            -->
            <span class="packages" title="Distinct components across all projects and versions (de-duplicated)">{{ g.package_count | number }} packages</span>
            <span class="vulns" [class.has-vulns]="g.vuln_count > 0" title="Distinct findings across all projects and versions (de-duplicated)">{{ g.vuln_count | number }} vulns</span>
            <span class="date">{{ g.latest_ingested | date:'short' }}</span>
          </div>
          <div class="members" *ngIf="isExpanded(g.name)">
            <app-project-group-list [projects]="g.members" [embedded]="true" />
          </div>
        </div>
      </ng-container>
    </div>
  `,
  styles: [`
    .group-list { flex: 1; min-height: 400px; overflow-y: auto; }
    .group-row { display: flex; align-items: center; gap: 16px; height: 52px; padding-right: 12px; border-bottom: 1px solid var(--border); }
    .expander { background: none; border: none; cursor: pointer; color: var(--text-muted); font-size: 0.8rem; width: 28px; flex-shrink: 0; padding: 4px; }
    .expander:hover { color: var(--accent); }
    .main { flex: 1; display: flex; align-items: center; gap: 10px; min-width: 0; }
    .name { font-weight: 700; font-size: 0.88rem; color: inherit; text-decoration: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    a.name:hover { color: var(--accent); }
    .name.label { font-style: italic; }
    .badge { background: var(--status-info-bg); color: var(--accent-hover); padding: 2px 6px; border-radius: 10px; font-size: 0.7rem; white-space: nowrap; }
    .hint { color: var(--text-muted); font-size: 0.7rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .packages { color: var(--text-secondary); font-size: 0.8rem; width: 110px; }
    .vulns { font-size: 0.8rem; width: 80px; color: var(--text-secondary); }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }
    .date { color: var(--text-muted); font-size: 0.75rem; width: 110px; }
    .members { padding-left: 28px; border-bottom: 1px solid var(--border); background: var(--surface-alt); }
    @media (max-width: 760px) { .hint, .date, .packages { display: none; } }
  `],
})
export class ParentGroupListComponent {
  /** One page of groups, loaded and paged by the parent component. */
  @Input() groups: ProjectGroupItem[] = [];

  private readonly expanded = new Set<string>();

  constructor(private readonly cdr: ChangeDetectorRef) {}

  /** Called by the parent when the underlying listing changes. */
  reset(): void {
    this.expanded.clear();
    this.cdr.markForCheck();
  }

  /** A project without a parent: rendered as the plain project row. */
  isSingle(g: ProjectGroupItem): boolean {
    return g.project_count === 1 && g.is_project && g.members.length === 1 && g.members[0].project_name === g.name;
  }

  isExpanded(name: string): boolean {
    return this.expanded.has(name);
  }

  toggle(name: string): void {
    if (this.expanded.has(name)) {
      this.expanded.delete(name);
    } else {
      this.expanded.add(name);
    }
    this.cdr.markForCheck();
  }

  /** Why the members were grouped, e.g. 'Grouped by repository owner "argoproj"'. */
  hint(g: ProjectGroupItem): string {
    if (g.sources.length === 1) {
      return parentSourceLabel(g.sources[0], g.owner);
    }
    if (g.sources.length > 1) {
      return 'Grouped by ' + g.sources.join(', ');
    }
    return '';
  }

  trackByGroup(_index: number, g: ProjectGroupItem): string {
    return g.name;
  }
}

