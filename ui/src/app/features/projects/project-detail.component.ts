import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { RouterModule, ActivatedRoute } from '@angular/router';
import { Subject, forkJoin, of } from 'rxjs';
import { catchError, debounceTime, distinctUntilChanged, switchMap, takeUntil } from 'rxjs/operators';
import { ApiService } from '../../core/api.service';
import {
  ProjectDetail,
  ProjectListItem,
  ProjectPackageItem,
  SBOMListItem,
  VulnerabilityListItem,
} from '../../core/api.models';

type Tab = 'versions' | 'vulns' | 'packages' | 'subprojects';

/**
 * One project as a unit (#398).
 *
 * Before this page existed, clicking a project ran a substring search over
 * the SBOM list — "kubernetes" returned 1 368 documents, eleven of which were
 * Kubernetes. This page is scoped by project identity, aggregates across all
 * of the project's versions with de-duplicated counts, and — through tags
 * that are themselves project names — shows the way up to a parent and down
 * to sub-projects.
 */
@Component({
  selector: 'app-project-detail',
  standalone: true,
  imports: [CommonModule, FormsModule, ScrollingModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="project-detail" *ngIf="detail">
      <div class="header">
        <a routerLink="/projects" class="back">← Projects</a>
        <h1>{{ detail.project_name }}</h1>
        <span class="product-version" *ngIf="detail.latest_version" [title]="'Latest version: ' + detail.latest_version">{{ detail.latest_version }}</span>
        <span class="badge">{{ detail.sbom_count }} {{ detail.sbom_count === 1 ? 'version' : 'versions' }}</span>
      </div>

      <!--
        Hierarchy row. Parents are tags that are also projects; the parent's
        page is where its own SBOMs live. Sub-projects are the projects tagged
        with this name — that listing already exists as /projects?tag=.
        Plain groupings (tier, org) are shown as filter links.
      -->
      <div class="context-row" *ngIf="detail.parents.length || detail.related_project_count || otherTags.length">
        <ng-container *ngIf="detail.parents.length">
          <span class="ctx-label">Part of</span>
          <a *ngFor="let p of detail.parents" [routerLink]="['/projects', p]" class="ctx-chip parent" [title]="'Open parent project ' + p">↑ {{ p }}</a>
        </ng-container>
        <ng-container *ngIf="detail.related_project_count">
          <span class="ctx-label">Has</span>
          <a routerLink="/projects" [queryParams]="{tag: detail.project_name}" class="ctx-chip children"
             [title]="'List projects tagged with ' + detail.project_name">
            ↓ {{ detail.related_project_count | number }} {{ detail.related_project_count === 1 ? 'sub-project' : 'sub-projects' }}
          </a>
        </ng-container>
        <ng-container *ngIf="otherTags.length">
          <span class="ctx-label">In</span>
          <a *ngFor="let t of otherTags" routerLink="/projects" [queryParams]="{tag: t}" class="ctx-chip" [title]="'Grouping: ' + t">{{ t }}</a>
        </ng-container>
      </div>

      <div class="source-row" *ngIf="detail.source_repo || detail.clusters.length">
        <ng-container *ngIf="detail.source_repo">
          <span class="source-label">Source:</span>
          <a *ngIf="isUrl(detail.source_repo)" [href]="detail.source_repo" target="_blank" rel="noopener" class="source-link">
            {{ detail.source_repo }} <span class="link-icon">↗</span>
          </a>
          <span *ngIf="!isUrl(detail.source_repo)" class="source-value">{{ detail.source_repo }}</span>
        </ng-container>
        <ng-container *ngIf="detail.clusters.length">
          <span class="source-label deployed">Deployed:</span>
          <span *ngFor="let c of detail.clusters" class="owner-badge cluster-badge" [title]="'Cluster'">{{ c }}</span>
          <span *ngFor="let n of detail.namespaces" class="owner-badge" [title]="'Namespace'">{{ n }}</span>
        </ng-container>
      </div>

      <!--
        The numbers are de-duplicated across versions — the title spells it
        out because the same page used to show a sum and readers will compare.
      -->
      <div class="stats-row">
        <div class="stat" title="Distinct components across all versions"><strong>{{ detail.package_count | number }}</strong> packages</div>
        <div class="stat" title="Distinct (vulnerability, package) pairs across all versions"><strong>{{ detail.vuln_count | number }}</strong> vulnerabilities</div>
        <div class="stat critical" *ngIf="detail.critical_vulns">{{ detail.critical_vulns | number }} critical</div>
        <div class="stat high" *ngIf="detail.high_vulns">{{ detail.high_vulns | number }} high</div>
        <div class="stat medium" *ngIf="detail.medium_vulns">{{ detail.medium_vulns | number }} medium</div>
        <div class="stat low" *ngIf="detail.low_vulns">{{ detail.low_vulns | number }} low</div>
        <div class="stat date" *ngIf="detail.latest_ingested" [title]="'Latest SBOM ingested'">{{ detail.latest_ingested | date:'mediumDate' }}</div>
      </div>

      <div class="tabs">
        <button [class.active]="activeTab === 'versions'" (click)="activeTab = 'versions'">
          Versions ({{ sboms.length | number }})
        </button>
        <button [class.active]="activeTab === 'vulns'" (click)="activeTab = 'vulns'">
          Vulnerabilities ({{ vulns.length | number }})
        </button>
        <button [class.active]="activeTab === 'packages'" (click)="selectPackages()">
          Packages ({{ packagesTotal | number }})
        </button>
        <button *ngIf="detail.related_project_count" [class.active]="activeTab === 'subprojects'" (click)="selectSubprojects()">
          Sub-projects ({{ detail.related_project_count | number }})
        </button>
      </div>

      <!-- Versions -->
      <div *ngIf="activeTab === 'versions'" class="tab-content">
        <cdk-virtual-scroll-viewport itemSize="56" class="viewport">
          <div *cdkVirtualFor="let sbom of sboms; trackBy: trackBySbom" class="row">
            <a [routerLink]="['/sboms', sbom.sbom_id]" class="row-link">
              <div class="row-main">
                <span class="row-title">
                  {{ sbom.document_name }}
                  <span class="product-version" *ngIf="sbom.document_version">{{ sbom.document_version }}</span>
                </span>
                <span class="row-meta">
                  <span class="owner-badge cluster-badge" *ngIf="sbom.cluster">{{ sbom.cluster }}</span>
                  <span class="owner-badge" *ngIf="sbom.namespace">{{ sbom.namespace }}</span>
                  <span class="mono">{{ sbom.source_file }}</span>
                </span>
              </div>
              <div class="row-stats">
                <span class="stat-inline">{{ sbom.package_count | number }} pkgs</span>
                <span class="stat-inline" [class.has-vulns]="sbom.vuln_count > 0">{{ sbom.vuln_count | number }} vulns</span>
                <span class="date">{{ sbom.ingested_at | date:'mediumDate' }}</span>
              </div>
            </a>
          </div>
        </cdk-virtual-scroll-viewport>
        <div *ngIf="sboms.length < sbomsTotal" class="load-more">
          <button (click)="loadMoreSboms()" class="load-more-btn">Load more ({{ sboms.length }} / {{ sbomsTotal }})</button>
        </div>
      </div>

      <!-- Vulnerabilities: one row per (vuln, package), with reach across versions -->
      <div *ngIf="activeTab === 'vulns'" class="tab-content">
        <div *ngIf="vulns.length === 0" class="empty">No vulnerabilities across any version.</div>
        <cdk-virtual-scroll-viewport *ngIf="vulns.length > 0" itemSize="56" class="viewport">
          <div *cdkVirtualFor="let vuln of vulns; trackBy: trackByVuln" class="vuln-row">
            <span class="severity-badge" [class]="'sev-' + vuln.severity.toLowerCase()">{{ vuln.severity }}</span>
            <div class="vuln-info">
              <a [routerLink]="['/cve-impact']" [queryParams]="{vuln: vuln.vuln_id}" class="vuln-id">{{ vuln.vuln_id }}</a>
              <span class="summary">{{ vuln.summary }}</span>
            </div>
            <span class="vex-badge" *ngIf="vuln.vex_status" [class]="'vex-' + vuln.vex_status">{{ vuln.vex_status | titlecase }}</span>
            <span class="reach" *ngIf="vuln.affected_sboms"
                  [class.all]="vuln.affected_sboms === detail.sbom_count"
                  [title]="'Present in ' + vuln.affected_sboms + ' of ' + detail.sbom_count + ' versions'">
              {{ vuln.affected_sboms }}/{{ detail.sbom_count }}
            </span>
            <span class="purl">{{ vuln.purl }}</span>
          </div>
        </cdk-virtual-scroll-viewport>
      </div>

      <!-- Packages: distinct components, most exposed first -->
      <div *ngIf="activeTab === 'packages'" class="tab-content">
        <div class="search-bar">
          <input type="text" [(ngModel)]="packageSearch" (ngModelChange)="onPackageSearch($event)"
                 placeholder="Filter components by name or PURL…" class="search-input" />
          <span class="search-loading" *ngIf="packagesLoading">⏳</span>
        </div>
        <div *ngIf="!packagesLoading && packages.length === 0" class="empty">
          No components<span *ngIf="packageSearch"> matching "{{ packageSearch }}"</span>.
        </div>
        <cdk-virtual-scroll-viewport *ngIf="packages.length > 0" itemSize="48" class="viewport">
          <div *cdkVirtualFor="let pkg of packages; trackBy: trackByPackage" class="pkg-row">
            <div class="pkg-info">
              <a [routerLink]="['/package-search', pkg.name]" class="pkg-name">{{ pkg.name }}</a>
              <span class="pkg-version">{{ pkg.version }}</span>
            </div>
            <span class="reach" [class.all]="pkg.sbom_count === detail.sbom_count"
                  [title]="'Shipped in ' + pkg.sbom_count + ' of ' + detail.sbom_count + ' versions'">
              {{ pkg.sbom_count }}/{{ detail.sbom_count }}
            </span>
            <span class="stat-inline vulns" [class.has-vulns]="pkg.vuln_count > 0" [title]="'Distinct vulnerability ids on this component'">
              {{ pkg.vuln_count | number }} vulns
            </span>
            <span class="purl">{{ pkg.purl }}</span>
          </div>
        </cdk-virtual-scroll-viewport>
        <div *ngIf="packages.length < packagesTotal" class="load-more">
          <button (click)="loadMorePackages()" class="load-more-btn">Load more ({{ packages.length }} / {{ packagesTotal }})</button>
        </div>
      </div>

      <!-- Sub-projects: projects tagged with this project's name -->
      <div *ngIf="activeTab === 'subprojects'" class="tab-content">
        <cdk-virtual-scroll-viewport itemSize="56" class="viewport">
          <div *cdkVirtualFor="let p of subprojects; trackBy: trackByProject" class="row">
            <a [routerLink]="['/projects', p.project_name]" class="row-link">
              <div class="row-main">
                <span class="row-title">{{ p.project_name }}</span>
                <span class="row-meta">{{ p.sbom_count }} {{ p.sbom_count === 1 ? 'version' : 'versions' }}</span>
              </div>
              <div class="row-stats">
                <span class="stat-inline">{{ p.package_count | number }} pkgs</span>
                <span class="stat-inline" [class.has-vulns]="p.vuln_count > 0">{{ p.vuln_count | number }} vulns</span>
                <span class="date">{{ p.latest_ingested | date:'mediumDate' }}</span>
              </div>
            </a>
          </div>
        </cdk-virtual-scroll-viewport>
        <div *ngIf="subprojects.length < (detail.related_project_count || 0)" class="load-more">
          <a routerLink="/projects" [queryParams]="{tag: detail.project_name}" class="load-more-btn">
            See all {{ detail.related_project_count | number }} in the project list →
          </a>
        </div>
      </div>
    </div>

    <div class="not-found" *ngIf="notFound">
      <a routerLink="/projects" class="back">← Projects</a>
      <h1>Project not found</h1>
      <p>No SBOM resolves to <code>{{ requestedName }}</code>.</p>
    </div>
  `,
  styles: [`
    .project-detail, .not-found { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }
    .back { color: var(--text-secondary); text-decoration: none; font-size: 0.8rem; }
    .back:hover { color: var(--accent); }
    h1 { margin: 0; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .badge { background: var(--surface-alt); padding: 2px 8px; border-radius: 2px; font-size: 0.7rem; color: var(--text-secondary); border: 1px solid var(--border); }
    .product-version {
      font-family: monospace; font-size: 0.75rem; color: var(--accent-hover);
      background: var(--status-info-bg); border: 1px solid var(--accent); border-radius: 2px;
      padding: 1px 6px; margin-left: 6px;
    }

    .context-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; font-size: 0.75rem; }
    .ctx-label { color: var(--text-muted); margin-left: 6px; }
    .ctx-label:first-child { margin-left: 0; }
    .ctx-chip {
      display: inline-block; padding: 2px 8px; border-radius: 12px; text-decoration: none;
      background: var(--surface); color: var(--text-secondary); border: 1px solid var(--border);
      font-size: 0.72rem; transition: all 0.15s;
    }
    .ctx-chip:hover { border-color: var(--accent); color: var(--accent); }
    .ctx-chip.parent { border-style: dashed; color: var(--accent-hover); font-weight: 600; }
    .ctx-chip.children { background: var(--status-info-bg); color: var(--accent-hover); border-color: var(--accent); font-weight: 600; }

    .source-row { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 0.78rem; flex-wrap: wrap; }
    .source-label { color: var(--text-secondary); font-weight: 500; flex-shrink: 0; }
    .source-label.deployed { margin-left: 12px; }
    .source-link { color: var(--accent); text-decoration: none; font-family: monospace; font-size: 0.72rem; display: inline-flex; align-items: center; gap: 4px; }
    .source-link:hover { text-decoration: underline; }
    .source-value { font-family: monospace; font-size: 0.72rem; }
    .owner-badge {
      display: inline-block; padding: 1px 6px; border-radius: 2px; font-size: 0.65rem; font-weight: 500;
      background: var(--surface-alt); color: var(--text-secondary); border: 1px solid var(--border);
    }
    .cluster-badge { background: var(--status-info-bg); color: var(--accent-hover); border-color: var(--accent); }

    .stats-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
    .stat { background: var(--surface-alt); padding: 6px 14px; border-radius: 2px; font-size: 0.8rem; border: 1px solid var(--border); }
    .stat.date { color: var(--text-muted); margin-left: auto; }
    .critical { color: var(--severity-critical); }
    .high { color: var(--severity-high); }
    .medium { color: var(--status-warning); }
    .low { color: var(--text-secondary); }

    .tabs { display: flex; gap: 2px; margin-bottom: 16px; border-bottom: 1px solid var(--border); }
    .tabs button {
      padding: 8px 18px; border: none; background: transparent; cursor: pointer;
      font-size: 0.8rem; border-radius: 0; transition: all 0.15s;
      font-family: inherit; color: var(--text-secondary); font-weight: 500;
      border-bottom: 2px solid transparent; margin-bottom: -1px;
    }
    .tabs button.active { color: var(--text); border-bottom-color: var(--accent); }
    .tab-content { flex: 1; min-height: 0; display: flex; flex-direction: column; }
    .viewport { flex: 1; min-height: 400px; }
    .empty { padding: 32px; text-align: center; color: var(--text-muted); font-size: 0.85rem; }

    .row { height: 52px; display: flex; align-items: center; border-bottom: 1px solid var(--border); }
    .row-link { display: flex; align-items: center; justify-content: space-between; width: 100%; padding: 0 12px; text-decoration: none; color: inherit; height: 100%; }
    .row-link:hover { background: var(--surface-alt); }
    .row-main { display: flex; flex-direction: column; gap: 2px; flex: 1; min-width: 0; }
    .row-title { font-weight: 600; font-size: 0.82rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-meta { font-size: 0.7rem; color: var(--text-muted); display: flex; gap: 6px; align-items: center; overflow: hidden; }
    .mono { font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-stats { display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
    .stat-inline { font-size: 0.78rem; color: var(--text-secondary); }
    .stat-inline.vulns { width: 80px; text-align: right; }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }
    .date { color: var(--text-muted); font-size: 0.72rem; width: 100px; text-align: right; }

    .vuln-row { height: 52px; display: flex; align-items: center; gap: 12px; padding: 0 12px; border-bottom: 1px solid var(--border); }
    .severity-badge {
      padding: 2px 7px; border-radius: 2px; font-size: 0.65rem; font-weight: 600;
      text-transform: uppercase; min-width: 64px; text-align: center; letter-spacing: 0.03em;
    }
    .sev-critical { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .sev-high { background: var(--severity-high-bg); color: var(--severity-high); }
    .sev-medium { background: var(--severity-high-bg); color: var(--status-warning); }
    .sev-low { background: var(--bg); color: var(--text-secondary); }
    .vuln-info { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
    .vuln-id { font-weight: 600; font-size: 0.8rem; color: var(--accent); text-decoration: none; }
    .summary { color: var(--text-secondary); font-size: 0.75rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .vex-badge { padding: 2px 6px; border-radius: 2px; font-size: 0.6rem; font-weight: 600; }
    .vex-not_affected { background: var(--status-success-bg); color: var(--status-success); }
    .vex-fixed { background: var(--status-info-bg); color: var(--accent-hover); }
    .vex-affected { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .vex-under_investigation { background: var(--severity-high-bg); color: var(--status-warning); }
    .purl { color: var(--text-secondary); font-size: 0.7rem; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    /* Reach: in how many of the project's versions. Full reach is emphasised —
       a finding in every version is a project problem, not a version problem. */
    .reach {
      font-family: monospace; font-size: 0.7rem; padding: 1px 6px; border-radius: 2px;
      background: var(--bg); color: var(--text-secondary); border: 1px solid var(--border);
      min-width: 44px; text-align: center; cursor: help;
    }
    .reach.all { color: var(--text); font-weight: 600; border-color: var(--text-secondary); }

    .pkg-row { height: 44px; display: flex; align-items: center; gap: 12px; padding: 0 12px; border-bottom: 1px solid var(--border); }
    .pkg-info { flex: 1; display: flex; align-items: baseline; gap: 8px; min-width: 0; }
    .pkg-name { font-weight: 600; font-size: 0.8rem; color: var(--accent); text-decoration: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .pkg-name:hover { text-decoration: underline; }
    .pkg-version { font-family: monospace; font-size: 0.72rem; color: var(--text-secondary); }

    .search-bar { position: relative; margin-bottom: 8px; }
    .search-input {
      width: 100%; padding: 8px 36px 8px 12px; font-size: 0.82rem; box-sizing: border-box;
      border: 1px solid var(--border); border-radius: 4px; background: var(--surface); color: var(--text);
      font-family: inherit; outline: none;
    }
    .search-input:focus { border-color: var(--accent); }
    .search-loading { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); font-size: 0.8rem; }

    .load-more { padding: 12px; text-align: center; }
    .load-more-btn {
      display: inline-block; padding: 8px 24px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-family: inherit;
      color: var(--text-secondary); text-decoration: none; transition: all 0.15s;
    }
    .load-more-btn:hover { border-color: var(--accent); color: var(--accent); }

    .not-found h1 { margin-top: 12px; }
    .not-found code { font-family: monospace; background: var(--surface-alt); padding: 1px 6px; border-radius: 2px; }
  `],
})
export class ProjectDetailComponent implements OnInit, OnDestroy {
  detail: ProjectDetail | null = null;
  notFound = false;
  requestedName = '';

  sboms: SBOMListItem[] = [];
  sbomsTotal = 0;
  vulns: VulnerabilityListItem[] = [];
  packages: ProjectPackageItem[] = [];
  packagesTotal = 0;
  packagesLoading = false;
  packageSearch = '';
  subprojects: ProjectListItem[] = [];

  activeTab: Tab = 'versions';

  private sbomPage = 1;
  private packagePage = 1;
  private packagesLoaded = false;
  private subprojectsLoaded = false;
  private readonly pageSize = 100;
  private readonly packageSearch$ = new Subject<string>();
  private readonly destroy$ = new Subject<void>();

  constructor(
    private readonly api: ApiService,
    private readonly route: ActivatedRoute,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Package filtering is server-side; debounce so typing does not fire a
    // request per keystroke against an arrayJoin over the project's SBOMs.
    this.packageSearch$.pipe(
      debounceTime(300),
      distinctUntilChanged(),
      takeUntil(this.destroy$),
    ).subscribe(() => {
      this.packagePage = 1;
      this.packages = [];
      this.loadPackages();
    });

    // The route param is the identity. switchMap so navigating between two
    // project pages cancels the first load instead of racing it.
    this.route.paramMap.pipe(
      switchMap((params) => {
        const name = params.get('name') ?? '';
        this.requestedName = name;
        this.reset();
        this.cdr.markForCheck();
        return forkJoin({
          detail: this.api.getProjectDetail(name),
          sboms: this.api.getProjectSboms(name, 1, this.pageSize),
          vulns: this.api.getProjectVulnerabilities(name).pipe(catchError(() => of([] as VulnerabilityListItem[]))),
        }).pipe(catchError(() => of(null)));
      }),
      takeUntil(this.destroy$),
    ).subscribe((res) => {
      if (!res) {
        this.notFound = true;
        this.cdr.markForCheck();
        return;
      }
      this.detail = res.detail;
      this.sboms = res.sboms.data;
      this.sbomsTotal = res.sboms.total;
      this.vulns = res.vulns;
      // Packages total is known from the header without loading the list;
      // the list itself loads on first tab open.
      this.packagesTotal = res.detail.package_count;
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  /** Tags that are groupings rather than parents. */
  get otherTags(): string[] {
    if (!this.detail) return [];
    const parents = new Set(this.detail.parents);
    return this.detail.tags.filter((t) => !parents.has(t));
  }

  isUrl(s: string): boolean {
    return /^https?:\/\//i.test(s);
  }

  selectPackages(): void {
    this.activeTab = 'packages';
    if (!this.packagesLoaded) {
      this.loadPackages();
    }
  }

  selectSubprojects(): void {
    this.activeTab = 'subprojects';
    if (!this.subprojectsLoaded && this.detail) {
      this.subprojectsLoaded = true;
      this.api.getProjects(1, this.pageSize, '', this.detail.project_name)
        .pipe(takeUntil(this.destroy$))
        .subscribe((resp) => {
          // The tag listing can include the project itself if it was
          // self-tagged; the count from the header already excludes it.
          this.subprojects = resp.data.filter((p) => p.project_name !== this.detail?.project_name);
          this.cdr.markForCheck();
        });
    }
  }

  onPackageSearch(term: string): void {
    this.packageSearch$.next(term.trim());
  }

  loadMoreSboms(): void {
    if (!this.detail) return;
    this.sbomPage++;
    this.api.getProjectSboms(this.detail.project_name, this.sbomPage, this.pageSize)
      .pipe(takeUntil(this.destroy$))
      .subscribe((resp) => {
        this.sboms = [...this.sboms, ...resp.data];
        this.sbomsTotal = resp.total;
        this.cdr.markForCheck();
      });
  }

  loadMorePackages(): void {
    this.packagePage++;
    this.loadPackages(true);
  }

  private loadPackages(append = false): void {
    if (!this.detail) return;
    this.packagesLoading = true;
    this.packagesLoaded = true;
    this.cdr.markForCheck();
    this.api.getProjectPackages(this.detail.project_name, this.packagePage, this.pageSize, this.packageSearch)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (resp) => {
          this.packages = append ? [...this.packages, ...resp.data] : resp.data;
          this.packagesTotal = resp.total;
          this.packagesLoading = false;
          this.cdr.markForCheck();
        },
        error: () => {
          this.packagesLoading = false;
          this.cdr.markForCheck();
        },
      });
  }

  private reset(): void {
    this.detail = null;
    this.notFound = false;
    this.sboms = [];
    this.sbomsTotal = 0;
    this.vulns = [];
    this.packages = [];
    this.packagesTotal = 0;
    this.packageSearch = '';
    this.subprojects = [];
    this.activeTab = 'versions';
    this.sbomPage = 1;
    this.packagePage = 1;
    this.packagesLoaded = false;
    this.subprojectsLoaded = false;
  }

  trackBySbom(_i: number, s: SBOMListItem): string { return s.sbom_id; }
  trackByVuln(_i: number, v: VulnerabilityListItem): string { return v.vuln_id + '|' + v.purl; }
  trackByPackage(_i: number, p: ProjectPackageItem): string { return p.purl || p.name + '@' + p.version; }
  trackByProject(_i: number, p: ProjectListItem): string { return p.project_name; }
}

