import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { secondaryVulnIds, VulnIdentity } from '../vuln-identity';

/**
 * The other names of a vulnerability (#412) as small chips next to its
 * primary id: OSV's id when the row leads with the CVE, then the remaining
 * aliases. At most `max` are shown; the rest are summarised as "+N" with
 * the full list in the tooltip.
 */
@Component({
  selector: 'app-vuln-aliases',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span class="aliases" *ngIf="ids.length" [title]="'Also known as: ' + ids.join(', ')">
      <span class="alias" *ngFor="let id of shown">{{ id }}</span>
      <span class="alias more" *ngIf="ids.length > shown.length">+{{ ids.length - shown.length }}</span>
    </span>
  `,
  styles: [`
    .aliases { display: inline-flex; flex-wrap: wrap; gap: 4px; vertical-align: middle; }
    .alias {
      font-family: var(--font-mono, monospace); font-size: 0.65rem; line-height: 1.4;
      padding: 0 5px; border-radius: 2px; white-space: nowrap;
      background: var(--bg); color: var(--text-secondary); border: 1px solid var(--border);
    }
    .alias.more { font-family: inherit; }
  `],
})
export class VulnAliasesComponent {
  @Input({ required: true }) vuln!: VulnIdentity;
  @Input() max = 2;

  get ids(): string[] { return this.vuln ? secondaryVulnIds(this.vuln) : []; }
  get shown(): string[] { return this.ids.slice(0, this.max); }
}
