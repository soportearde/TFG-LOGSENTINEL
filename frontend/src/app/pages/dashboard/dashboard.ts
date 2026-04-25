import { Component, inject, computed } from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe, DecimalPipe } from '@angular/common';
import { CacheService } from '../../core/services/cache.service';
import { DashboardData } from '../../core/models';

@Component({
  selector: 'app-dashboard',
  imports: [RouterLink, DatePipe, DecimalPipe],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss'
})
export class DashboardPage {
  private cache = inject(CacheService);

  data = this.cache.signal<DashboardData>('dashboard');

  severityOrder = ['critical', 'high', 'medium', 'low'];

  chartBars = computed(() => {
    const d = this.data();
    if (!d) return [];
    const levels = d.alerts_by_level ?? {};
    const max = Math.max(...Object.values(levels), 1);
    return this.severityOrder
      .filter(k => levels[k] !== undefined)
      .map(k => ({
        label: this.severityLabel(k),
        value: levels[k],
        pct: Math.round((levels[k] / max) * 100),
        cls: k
      }));
  });

  severityLabel(k: string): string {
    return { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }[k] ?? k;
  }

  severityClass(name?: string): string {
    return `badge badge-${name?.toLowerCase() ?? 'low'}`;
  }

  statusClass(status: string): string {
    return `badge badge-${status}`;
  }
}
