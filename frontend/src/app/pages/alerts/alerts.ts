import { Component, inject, signal, computed, OnDestroy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { Router } from '@angular/router';
import { Subject, debounceTime, takeUntil } from 'rxjs';
import { AlertService, AlertFilters } from '../../core/services/alert.service';
import { CacheService } from '../../core/services/cache.service';
import { AuthService } from '../../core/services/auth.service';
import { Alert, PaginatedResponse } from '../../core/models';

@Component({
  selector: 'app-alerts',
  imports: [FormsModule, DatePipe],
  templateUrl: './alerts.html',
  styleUrl: './alerts.scss'
})
export class AlertsPage implements OnDestroy {
  private svc    = inject(AlertService);
  private cache  = inject(CacheService);
  private router = inject(Router);
  auth           = inject(AuthService);

  private defaultResult = this.cache.signal<PaginatedResponse<Alert>>('alerts_default');
  private filterResult  = signal<PaginatedResponse<Alert> | null>(null);
  isFiltered            = signal(false);
  private destroy$      = new Subject<void>();
  private search$       = new Subject<string>();

  result      = computed(() => this.isFiltered() ? this.filterResult() : this.defaultResult());
  loading     = signal(false);
  error       = signal('');
  selected    = signal<Alert | null>(null);
  filtersOpen = signal(false);

  filters: AlertFilters = {};

  constructor() {
    this.search$.pipe(debounceTime(400), takeUntil(this.destroy$)).subscribe(() => {
      this.applyFilters();
    });
  }

  ngOnDestroy() { this.destroy$.next(); this.destroy$.complete(); }

  onSearchInput() { this.search$.next(this.filters.search ?? ''); }

  applyFilters() {
    this.isFiltered.set(true);
    this.loading.set(true);
    this.error.set('');
    this.svc.list({ ...this.filters, page: 1 }).subscribe({
      next: r  => { this.filterResult.set(r); this.loading.set(false); },
      error: () => { this.error.set('Error al cargar alertas.'); this.loading.set(false); }
    });
  }

  toggleFilters() { this.filtersOpen.update(v => !v); }

  resetFilters() {
    this.filters = {};
    this.isFiltered.set(false);
    this.filterResult.set(null);
    this.error.set('');
  }

  goTo(page: number) {
    this.loading.set(true);
    const params = this.isFiltered() ? { ...this.filters, page } : { page };
    this.svc.list(params).subscribe({
      next: r  => { this.filterResult.set(r); this.isFiltered.set(true); this.loading.set(false); },
      error: () => { this.loading.set(false); }
    });
  }

  open(alert: Alert)  { this.selected.set(alert); }
  close()             { this.selected.set(null); }

  viewRelatedLogs(alert: Alert) {
    const qp: Record<string, string> = {};
    if (alert.source_system) qp['source_system'] = alert.source_system;
    if (alert.source_ip)     qp['search']        = alert.source_ip;

    this.close();
    this.router.navigate(['/app/logs'], { queryParams: qp });
  }

  deleteAlert(alert: Alert) {
    if (!confirm(`¿Eliminar la alerta "${alert.title}"? Esta acción no se puede deshacer.`)) return;
    this.svc.delete(alert.id).subscribe({
      next: () => {
        const r = this.result();
        if (r) {
          const updated = { ...r, data: r.data.filter(a => a.id !== alert.id), total: r.total - 1 };
          if (this.isFiltered()) this.filterResult.set(updated);
          else this.cache.set('alerts_default', updated);
        }
        if (this.selected()?.id === alert.id) this.close();
      },
      error: () => this.error.set('Error al eliminar la alerta.')
    });
  }

  changeStatus(alert: Alert, status: string) {
    this.svc.updateStatus(alert.id, status).subscribe({
      next: updated => {
        const r = this.result();
        if (r) {
          const updated_list = { ...r, data: r.data.map(a => a.id === updated.id ? updated : a) };
          if (this.isFiltered()) this.filterResult.set(updated_list);
          else this.cache.set('alerts_default', updated_list);
        }
        if (this.selected()?.id === updated.id) this.selected.set(updated);
      },
      error: () => this.error.set('Error al cambiar el estado de la alerta.')
    });
  }

  severityClass(name?: string) { return `badge badge-${name?.toLowerCase() ?? 'low'}`; }
  statusClass(s: string)       { return `badge badge-${s}`; }
  severityLabel(k?: string) {
    return { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }[k ?? ''] ?? (k ?? '');
  }
  statusLabel(s: string) {
    return { open: 'Abierta', in_progress: 'En proceso', resolved: 'Resuelta', dismissed: 'Descartada' }[s] ?? s;
  }
}
