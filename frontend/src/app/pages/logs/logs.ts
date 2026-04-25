import { Component, inject, signal, computed, OnInit, OnDestroy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe, JsonPipe } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { Subject, debounceTime, takeUntil } from 'rxjs';
import { LogService, LogFilters } from '../../core/services/log.service';
import { CacheService } from '../../core/services/cache.service';
import { RawLog, PaginatedResponse } from '../../core/models';

@Component({
  selector: 'app-logs',
  imports: [FormsModule, DatePipe, JsonPipe],
  templateUrl: './logs.html',
  styleUrl: './logs.scss'
})
export class LogsPage implements OnInit, OnDestroy {
  private svc     = inject(LogService);
  private cache   = inject(CacheService);
  private route   = inject(ActivatedRoute);

  private defaultResult = this.cache.signal<PaginatedResponse<RawLog>>('logs_default');
  private filterResult  = signal<PaginatedResponse<RawLog> | null>(null);
  isFiltered            = signal(false);
  private destroy$      = new Subject<void>();
  private search$       = new Subject<string>();

  result      = computed(() => this.isFiltered() ? this.filterResult() : this.defaultResult());
  loading     = signal(false);
  error       = signal('');
  selected    = signal<RawLog | null>(null);
  filtersOpen = signal(false);

  filters: LogFilters = {};

  constructor() {
    this.search$.pipe(debounceTime(400), takeUntil(this.destroy$)).subscribe(() => {
      this.applyFilters();
    });
  }

  ngOnInit() {
    // Si venimos desde una alerta, los query params pre-rellenan los filtros
    const qp = this.route.snapshot.queryParams;
    const hasParams = qp['search'] || qp['source_system'] || qp['source_ip'] || qp['from'] || qp['to'];

    if (hasParams) {
      if (qp['search'])        this.filters.search        = qp['search'];
      if (qp['source_system']) this.filters.source_system = qp['source_system'];
      if (qp['source_ip'])     this.filters.source_ip     = qp['source_ip'];
      if (qp['from'])          this.filters.from          = qp['from'];
      if (qp['to'])            this.filters.to            = qp['to'];
      this.applyFilters();
    } else if (!this.defaultResult()) {
      this.loading.set(true);
      this.svc.list({ page: 1 }).pipe(takeUntil(this.destroy$)).subscribe({
        next: data => { this.cache.set('logs_default', data); this.loading.set(false); },
        error: () => { this.error.set('Error al cargar logs.'); this.loading.set(false); }
      });
    }
  }

  ngOnDestroy() { this.destroy$.next(); this.destroy$.complete(); }

  onSearchInput() { this.search$.next(this.filters.search ?? ''); }

  applyFilters() {
    this.isFiltered.set(true);
    this.loading.set(true);
    this.error.set('');
    this.svc.list({ ...this.filters, page: 1 }).subscribe({
      next: r  => { this.filterResult.set(r); this.loading.set(false); },
      error: () => { this.error.set('Error al cargar logs.'); this.loading.set(false); }
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

  open(log: RawLog) { this.selected.set(log); }
  close()           { this.selected.set(null); }
}
