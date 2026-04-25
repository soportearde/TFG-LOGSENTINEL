import { Injectable, inject } from '@angular/core';
import { Observable, Subscription, forkJoin, of, timer, concat } from 'rxjs';
import { catchError, map, tap, delay } from 'rxjs/operators';
import { DashboardService } from './dashboard.service';
import { AlertService } from './alert.service';
import { LogService } from './log.service';
import { ReportService } from './report.service';
import { RuleService } from './rule.service';
import { UserService } from './user.service';
import { CacheService } from './cache.service';

const INTERVAL_MS = 5_000; // 15 segundos

@Injectable({ providedIn: 'root' })
export class BackgroundSyncService {
  private dashboard = inject(DashboardService);
  private alerts    = inject(AlertService);
  private logs      = inject(LogService);
  private reports   = inject(ReportService);
  private rules     = inject(RuleService);
  private users     = inject(UserService);
  private cache     = inject(CacheService);

  private sub: Subscription | null = null;

  // Flujo secuencial optimizado: login → dashboard → alerts/logs → rules/users/reports
  start(): Observable<void> {
    this.stop();
    
    // Fase 1: Dashboard (inmediato después del login)
    const phase1$ = this.loadDashboard();
    
    // Fase 2: Alerts y Logs (rápido después de dashboard)
    const phase2$ = this.loadAlertsAndLogs();
    
    // Fase 3: Rules, Users y Reports (secundario)
    const phase3$ = this.loadRulesUsersReports();
    
    // Ejecutar fases secuencialmente con delays mínimos
    const sequential$ = concat(
      phase1$.pipe(delay(100)),  // Pequeño delay para asegurar UI lista
      phase2$.pipe(delay(200)),  // Delay entre fases
      phase3$.pipe(delay(300))   // Delay final
    );
    
    sequential$.subscribe({
      complete: () => {
        // Iniciar sincronización periódica completa
        this.sub = timer(INTERVAL_MS, INTERVAL_MS)
          .subscribe(() => this.syncAll().subscribe());
      }
    });
    
    return phase1$; // Devolver solo la primera fase para el login
  }

  stop(): void {
    this.sub?.unsubscribe();
    this.sub = null;
    this.cache.invalidateAll();
  }

  private safe<T>(obs: Observable<T>): Observable<T | null> {
    return obs.pipe(catchError(() => of(null)));
  }

  // Fase 1: Cargar solo datos del dashboard (más rápido posible)
  private loadDashboard(): Observable<void> {
    return this.safe(this.dashboard.get()).pipe(
      tap(data => {
        if (data) this.cache.set('dashboard', data);
      }),
      map(() => void 0)
    );
  }

  // Fase 2: Cargar alerts y logs (datos prioritarios)
  private loadAlertsAndLogs(): Observable<void> {
    return forkJoin({
      alerts: this.safe(this.alerts.list({ page: 1 })),
      logs: this.safe(this.logs.list({ page: 1 }))
    }).pipe(
      tap(res => {
        if (res.alerts) this.cache.set('alerts_default', res.alerts);
        if (res.logs) this.cache.set('logs_default', res.logs);
      }),
      map(() => void 0)
    );
  }

  // Fase 3: Cargar datos secundarios (rules, users, reports)
  private loadRulesUsersReports(): Observable<void> {
    return forkJoin({
      rules: this.safe(this.rules.list()),
      users: this.safe(this.users.list()),
      roles: this.safe(this.users.roles()),
      reports: this.safe(this.reports.list())
    }).pipe(
      tap(res => {
        if (res.rules) this.cache.set('rules', res.rules);
        if (res.users) this.cache.set('users', res.users);
        if (res.roles) this.cache.set('roles', res.roles);
        if (res.reports) this.cache.set('reports', res.reports);
      }),
      map(() => void 0)
    );
  }

  // Carga solo datos críticos para el dashboard (rápido) - DEPRECATED
  private syncCritical(): Observable<void> {
    return forkJoin({
      dashboard: this.safe(this.dashboard.get()),
      alerts: this.safe(this.alerts.list({ page: 1 }))
    }).pipe(
      tap(res => {
        if (res.dashboard) this.cache.set('dashboard', res.dashboard);
        if (res.alerts) this.cache.set('alerts_default', res.alerts);
      }),
      map(() => void 0)
    );
  }

  // Carga datos secundarios en background - DEPRECATED
  private syncSecondary(): Observable<void> {
    return forkJoin({
      logs: this.safe(this.logs.list({ page: 1 })),
      reports: this.safe(this.reports.list()),
      rules: this.safe(this.rules.list()),
      users: this.safe(this.users.list()),
      roles: this.safe(this.users.roles())
    }).pipe(
      tap(res => {
        if (res.logs) this.cache.set('logs_default', res.logs);
        if (res.reports) this.cache.set('reports', res.reports);
        if (res.rules) this.cache.set('rules', res.rules);
        if (res.users) this.cache.set('users', res.users);
        if (res.roles) this.cache.set('roles', res.roles);
      }),
      map(() => void 0)
    );
  }

  private syncAll(): Observable<void> {
    return forkJoin({
      dashboard: this.safe(this.dashboard.get()),
      alerts:    this.safe(this.alerts.list({ page: 1 })),
      logs:      this.safe(this.logs.list({ page: 1 })),
      reports:   this.safe(this.reports.list()),
      rules:     this.safe(this.rules.list()),
      users:     this.safe(this.users.list()),
      roles:     this.safe(this.users.roles()),
    }).pipe(
      tap(res => {
        if (res.dashboard) this.cache.set('dashboard', res.dashboard);
        if (res.alerts)    this.cache.set('alerts_default', res.alerts);
        if (res.logs)      this.cache.set('logs_default', res.logs);
        if (res.reports)   this.cache.set('reports', res.reports);
        if (res.rules)     this.cache.set('rules', res.rules);
        if (res.users)     this.cache.set('users', res.users);
        if (res.roles)     this.cache.set('roles', res.roles);
      }),
      map(() => void 0)
    );
  }
}
