import { Component, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { ReportService } from '../../core/services/report.service';
import { AuthService } from '../../core/services/auth.service';
import { CacheService } from '../../core/services/cache.service';
import { Report } from '../../core/models';

@Component({
  selector: 'app-reports',
  imports: [FormsModule, DatePipe],
  templateUrl: './reports.html',
  styleUrl: './reports.scss'
})
export class ReportsPage implements OnInit {
  private svc   = inject(ReportService);
  private auth  = inject(AuthService);
  private cache = inject(CacheService);

  ngOnInit() {
    // Cargar datos solo si no existen en caché
    if (!this.reports()) {
      this.loading.set(true);
      this.svc.list().subscribe({
        next: (data) => {
          this.cache.set('reports', data);
          this.loading.set(false);
        },
        error: () => {
          this.error.set('Error al cargar informes.');
          this.loading.set(false);
        }
      });
    }
  }

  reports       = this.cache.signal<Report[]>('reports');
  loading       = signal(false);
  saving        = signal(false);
  error         = signal('');
  showModal     = signal(false);
  deleteConfirm = signal<number | null>(null);

  form = { title: '', filters: { status: '', severity: '', from: '', to: '' } };
  apiBase = '/api';

  openModal() {
    this.form = { title: '', filters: { status: '', severity: '', from: '', to: '' } };
    this.showModal.set(true);
  }
  closeModal() { this.showModal.set(false); }

  generate() {
    if (!this.form.title) return;
    this.saving.set(true);
    const filters: Record<string, string> = {};
    Object.entries(this.form.filters).forEach(([k, v]) => { if (v) filters[k] = v; });

    this.svc.create({ title: this.form.title, filters }).subscribe({
      next: () => {
        this.svc.list().subscribe(r => this.cache.set('reports', r));
        this.closeModal();
        this.saving.set(false);
      },
      error: () => { this.saving.set(false); this.error.set('Error al generar el informe.'); }
    });
  }

  download(report: Report) {
    const token = localStorage.getItem('ls_token');
    fetch(`${this.apiBase}/reports/${report.id}/download`, {
      headers: { Authorization: `Bearer ${token}` }
    }).then(r => r.blob()).then(blob => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${report.title}.csv`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  confirmDelete(id: number) { this.deleteConfirm.set(id); }
  cancelDelete()             { this.deleteConfirm.set(null); }

  doDelete() {
    const id = this.deleteConfirm();
    if (!id) return;
    this.svc.delete(id).subscribe({
      next: () => {
        this.svc.list().subscribe(r => this.cache.set('reports', r));
        this.deleteConfirm.set(null);
      },
      error: () => { this.error.set('Error al eliminar el informe.'); this.deleteConfirm.set(null); }
    });
  }

  isAdmin() { return this.auth.isAdmin(); }

  toEntries(obj: Record<string, string> | undefined): [string, string][] {
    if (!obj) return [];
    return Object.entries(obj).filter(([, v]) => !!v);
  }
}
