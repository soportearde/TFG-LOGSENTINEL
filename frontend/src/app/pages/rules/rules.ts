import { Component, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { RuleService } from '../../core/services/rule.service';
import { CacheService } from '../../core/services/cache.service';
import { CorrelationRule } from '../../core/models';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

type ModalMode = 'create' | 'edit';

@Component({
  selector: 'app-rules',
  imports: [FormsModule, DatePipe],
  templateUrl: './rules.html',
  styleUrl: './rules.scss'
})
export class RulesPage implements OnInit {
  private svc   = inject(RuleService);
  private cache = inject(CacheService);

  rules         = this.cache.signal<CorrelationRule[]>('rules');
  loading       = signal(false);
  saving        = signal(false);
  error         = signal('');
  deleteConfirm = signal<number | null>(null);
  modalMode     = signal<ModalMode | null>(null);
  form: Partial<CorrelationRule> = {};

  ngOnInit() {
    // Cargar datos solo si no existen en caché
    if (!this.rules()) {
      this.loading.set(true);
      this.svc.list().pipe(
        takeUntilDestroyed()
      ).subscribe({
        next: (data) => {
          this.cache.set('rules', data);
          this.loading.set(false);
        },
        error: () => {
          this.error.set('Error al cargar reglas.');
          this.loading.set(false);
        }
      });
    }
  }

  severityOptions = [
    { id: 1, name: 'low' },
    { id: 2, name: 'medium' },
    { id: 3, name: 'high' },
    { id: 4, name: 'critical' }
  ];

  openCreate() {
    this.form = { enabled: true, severity_id: 3 };
    this.modalMode.set('create');
  }

  openEdit(rule: CorrelationRule) {
    this.form = { ...rule };
    this.modalMode.set('edit');
  }

  closeModal() { this.modalMode.set(null); this.form = {}; }

  save() {
    this.saving.set(true);
    const obs = this.modalMode() === 'create'
      ? this.svc.create(this.form)
      : this.svc.update(this.form.id!, this.form);

    obs.subscribe({
      next: () => {
        this.svc.list().subscribe(r => this.cache.set('rules', r));
        this.closeModal();
        this.saving.set(false);
      },
      error: () => { this.saving.set(false); this.error.set('Error al guardar la regla.'); }
    });
  }

  toggleEnabled(rule: CorrelationRule) {
    this.svc.update(rule.id, { enabled: !rule.enabled }).subscribe({
      next: () => this.svc.list().subscribe(r => this.cache.set('rules', r))
    });
  }

  confirmDelete(id: number) { this.deleteConfirm.set(id); }
  cancelDelete()             { this.deleteConfirm.set(null); }

  doDelete() {
    const id = this.deleteConfirm();
    if (!id) return;
    this.svc.delete(id).subscribe({
      next: () => {
        this.svc.list().subscribe(r => this.cache.set('rules', r));
        this.deleteConfirm.set(null);
      },
      error: () => { this.error.set('Error al eliminar la regla.'); this.deleteConfirm.set(null); }
    });
  }

  severityClass(name?: string) { return `badge badge-${name?.toLowerCase() ?? 'low'}`; }
  severityLabel(k?: string) {
    return { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }[k ?? ''] ?? k ?? '';
  }
  severityNameById(id: number) {
    return this.severityOptions.find(s => s.id === id)?.name ?? '';
  }
}
