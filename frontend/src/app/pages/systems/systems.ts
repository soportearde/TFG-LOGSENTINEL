import { Component, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { SystemService } from '../../core/services/system.service';
import { CacheService } from '../../core/services/cache.service';
import { ConnectedSystem } from '../../core/models';


type ModalMode = 'create' | 'edit' | 'install';

@Component({
  selector: 'app-systems',
  imports: [FormsModule, DatePipe],
  templateUrl: './systems.html',
  styleUrl: './systems.scss'
})
export class SystemsPage implements OnInit {
  private svc   = inject(SystemService);
  private cache = inject(CacheService);

  systems       = this.cache.signal<ConnectedSystem[]>('systems');
  loading       = signal(false);
  saving        = signal(false);
  error         = signal('');
  deleteConfirm = signal<number | null>(null);
  modalMode     = signal<ModalMode | null>(null);
  form: Partial<ConnectedSystem> = {};

  // Para el modal de comando de instalación
  installCommand = signal('');
  installLoading = signal(false);
  copySuccess    = signal(false);

  ngOnInit() {
    this.loading.set(true);
    this.svc.list().subscribe({
      next: (data) => {
        this.cache.set('systems', data);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('Error al cargar sistemas.');
        this.loading.set(false);
      }
    });
  }

  // Tipos de sistema disponibles
  systemTypes = [
    { value: 'ubuntu',    label: 'Ubuntu Server' },
    { value: 'debian',    label: 'Debian Server' },
    { value: 'centos',    label: 'CentOS / RHEL' },
    { value: 'wordpress', label: 'WordPress' },
    { value: 'windows',   label: 'Windows Server' },
    { value: 'other',     label: 'Otro' },
  ];

  // ── Modales ──────────────────────────────────────────────

  openCreate() {
    this.form = { system_type: 'ubuntu' };
    this.modalMode.set('create');
  }

  openEdit(system: ConnectedSystem) {
    this.form = { ...system };
    this.modalMode.set('edit');
  }

  closeModal() {
    this.modalMode.set(null);
    this.form = {};
    this.installCommand.set('');
    this.copySuccess.set(false);
  }

  // ── CRUD ─────────────────────────────────────────────────

  save() {
    this.saving.set(true);
    const obs = this.modalMode() === 'create'
      ? this.svc.create(this.form)
      : this.svc.update(this.form.id!, this.form);

    obs.subscribe({
      next: (saved) => {
        this.svc.list().subscribe(s => this.cache.set('systems', s));
        this.saving.set(false);

        // Si acabamos de crear, mostramos directamente el comando de instalación
        if (this.modalMode() === 'create') {
          this.showInstallCommand(saved);
        } else {
          this.closeModal();
        }
      },
      error: () => {
        this.saving.set(false);
        this.error.set('Error al guardar el sistema.');
      }
    });
  }

  confirmDelete(id: number) { this.deleteConfirm.set(id); }
  cancelDelete()             { this.deleteConfirm.set(null); }

  doDelete() {
    const id = this.deleteConfirm();
    if (!id) return;
    this.svc.delete(id).subscribe({
      next: () => {
        this.svc.list().subscribe(s => this.cache.set('systems', s));
        this.deleteConfirm.set(null);
      },
      error: () => {
        this.error.set('Error al eliminar el sistema.');
        this.deleteConfirm.set(null);
      }
    });
  }

  // ── Comando de instalación ───────────────────────────────

  showInstallCommand(system: ConnectedSystem) {
    this.installLoading.set(true);
    this.modalMode.set('install');
    this.form = system;

    this.svc.getInstallCommand(system.id).subscribe({
      next: (res) => {
        this.installCommand.set(res.install_command);
        this.installLoading.set(false);
      },
      error: () => {
        this.error.set('Error al generar el comando.');
        this.installLoading.set(false);
      }
    });
  }

  copyCommand() {
    navigator.clipboard.writeText(this.installCommand()).then(() => {
      this.copySuccess.set(true);
      setTimeout(() => this.copySuccess.set(false), 2000);
    });
  }

  downloadPlugin() {
    const id = this.form.id;
    if (!id) return;
    this.svc.downloadPlugin(id).subscribe({
      next: (res) => {
        const blob = res.body!;
        const cd = res.headers.get('Content-Disposition') ?? '';
        const match = cd.match(/filename="?([^"]+)"?/);
        const filename = match ? match[1] : 'logsentinel-wp.php';
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
      },
      error: () => this.error.set('Error al descargar el plugin.')
    });
  }

  regenerateKey(system: ConnectedSystem) {
    this.svc.regenerateKey(system.id).subscribe({
      next: () => {
        this.svc.list().subscribe(s => this.cache.set('systems', s));
        // Si estamos en el modal de instalación, recargamos el comando
        if (this.modalMode() === 'install') {
          this.showInstallCommand({ ...system });
        }
      },
      error: () => this.error.set('Error al regenerar la API key.')
    });
  }

  // ── Helpers visuales ─────────────────────────────────────

  statusClass(status: string) {
    const map: Record<string, string> = {
      active:   'badge badge-success',
      pending:  'badge badge-warning',
      inactive: 'badge badge-danger',
    };
    return map[status] ?? 'badge badge-low';
  }

  statusLabel(status: string) {
    const map: Record<string, string> = {
      active:   'Activo',
      pending:  'Pendiente',
      inactive: 'Inactivo',
    };
    return map[status] ?? status;
  }

  typeLabel(type: string) {
    return this.systemTypes.find(t => t.value === type)?.label ?? type;
  }
}
