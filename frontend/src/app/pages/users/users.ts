import { Component, inject, signal, computed, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { UserService } from '../../core/services/user.service';
import { AuthService } from '../../core/services/auth.service';
import { CacheService } from '../../core/services/cache.service';
import { User, Role } from '../../core/models';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

type ModalMode = 'create' | 'edit';

@Component({
  selector: 'app-users',
  imports: [FormsModule],
  templateUrl: './users.html',
  styleUrl: './users.scss'
})
export class UsersPage implements OnInit {
  private svc   = inject(UserService);
  private auth  = inject(AuthService);
  private cache = inject(CacheService);

  users         = this.cache.signal<User[]>('users');
  roles         = this.cache.signal<Role[]>('roles');
  loading       = signal(false);
  saving        = signal(false);
  error         = signal('');
  deleteConfirm        = signal<number | null>(null);
  modalMode            = signal<ModalMode | null>(null);
  editingProtected     = signal(false);

  private readonly PROTECTED_EMAIL = 'admin@logsentinel.com';

  form: { name: string; email: string; password: string; role_id: number } =
    { name: '', email: '', password: '', role_id: 2 };

  ngOnInit() {
    // Cargar datos solo si no existen en caché
    if (!this.users()) {
      this.loading.set(true);
      this.svc.list().pipe(
        takeUntilDestroyed()
      ).subscribe({
        next: (data) => {
          this.cache.set('users', data);
          this.loading.set(false);
        },
        error: () => {
          this.error.set('Error al cargar usuarios.');
          this.loading.set(false);
        }
      });
    }
    
    if (!this.roles()) {
      this.svc.roles().pipe(
        takeUntilDestroyed()
      ).subscribe({
        next: (data) => {
          this.cache.set('roles', data);
        }
      });
    }
  }

  currentUserId = this.auth.currentUser()?.id;

  openCreate() {
    this.form = { name: '', email: '', password: '', role_id: 2 };
    this.modalMode.set('create');
  }

  openEdit(user: User) {
    this.form = { name: user.name, email: user.email, password: '', role_id: user.role_id ?? user.role?.id ?? 2 };
    (this.form as any)._id = user.id;
    this.editingProtected.set(user.email === this.PROTECTED_EMAIL);
    this.modalMode.set('edit');
  }

  closeModal() { this.modalMode.set(null); }

  save() {
    this.saving.set(true);
    const id = (this.form as any)._id;

    if (this.modalMode() === 'create') {
      this.svc.create(this.form).subscribe({
        next: () => {
          this.svc.list().subscribe(u => this.cache.set('users', u));
          this.closeModal();
          this.saving.set(false);
        },
        error: () => { this.saving.set(false); this.error.set('Error al crear el usuario.'); }
      });
    } else {
      const payload: any = { name: this.form.name, email: this.form.email };
      if (!this.editingProtected()) payload.role_id = this.form.role_id;
      if (this.form.password) payload.password = this.form.password;
      this.svc.update(id, payload).subscribe({
        next: () => {
          this.svc.list().subscribe(u => this.cache.set('users', u));
          this.closeModal();
          this.saving.set(false);
        },
        error: () => { this.saving.set(false); this.error.set('Error al actualizar el usuario.'); }
      });
    }
  }

  toggleActive(user: User) {
    if (this.isSelf(user.id)) return;
    this.svc.toggleActive(user.id).subscribe({
      next: (updated) => {
        const list = this.users();
        if (list) {
          this.cache.set('users', list.map(u => u.id === updated.id ? updated : u));
        }
      },
      error: () => this.error.set('Error al cambiar el estado del usuario.')
    });
  }

  confirmDelete(id: number) { this.deleteConfirm.set(id); }
  cancelDelete()             { this.deleteConfirm.set(null); }

  doDelete() {
    const id = this.deleteConfirm();
    if (!id) return;
    this.svc.delete(id).subscribe({
      next: () => {
        this.svc.list().subscribe(u => this.cache.set('users', u));
        this.deleteConfirm.set(null);
      },
      error: () => { this.error.set('Error al eliminar el usuario.'); this.deleteConfirm.set(null); }
    });
  }

  roleClass(name?: string) { return `badge badge-${name ?? 'user'}`; }
  roleLabel(name?: string) {
    return { admin: 'Administrador', analyst: 'Analista', user: 'Usuario' }[name ?? ''] ?? name ?? '';
  }

  isSelf(id: number)             { return id === this.currentUserId; }
  isProtectedAdmin(user: User)   { return user.email === this.PROTECTED_EMAIL; }
}
