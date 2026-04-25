import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { tap, switchMap } from 'rxjs/operators';
import { AuthService } from '../../core/services/auth.service';
import { BackgroundSyncService } from '../../core/services/background-sync.service';

@Component({
  selector: 'app-login',
  imports: [FormsModule, RouterLink],
  templateUrl: './login.html',
  styleUrl: './login.scss'
})
export class LoginPage {
  private auth   = inject(AuthService);
  private router = inject(Router);
  private bgSync = inject(BackgroundSyncService);

  email    = '';
  password = '';
  phase    = signal<'idle' | 'login' | 'dashboard' | 'alerts' | 'complete'>('idle');
  error    = signal('');

  get loading() { return this.phase() !== 'idle'; }

  submit() {
    if (!this.email || !this.password) {
      this.error.set('Por favor completa todos los campos.');
      return;
    }
    this.phase.set('login');
    this.error.set('');

    this.auth.login(this.email, this.password).pipe(
      tap(() => this.phase.set('dashboard')),
      switchMap(() => this.bgSync.start())
    ).subscribe({
      next: () => {
        // Redirección inmediata después del dashboard
        this.phase.set('complete');
        setTimeout(() => this.router.navigate(['/app/dashboard']), 50);
      },
      error: (err) => {
        this.phase.set('idle');
        this.error.set(
          err?.error?.message ?? err?.error?.errors?.email?.[0] ?? 'Credenciales incorrectas.'
        );
      }
    });
  }
}
