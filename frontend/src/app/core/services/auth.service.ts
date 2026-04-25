import { Injectable, signal, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { tap } from 'rxjs/operators';
import { AuthResponse, User } from '../models';
import { BackgroundSyncService } from './background-sync.service';

const API = '/api';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http   = inject(HttpClient);
  private router = inject(Router);
  private bgSync = inject(BackgroundSyncService);

  currentUser = signal<{ id: number; name: string; email: string; role: string } | null>(
    this.loadUser()
  );

  private loadUser() {
    try {
      const u = localStorage.getItem('ls_user');
      return u ? JSON.parse(u) : null;
    } catch { return null; }
  }

  login(email: string, password: string) {
    return this.http.post<AuthResponse>(`${API}/login`, { email, password }).pipe(
      tap(res => {
        localStorage.setItem('ls_token', res.token);
        localStorage.setItem('ls_user', JSON.stringify(res.user));
        this.currentUser.set(res.user);
      })
    );
  }

  logout() {
    this.http.post(`${API}/logout`, {}).subscribe({
      complete: () => this.clearSession(),
      error:    () => this.clearSession()
    });
  }

  private clearSession() {
    this.bgSync.stop();
    localStorage.removeItem('ls_token');
    localStorage.removeItem('ls_user');
    this.currentUser.set(null);
    this.router.navigate(['/login']);
  }

  getToken(): string | null {
    return localStorage.getItem('ls_token');
  }

  isLoggedIn(): boolean {
    return !!this.getToken();
  }

  get role(): string {
    return this.currentUser()?.role ?? '';
  }

  isAdmin(): boolean   { return this.role === 'admin'; }
  isAnalyst(): boolean { return this.role === 'analyst' || this.role === 'admin'; }
}
