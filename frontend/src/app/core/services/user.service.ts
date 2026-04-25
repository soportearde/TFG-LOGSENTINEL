import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { User, Role } from '../models';

const API = '/api';

@Injectable({ providedIn: 'root' })
export class UserService {
  private http = inject(HttpClient);

  list() {
    return this.http.get<User[]>(`${API}/users`);
  }

  get(id: number) {
    return this.http.get<User>(`${API}/users/${id}`);
  }

  create(data: { name: string; email: string; password: string; role_id: number }) {
    return this.http.post<User>(`${API}/users`, data);
  }

  update(id: number, data: Partial<{ name: string; email: string; password: string; role_id: number }>) {
    return this.http.put<User>(`${API}/users/${id}`, data);
  }

  toggleActive(id: number) {
    return this.http.patch<User>(`${API}/users/${id}/toggle-active`, {});
  }

  delete(id: number) {
    return this.http.delete(`${API}/users/${id}`);
  }

  roles() {
    return this.http.get<Role[]>('/api/roles');
  }
}
