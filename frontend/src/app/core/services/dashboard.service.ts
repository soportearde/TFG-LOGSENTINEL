import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DashboardData } from '../models';

const API = '/api';

@Injectable({ providedIn: 'root' })
export class DashboardService {
  private http = inject(HttpClient);

  get() {
    return this.http.get<DashboardData>(`${API}/dashboard`);
  }
}
