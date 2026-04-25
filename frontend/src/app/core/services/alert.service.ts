import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Alert, PaginatedResponse } from '../models';

const API = '/api';

export interface AlertFilters {
  search?: string;
  status?: string;
  severity?: string;
  source_system?: string;
  from?: string;
  to?: string;
  page?: number;
}

@Injectable({ providedIn: 'root' })
export class AlertService {
  private http = inject(HttpClient);

  list(filters: AlertFilters = {}) {
    let params = new HttpParams();
    Object.entries(filters).forEach(([k, v]) => { if (v) params = params.set(k, String(v)); });
    return this.http.get<PaginatedResponse<Alert>>(`${API}/alerts`, { params });
  }

  get(id: number) {
    return this.http.get<Alert>(`${API}/alerts/${id}`);
  }

  updateStatus(id: number, status: string) {
    return this.http.patch<Alert>(`${API}/alerts/${id}/status`, { status });
  }

  delete(id: number) {
    return this.http.delete<{ message: string }>(`${API}/alerts/${id}`);
  }
}
