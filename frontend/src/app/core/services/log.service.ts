import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { RawLog, PaginatedResponse } from '../models';

const API = '/api';

export interface LogFilters {
  search?: string;
  source_system?: string;
  source_ip?: string;
  event_type?: string;
  from?: string;
  to?: string;
  page?: number;
}

@Injectable({ providedIn: 'root' })
export class LogService {
  private http = inject(HttpClient);

  list(filters: LogFilters = {}) {
    let params = new HttpParams();
    Object.entries(filters).forEach(([k, v]) => { if (v) params = params.set(k, String(v)); });
    return this.http.get<PaginatedResponse<RawLog>>(`${API}/raw-logs`, { params });
  }

  get(id: number) {
    return this.http.get<RawLog>(`${API}/raw-logs/${id}`);
  }
}
