import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Report } from '../models';

const API = '/api';

@Injectable({ providedIn: 'root' })
export class ReportService {
  private http = inject(HttpClient);

  list() {
    return this.http.get<Report[]>(`${API}/reports`);
  }

  create(data: { title: string; filters?: Record<string, string> }) {
    return this.http.post<Report>(`${API}/reports`, data);
  }

  delete(id: number) {
    return this.http.delete(`${API}/reports/${id}`);
  }

  downloadUrl(id: number): string {
    return `${API}/reports/${id}/download`;
  }
}
