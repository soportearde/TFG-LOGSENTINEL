import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { CorrelationRule } from '../models';

const API = '/api';

@Injectable({ providedIn: 'root' })
export class RuleService {
  private http = inject(HttpClient);

  list() {
    return this.http.get<CorrelationRule[]>(`${API}/correlation-rules`);
  }

  get(id: number) {
    return this.http.get<CorrelationRule>(`${API}/correlation-rules/${id}`);
  }

  create(data: Partial<CorrelationRule>) {
    return this.http.post<CorrelationRule>(`${API}/correlation-rules`, data);
  }

  update(id: number, data: Partial<CorrelationRule>) {
    return this.http.put<CorrelationRule>(`${API}/correlation-rules/${id}`, data);
  }

  delete(id: number) {
    return this.http.delete(`${API}/correlation-rules/${id}`);
  }

  getCode(id: number) {
    return this.http.get<{ code: string | null }>(`${API}/correlation-rules/${id}/code`);
  }
}
