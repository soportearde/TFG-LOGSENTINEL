import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { ConnectedSystem } from '../models';

const API = '/api';

@Injectable({ providedIn: 'root' })
export class SystemService {
  private http = inject(HttpClient);

  list() {
    return this.http.get<ConnectedSystem[]>(`${API}/connected-systems`);
  }

  get(id: number) {
    return this.http.get<ConnectedSystem>(`${API}/connected-systems/${id}`);
  }

  create(data: Partial<ConnectedSystem>) {
    return this.http.post<ConnectedSystem>(`${API}/connected-systems`, data);
  }

  update(id: number, data: Partial<ConnectedSystem>) {
    return this.http.put<ConnectedSystem>(`${API}/connected-systems/${id}`, data);
  }

  delete(id: number) {
    return this.http.delete(`${API}/connected-systems/${id}`);
  }

  /**
   * Obtiene el comando de instalación para copiar y pegar en el servidor.
   */
  getInstallCommand(id: number) {
    return this.http.get<{
      system_name: string;
      api_key: string;
      install_command: string;
    }>(`${API}/connected-systems/${id}/install-command`);
  }

  /**
   * Descarga el plugin de WordPress con la API key inyectada.
   */
  downloadPlugin(id: number) {
    return this.http.get(`${API}/connected-systems/${id}/download-plugin`, {
      responseType: 'blob',
      observe: 'response',
    });
  }

  /**
   * Regenera la API key de un sistema (por si se compromete).
   */
  regenerateKey(id: number) {
    return this.http.post<ConnectedSystem>(
      `${API}/connected-systems/${id}/regenerate-key`, {}
    );
  }
}
