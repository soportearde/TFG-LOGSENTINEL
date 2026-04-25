export interface Role {
  id: number;
  name: 'admin' | 'analyst' | 'user';
}

export interface User {
  id: number;
  name: string;
  email: string;
  role?: Role;
  role_id?: number;
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface AuthResponse {
  token: string;
  user: { id: number; name: string; email: string; role: string };
}

export interface SeverityLevel {
  id: number;
  name: 'critical' | 'high' | 'medium' | 'low';
  level: number;
}

export interface CorrelationRule {
  id: number;
  rule_name: string;
  description?: string;
  severity_id: number;
  severity?: SeverityLevel;
  enabled: boolean;
  conditions?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

export interface Alert {
  id: number;
  rule_id: number;
  rule?: CorrelationRule;
  severity_id: number;
  severity?: SeverityLevel;
  source_ip?: string;
  username?: string;
  source_system?: string;
  title: string;
  message?: string;
  metadata?: Record<string, unknown>;
  event_timestamp: string;
  status: 'open' | 'in_progress' | 'resolved' | 'dismissed';
  created_at?: string;
}

export interface RawLog {
  id: number;
  source_system: string;
  source_ip: string;
  username: string;
  event_type: string;
  raw_data?: Record<string, unknown>;
  created_at: string;
}

export interface Report {
  id: number;
  user_id: number;
  user?: User;
  title: string;
  filters?: {
    status?: string;
    severity?: string;
    from?: string;
    to?: string;
  };
  file_path?: string;
  created_at?: string;
  updated_at?: string;
}

export interface DashboardData {
  alerts_total: number;
  alerts_open: number;
  alerts_by_level: Record<string, number>;
  recent_alerts: Alert[];
  raw_logs_today?: number;
  total_users?: number;
  active_rules?: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  current_page: number;
  last_page: number;
  per_page: number;
  total: number;
}
export interface ConnectedSystem {
  id: number;
  system_name: string;
  system_type: string;
  api_key: string;
  description?: string;
  ip_address?: string;
  status: 'pending' | 'active' | 'inactive';
  last_seen?: string;
  created_at?: string;
  updated_at?: string;
}
