/**
 * Multi-Tenant API Security Ingestion & Dashboard Data Types
 */

export interface RegisteredApp {
  id: string;
  name: string;
  environment: 'dev' | 'prod';
  key_prefix: string; // e.g. "sk_live_9a4b...3f12"
  key_hash: string;   // SHA-256 hash of the full secret key (never stored in plain text)
  status: 'active' | 'disabled';
  created_at: string;
  last_seen_at: string | null;
  total_requests: number;
  key_history: KeyRotation[];
}

export interface KeyRotation {
  old_key_prefix: string | null;
  new_key_prefix: string;
  rotated_at: string;
}

export interface IngestEvent {
  timestamp?: string | number;
  method: string;
  path: string;
  status: number;
  response_time_ms: number;
  request_size?: number;
  response_size?: number;
  client_ip?: string;
  user_agent?: string;
  user_id?: string;
  login_result?: 'ok' | 'fail' | 'none';
}

export type LabelSource = 'rule' | 'human';
export type FeatureWindowSize = '1m' | '5m' | '1h';

export interface TrafficRecord {
  request_id: string;
  app_id?: string;
  app_name?: string;
  environment?: 'dev' | 'prod';
  timestamp: string; // ISO 8601 string
  client_ip: string;
  method: string;
  path: string;
  normalized_path: string;
  query_param_names: string[];
  status_code: number;
  response_time_ms: number;
  request_size: number;
  response_size: number;
  user_agent: string;
  user_id_hash?: string;
  login_result: 'ok' | 'fail' | 'none';
  threat_rule?: string; // e.g. "normal" or human-readable rule name
  threat_rule_id?: string; // rule ID (e.g. "RULE-06-SQL-INJECTION") if a rule fired
  label?: string; // "normal" or ML label (e.g. "sqli_suspected", "brute_force")
  label_source?: LabelSource; // "rule" | "human"
  is_synthetic?: boolean;
}

export interface FeatureRow {
  feature_id: string;
  timestamp: string; // ISO 8601 window end timestamp
  app_id: string;
  app_name: string;
  client_ip: string; // raw IP or salted HMAC hash if HASH_IPS=true
  window_size: FeatureWindowSize;
  request_count: number;
  error_rate_4xx: number;
  error_rate_5xx: number;
  unique_endpoints: number;
  unique_user_ids: number;
  failed_logins: number;
  avg_gap_between_requests_ms: number;
  avg_response_time_ms: number;
  avg_request_size: number;
  max_request_size: number;
  post_ratio: number;
  night_time_ratio: number;
  unique_user_agents: number;
  label: string;
  label_source: LabelSource;
}

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ThreatStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive';

export interface ThreatRule {
  id: string;
  name: string;
  severity: ThreatSeverity;
  window_seconds: number;
  threshold: number;
  enabled: boolean;
  owasp_tag: string;
  description: string;
}

export interface ThreatRecord {
  id: string;
  app_id: string;
  app_name: string;
  rule_id: string;
  rule_name: string;
  severity: ThreatSeverity;
  client_ip: string;
  hashed_user_id?: string;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  status: ThreatStatus;
  evidence: string;
  owasp_tag: string;
  milestone_100_alerted?: boolean;
}

export interface PlatformSettings {
  mode: 'shadow' | 'alert_only';
  notify_on_high_critical: boolean;
  description?: string;
  alert_webhook_url?: string;
  alert_min_severity?: ThreatSeverity; // default 'high'
  alert_dedup_minutes?: number; // default 30
  raw_traffic_retention_days?: number; // default 30
  feature_retention_days?: number; // default 90
}

export interface AlertHistoryEntry {
  id: string;
  timestamp: string;
  threat_id: string;
  app_id: string;
  app_name: string;
  rule_id: string;
  rule_name: string;
  severity: ThreatSeverity;
  client_ip: string;
  trigger_reason: 'new_threat' | 'milestone_100_hits' | 'test_alert';
  status: 'sent' | 'failed';
  attempts: number;
  error?: string;
}

export interface TelemetryStats {
  total_records: number;
  in_memory_records: number;
  avg_response_time_ms: number;
  min_response_time_ms: number;
  max_response_time_ms: number;
  login_counts: {
    ok: number;
    fail: number;
    none: number;
  };
  status_counts: {
    '2xx': number;
    '3xx': number;
    '4xx': number;
    '5xx': number;
  };
  methods_breakdown: Record<string, number>;
  top_paths: { path: string; count: number }[];
  started_at: string;
}

export interface MinuteMetric {
  time: string; // "HH:MM"
  timestamp: number;
  requests: number;
  errors: number;
}

export interface EndpointMetric {
  endpoint: string;
  count: number;
  percentage: number;
}

export interface ClientIpMetric {
  ip: string;
  count: number;
  percentage: number;
}

export interface SlowestEndpointMetric {
  endpoint: string;
  avg_response_time_ms: number;
  count: number;
}

export interface DashboardStats {
  total_requests: number;
  error_rate: number; // percentage (e.g. 15.4)
  failed_logins: number;
  avg_response_time_ms: number;
  status_code_breakdown: {
    '2xx': number;
    '3xx': number;
    '4xx': number;
    '5xx': number;
  };
  requests_per_minute: MinuteMetric[];
  top_endpoints: EndpointMetric[];
  top_client_ips: ClientIpMetric[];
  slowest_endpoints: SlowestEndpointMetric[];
  generated_at: string;
  selected_app_id: string | null;
  open_threats_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}
