export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';

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
  milestone_100_alerted?: boolean;
}

export type LabelSource = 'rule' | 'human';
export type FeatureWindowSize = '1m' | '5m' | '1h';

export interface FeatureRow {
  feature_id: string;
  timestamp: string;
  app_id: string;
  app_name: string;
  client_ip: string;
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

export interface PlatformSettings {
  mode: 'shadow' | 'alert_only';
  notify_on_high_critical: boolean;
  alert_webhook_url?: string;
  alert_min_severity?: ThreatSeverity;
  alert_dedup_minutes?: number;
  raw_traffic_retention_days?: number;
  feature_retention_days?: number;
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

export interface OpenThreatsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}
