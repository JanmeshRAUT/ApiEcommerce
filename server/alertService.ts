import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { config } from './config.js';
import { AlertHistoryEntry, PlatformSettings, ThreatRecord, ThreatSeverity } from './types.js';

const ALERT_HISTORY_FILE = path.resolve(process.cwd(), 'alerts_history.json');
const MAX_HISTORY_ENTRIES = 500;
const WEBHOOK_TIMEOUT_MS = 3000;
const MAX_RETRIES = 2; // 1 initial attempt + up to 2 retries = 3 total attempts

const SEVERITY_RANK: Record<ThreatSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

class AlertService {
  private history: AlertHistoryEntry[] = [];
  // Dedup tracker: `${app_id}:${client_ip}:${rule_id}` -> timestamp (ms) of last sent alert
  private lastAlertSentAt = new Map<string, number>();

  constructor() {
    this.loadHistory();
  }

  private loadHistory(): void {
    try {
      if (fs.existsSync(ALERT_HISTORY_FILE)) {
        const raw = fs.readFileSync(ALERT_HISTORY_FILE, 'utf8');
        const list = JSON.parse(raw);
        if (Array.isArray(list)) {
          this.history = list.slice(0, MAX_HISTORY_ENTRIES);
        }
      }
    } catch (err) {
      console.warn('[AlertService] Could not load alerts_history.json:', err);
    }
  }

  private saveHistory(): void {
    try {
      fs.writeFileSync(ALERT_HISTORY_FILE, JSON.stringify(this.history, null, 2), 'utf8');
    } catch (err) {
      console.error('[AlertService] Failed to save alerts_history.json:', err);
    }
  }

  /**
   * Resolve effective webhook URL (dashboard setting takes precedence over env var ALERT_WEBHOOK_URL)
   */
  public resolveWebhookUrl(settings: PlatformSettings): string {
    const fromSettings = settings.alert_webhook_url?.trim();
    if (fromSettings) return fromSettings;
    return config.alertWebhookUrl?.trim() || '';
  }

  /**
   * Check whether threat severity meets minimum threshold (default: 'high')
   */
  public meetsSeverityThreshold(
    severity: ThreatSeverity,
    minSeverity: ThreatSeverity = 'high'
  ): boolean {
    const threatRank = SEVERITY_RANK[severity] || 0;
    const minRank = SEVERITY_RANK[minSeverity] || SEVERITY_RANK.high;
    return threatRank >= minRank;
  }

  /**
   * Determine if a new threat alert should be sent (checking severity and dedup cooldown window).
   */
  public shouldAlertForNewThreat(
    threat: ThreatRecord,
    settings: PlatformSettings,
    now: number = Date.now()
  ): { shouldSend: boolean; reason?: 'below_min_severity' | 'deduplicated' } {
    const minSeverity = settings.alert_min_severity || 'high';
    if (!this.meetsSeverityThreshold(threat.severity, minSeverity)) {
      return { shouldSend: false, reason: 'below_min_severity' };
    }

    const dedupMinutes = settings.alert_dedup_minutes !== undefined ? Number(settings.alert_dedup_minutes) : 30;
    const dedupWindowMs = Math.max(0, dedupMinutes) * 60 * 1000;
    const dedupKey = `${threat.app_id}:${threat.client_ip}:${threat.rule_id}`;

    if (dedupWindowMs > 0) {
      const lastSent = this.lastAlertSentAt.get(dedupKey);
      if (lastSent !== undefined && now - lastSent < dedupWindowMs) {
        return { shouldSend: false, reason: 'deduplicated' };
      }
    }

    return { shouldSend: true };
  }

  /**
   * Record that an alert cooldown window started for attacker + rule
   */
  public markAlertDispatched(threat: ThreatRecord, now: number = Date.now()): void {
    const dedupKey = `${threat.app_id}:${threat.client_ip}:${threat.rule_id}`;
    this.lastAlertSentAt.set(dedupKey, now);
  }

  /**
   * Build safe, secret-free alert payload compatible with Slack, Discord, Telegram, or generic webhooks
   */
  public buildWebhookPayload(
    webhookUrl: string,
    threat: ThreatRecord,
    triggerReason: 'new_threat' | 'milestone_100_hits' | 'test_alert'
  ): Record<string, any> {
    const dashboardLink = `${config.appUrl}/?tab=threats&threat_id=${encodeURIComponent(threat.id)}`;
    const prefix =
      triggerReason === 'milestone_100_hits'
        ? '[100-HIT MILESTONE]'
        : triggerReason === 'test_alert'
        ? '[TEST ALERT]'
        : '[NEW THREAT]';

    const summaryText = [
      `${prefix} ${threat.severity.toUpperCase()}: ${threat.rule_name}`,
      `App: ${threat.app_name}`,
      `Client IP: ${threat.client_ip}`,
      `Hits: ${threat.hit_count}`,
      `Evidence: ${threat.evidence}`,
      `Time: ${threat.last_seen}`,
      `Dashboard: ${dashboardLink}`,
    ].join('\n');

    const lowerUrl = webhookUrl.toLowerCase();

    // Discord Webhook format
    if (lowerUrl.includes('discord.com/api/webhooks') || lowerUrl.includes('discordapp.com/api/webhooks')) {
      const color =
        threat.severity === 'critical'
          ? 0xdc2626
          : threat.severity === 'high'
          ? 0xea580c
          : threat.severity === 'medium'
          ? 0xd97706
          : 0x2563eb;

      return {
        content: `${prefix} **${threat.severity.toUpperCase()}** — ${threat.rule_name} on **${threat.app_name}**`,
        embeds: [
          {
            title: `${threat.rule_name} (${threat.rule_id})`,
            url: dashboardLink,
            color,
            fields: [
              { name: 'Application', value: threat.app_name, inline: true },
              { name: 'Severity', value: threat.severity.toUpperCase(), inline: true },
              { name: 'Client IP', value: threat.client_ip, inline: true },
              { name: 'Hit Count', value: String(threat.hit_count), inline: true },
              { name: 'Evidence', value: threat.evidence, inline: false },
              { name: 'Dashboard Link', value: dashboardLink, inline: false },
            ],
            timestamp: threat.last_seen,
          },
        ],
      };
    }

    // Slack Webhook format
    if (lowerUrl.includes('hooks.slack.com')) {
      return {
        text: summaryText,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `${prefix} ${threat.severity.toUpperCase()}: ${threat.rule_name}`,
            },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*App:*\n${threat.app_name}` },
              { type: 'mrkdwn', text: `*Severity:*\n${threat.severity.toUpperCase()}` },
              { type: 'mrkdwn', text: `*Client IP:*\n\`${threat.client_ip}\`` },
              { type: 'mrkdwn', text: `*Hits:*\n${threat.hit_count}` },
            ],
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Evidence:* ${threat.evidence}\n*Time:* ${threat.last_seen}\n<${dashboardLink}|Inspect Threat on Dashboard>`,
            },
          },
        ],
      };
    }

    // Telegram Bot API format
    if (lowerUrl.includes('api.telegram.org')) {
      return {
        text: summaryText,
        disable_web_page_preview: true,
      };
    }

    // Generic webhook (includes text, content, and structured fields)
    return {
      text: summaryText,
      content: summaryText,
      trigger_reason: triggerReason,
      threat_id: threat.id,
      app_name: threat.app_name,
      rule_id: threat.rule_id,
      rule_name: threat.rule_name,
      severity: threat.severity,
      client_ip: threat.client_ip,
      hit_count: threat.hit_count,
      evidence: threat.evidence,
      time: threat.last_seen,
      dashboard_link: dashboardLink,
    };
  }

  /**
   * Non-blocking background dispatch for new threat or 100-hit milestone
   */
  public notifyThreatInBackground(
    threat: ThreatRecord,
    settings: PlatformSettings,
    triggerReason: 'new_threat' | 'milestone_100_hits'
  ): boolean {
    const webhookUrl = this.resolveWebhookUrl(settings);

    if (triggerReason === 'new_threat') {
      const check = this.shouldAlertForNewThreat(threat, settings);
      if (!check.shouldSend) {
        return false;
      }
      this.markAlertDispatched(threat);
    } else if (triggerReason === 'milestone_100_hits') {
      const minSeverity = settings.alert_min_severity || 'high';
      if (!this.meetsSeverityThreshold(threat.severity, minSeverity)) {
        return false;
      }
    }

    if (!webhookUrl) {
      // No webhook URL configured; dedup state updated, nothing to HTTP-post
      return false;
    }

    // Snapshot threat at trigger time so concurrent batch hits do not mutate hit_count (e.g. 1 vs 100)
    const threatSnapshot: ThreatRecord = { ...threat };

    // Dispatch asynchronously so ingest & detection never block
    setImmediate(() => {
      this.deliverWebhookWithRetry(webhookUrl, threatSnapshot, triggerReason).catch(() => {
        // Silently ignore unexpected background delivery errors
      });
    });

    return true;
  }

  /**
   * Send test alert synchronously (awaitable so Settings UI gets immediate sent/failed feedback)
   */
  public async sendTestAlert(
    settings: PlatformSettings,
    overrideWebhookUrl?: string
  ): Promise<AlertHistoryEntry> {
    const webhookUrl = overrideWebhookUrl?.trim() || this.resolveWebhookUrl(settings);
    const nowIso = new Date().toISOString();

    const sampleThreat: ThreatRecord = {
      id: `thr_test_${Date.now()}`,
      app_id: 'app_fakeshop_demo',
      app_name: 'Gatekeeper Security Platform',
      rule_id: 'TEST-ALERT',
      rule_name: 'Manual Webhook Test Alert',
      severity: settings.alert_min_severity || 'high',
      client_ip: '203.0.113.10',
      first_seen: nowIso,
      last_seen: nowIso,
      hit_count: 1,
      status: 'open',
      evidence: 'Test alert triggered from Platform Settings (safe synthetic payload)',
      owasp_tag: 'API-TEST',
    };

    if (!webhookUrl) {
      const entry: AlertHistoryEntry = {
        id: `alt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
        timestamp: nowIso,
        threat_id: sampleThreat.id,
        app_id: sampleThreat.app_id,
        app_name: sampleThreat.app_name,
        rule_id: sampleThreat.rule_id,
        rule_name: sampleThreat.rule_name,
        severity: sampleThreat.severity,
        client_ip: sampleThreat.client_ip,
        trigger_reason: 'test_alert',
        status: 'failed',
        attempts: 0,
        error: 'No Webhook URL configured',
      };
      this.recordHistoryEntry(entry);
      return entry;
    }

    return this.deliverWebhookWithRetry(webhookUrl, sampleThreat, 'test_alert');
  }

  /**
   * Deliver webhook with 3 second timeout per attempt and up to 2 retries (3 attempts max)
   */
  public async deliverWebhookWithRetry(
    webhookUrl: string,
    threat: ThreatRecord,
    triggerReason: 'new_threat' | 'milestone_100_hits' | 'test_alert',
    options?: { timeoutMs?: number; maxRetries?: number; retryDelayMs?: number }
  ): Promise<AlertHistoryEntry> {
    const timeoutMs = options?.timeoutMs ?? WEBHOOK_TIMEOUT_MS;
    const maxRetries = options?.maxRetries ?? MAX_RETRIES;
    const retryDelayMs = options?.retryDelayMs ?? 300;
    const payload = this.buildWebhookPayload(webhookUrl, threat, triggerReason);

    let attempts = 0;
    let lastError = 'Unknown error';
    let sent = false;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      attempts = attempt + 1;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetch(webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Gatekeeper-Security-Alert/1.0',
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        clearTimeout(timer);

        if (response.ok) {
          sent = true;
          break;
        } else {
          lastError = `HTTP ${response.status}`;
        }
      } catch (err: any) {
        clearTimeout(timer);
        if (err?.name === 'AbortError') {
          lastError = `Timeout (${timeoutMs}ms)`;
        } else {
          lastError = err?.message ? String(err.message).slice(0, 80) : 'Network error';
        }
      }

      if (attempt < maxRetries && retryDelayMs > 0) {
        await new Promise((r) => setTimeout(r, retryDelayMs));
      }
    }

    const entry: AlertHistoryEntry = {
      id: `alt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date().toISOString(),
      threat_id: threat.id,
      app_id: threat.app_id,
      app_name: threat.app_name,
      rule_id: threat.rule_id,
      rule_name: threat.rule_name,
      severity: threat.severity,
      client_ip: threat.client_ip,
      trigger_reason: triggerReason,
      status: sent ? 'sent' : 'failed',
      attempts,
      error: sent ? undefined : lastError,
    };

    this.recordHistoryEntry(entry);
    return entry;
  }

  private recordHistoryEntry(entry: AlertHistoryEntry): void {
    this.history.unshift(entry);
    if (this.history.length > MAX_HISTORY_ENTRIES) {
      this.history = this.history.slice(0, MAX_HISTORY_ENTRIES);
    }
    this.saveHistory();
  }

  public getAlertHistory(limit: number = 100): AlertHistoryEntry[] {
    return this.history.slice(0, limit);
  }

  public clearStateForTesting(): void {
    this.history = [];
    this.lastAlertSentAt.clear();
    this.saveHistory();
  }
}

export const alertService = new AlertService();
