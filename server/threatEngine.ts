import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ThreatRule, ThreatRecord, ThreatSeverity, ThreatStatus, PlatformSettings } from './types.js';
import { alertService } from './alertService.js';
import { config } from './config.js';
import { recorder } from './recorder.js';
import { featureService } from './featureService.js';
import { ruleToLabel } from './normalizer.js';

const RULES_FILE = path.resolve(process.cwd(), 'rules.json');
const SETTINGS_FILE = path.resolve(process.cwd(), 'settings.json');
const THREATS_FILE = path.resolve(process.cwd(), 'threats.json');

export interface DetectionInput {
  app_id: string;
  app_name: string;
  client_ip: string;
  method: string;
  raw_path_and_query: string; // evaluated in memory only, never persisted
  status_code: number;
  response_time_ms: number;
  user_agent: string;
  user_id?: string;
  login_result?: 'ok' | 'fail' | 'none';
}

class ThreatEngine {
  private rules: Map<string, ThreatRule> = new Map();
  private threats: Map<string, ThreatRecord> = new Map(); // key: app_id:ip:rule_id -> ThreatRecord
  private settings: PlatformSettings = {
    mode: 'shadow',
    notify_on_high_critical: true,
    alert_webhook_url: '',
    alert_min_severity: 'high',
    alert_dedup_minutes: 30,
    raw_traffic_retention_days: 30,
    feature_retention_days: 90,
  };

  // Sliding window in-memory state tracking
  private failedLoginsByIp = new Map<string, number[]>(); // key: app:ip -> timestamps
  private failedLoginsByUser = new Map<string, { time: number; user: string }[]>(); // key: app:ip -> [{ time, user }]
  private requestsByIp = new Map<string, number[]>(); // key: app:ip -> timestamps
  private productRequestsByIp = new Map<string, number[]>(); // key: app:ip -> timestamps
  private orderAccessByIp = new Map<string, { time: number; id: string }[]>(); // key: app:ip -> [{ time, id }]
  private errorsByApp = new Map<string, number[]>(); // key: app -> timestamps
  private registrationsByIp = new Map<string, number[]>(); // key: app:ip -> timestamps
  private couponTriesByIp = new Map<string, number[]>(); // key: app:ip -> timestamps
  private knownIpsByApp = new Map<string, Set<string>>(); // key: app -> Set of IPs that called benign endpoints

  // Listeners for live toast notification events (SSE or polling)
  private newThreatListeners: ((threat: ThreatRecord) => void)[] = [];

  constructor() {
    this.loadRules();
    this.loadSettings();
    this.loadThreats();

    // Auto cleanup old window counters every 60 seconds
    setInterval(() => this.cleanupExpiredCounters(), 60000).unref();
  }

  public loadRules(): ThreatRule[] {
    try {
      if (fs.existsSync(RULES_FILE)) {
        const raw = fs.readFileSync(RULES_FILE, 'utf8');
        const list: ThreatRule[] = JSON.parse(raw);
        this.rules.clear();
        for (const r of list) {
          this.rules.set(r.id, r);
        }
      }
    } catch (err) {
      console.warn('[ThreatEngine] Could not load rules.json:', err);
    }
    return Array.from(this.rules.values());
  }

  public saveRules(): void {
    try {
      const list = Array.from(this.rules.values());
      fs.writeFileSync(RULES_FILE, JSON.stringify(list, null, 2), 'utf8');
    } catch (err) {
      console.error('[ThreatEngine] Failed to save rules.json:', err);
    }
  }

  public updateRule(id: string, updates: Partial<ThreatRule>): ThreatRule | null {
    const rule = this.rules.get(id);
    if (!rule) return null;
    Object.assign(rule, updates);
    this.saveRules();
    return rule;
  }

  public getRules(): ThreatRule[] {
    return Array.from(this.rules.values());
  }

  public loadSettings(): PlatformSettings {
    try {
      if (fs.existsSync(SETTINGS_FILE)) {
        const raw = fs.readFileSync(SETTINGS_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        this.settings = {
          mode: parsed.mode === 'alert_only' ? 'alert_only' : 'shadow',
          notify_on_high_critical: parsed.notify_on_high_critical !== false,
          description: parsed.description,
          alert_webhook_url: typeof parsed.alert_webhook_url === 'string' ? parsed.alert_webhook_url : '',
          alert_min_severity: parsed.alert_min_severity || 'high',
          alert_dedup_minutes: parsed.alert_dedup_minutes !== undefined ? Number(parsed.alert_dedup_minutes) : 30,
          raw_traffic_retention_days: parsed.raw_traffic_retention_days !== undefined ? Math.max(1, Number(parsed.raw_traffic_retention_days) || 30) : 30,
          feature_retention_days: parsed.feature_retention_days !== undefined ? Math.max(1, Number(parsed.feature_retention_days) || 90) : 90,
        };
      }
    } catch {
      this.settings = {
        mode: 'shadow',
        notify_on_high_critical: true,
        alert_webhook_url: '',
        alert_min_severity: 'high',
        alert_dedup_minutes: 30,
        raw_traffic_retention_days: 30,
        feature_retention_days: 90,
      };
    }
    return this.getSettings();
  }

  public updateSettings(updates: Partial<PlatformSettings>): PlatformSettings {
    const cleanUpdates: Partial<PlatformSettings> = { ...updates };
    if (cleanUpdates.alert_dedup_minutes !== undefined) {
      cleanUpdates.alert_dedup_minutes = Math.max(0, Number(cleanUpdates.alert_dedup_minutes) || 0);
    }
    if (cleanUpdates.raw_traffic_retention_days !== undefined) {
      cleanUpdates.raw_traffic_retention_days = Math.max(1, Number(cleanUpdates.raw_traffic_retention_days) || 30);
    }
    if (cleanUpdates.feature_retention_days !== undefined) {
      cleanUpdates.feature_retention_days = Math.max(1, Number(cleanUpdates.feature_retention_days) || 90);
    }
    Object.assign(this.settings, cleanUpdates);
    try {
      fs.writeFileSync(SETTINGS_FILE, JSON.stringify(this.settings, null, 2), 'utf8');
    } catch (err) {
      console.error('[ThreatEngine] Failed to save settings.json:', err);
    }
    return this.getSettings();
  }

  public getSettings(): PlatformSettings {
    return {
      ...this.settings,
      alert_webhook_url: this.settings.alert_webhook_url || config.alertWebhookUrl || '',
      alert_min_severity: this.settings.alert_min_severity || 'high',
      alert_dedup_minutes: this.settings.alert_dedup_minutes !== undefined ? this.settings.alert_dedup_minutes : 30,
      raw_traffic_retention_days: this.settings.raw_traffic_retention_days !== undefined ? this.settings.raw_traffic_retention_days : 30,
      feature_retention_days: this.settings.feature_retention_days !== undefined ? this.settings.feature_retention_days : 90,
    };
  }

  private loadThreats(): void {
    try {
      if (fs.existsSync(THREATS_FILE)) {
        const raw = fs.readFileSync(THREATS_FILE, 'utf8');
        const list: ThreatRecord[] = JSON.parse(raw);
        for (const t of list) {
          const key = `${t.app_id}:${t.client_ip}:${t.rule_id}`;
          this.threats.set(key, t);
        }
      }
    } catch (err) {
      console.warn('[ThreatEngine] Could not load threats.json:', err);
    }
  }

  private saveThreats(): void {
    try {
      const list = Array.from(this.threats.values());
      fs.writeFileSync(THREATS_FILE, JSON.stringify(list, null, 2), 'utf8');
    } catch (err) {
      console.error('[ThreatEngine] Failed to save threats.json:', err);
    }
  }

  /**
   * Evaluate input and return structured rule + canonical ML label info.
   */
  public evaluateDetailed(input: DetectionInput): { ruleId: string | null; ruleName: string | null; label: string } {
    const ruleName = this.evaluate(input);
    if (!ruleName) {
      return { ruleId: null, ruleName: null, label: 'normal' };
    }
    let matchedRuleId: string | null = null;
    for (const r of this.rules.values()) {
      if (r.name === ruleName) {
        matchedRuleId = r.id;
        break;
      }
    }
    return {
      ruleId: matchedRuleId,
      ruleName,
      label: ruleToLabel(matchedRuleId || ruleName),
    };
  }

  /**
   * Main threat evaluation pipeline.
   * Runs in the background (post-ingest).
   * Evaluates input in memory and returns any matched rule names or null.
   */
  public evaluate(input: DetectionInput): string | null {
    const now = Date.now();
    const appKey = input.app_id || 'default_app';
    const ipKey = `${appKey}:${input.client_ip}`;
    const rawPath = input.raw_path_and_query || '/';
    const pathOnly = rawPath.split('?')[0].split('#')[0] || '/';
    const userAgent = input.user_agent || '';

    let matchedRuleName: string | null = null;

    // Helper to check if rule is enabled
    const isRuleActive = (ruleId: string): ThreatRule | undefined => {
      const r = this.rules.get(ruleId);
      return r && r.enabled ? r : undefined;
    };

    // RULE-06: SQL injection detection
    const sqlRule = isRuleActive('RULE-06-SQL-INJECTION');
    if (sqlRule) {
      const sqlPattern =
        /(union\s+(all\s+)?select|select\s+.*from|or\s+['"\d\s]+=|\bdrop\s+table|\binsert\s+into|\bupdate\s+.*set|\bwaitfor\s+delay|\bsleep\s*\(\s*\d+\s*\)|--|\/\*|\*\/|['"]\s*or\s*['"]|benchmark\s*\()/i;
      if (sqlPattern.test(rawPath)) {
        matchedRuleName = sqlRule.name;
        this.recordThreat(sqlRule, input, `SQL injection pattern matched in request URI parameters`);
      }
    }

    // RULE-07: Cross-Site Scripting (XSS) detection
    const xssRule = isRuleActive('RULE-07-XSS');
    if (xssRule) {
      const xssPattern =
        /(<script|<\/script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|alert\s*\(|document\.cookie|<img\s+src=|<svg|onfocus=)/i;
      if (xssPattern.test(rawPath)) {
        matchedRuleName = matchedRuleName || xssRule.name;
        this.recordThreat(xssRule, input, `XSS script injection pattern detected in request URI`);
      }
    }

    // RULE-08: Path traversal and command injection
    const travRule = isRuleActive('RULE-08-PATH-TRAVERSAL');
    if (travRule) {
      const travPattern =
        /(\.\.[\/\\]|%2e%2e|%2f\.\.|%5c\.\.|\/etc\/(passwd|shadow)|c:[\\\/]windows|(\||;|&)\s*(id|whoami|cat\s+|ls\s+|uname|cmd|powershell|curl|wget))/i;
      if (travPattern.test(rawPath)) {
        matchedRuleName = matchedRuleName || travRule.name;
        this.recordThreat(travRule, input, `Path traversal or shell command injection pattern detected in URI`);
      }
    }

    // RULE-09: Bad bots and automated scanners
    const botRule = isRuleActive('RULE-09-BAD-BOTS');
    if (botRule) {
      const botPattern = /(sqlmap|nikto|nmap|dirbuster|gobuster|hydra|masscan|wpscan|burpsuite|acunetix|havij|netsparker)/i;
      const isEmptyUa = !userAgent || userAgent.trim() === '' || userAgent.toLowerCase() === 'unknown';
      if (botPattern.test(userAgent) || isEmptyUa) {
        matchedRuleName = matchedRuleName || botRule.name;
        this.recordThreat(botRule, input, isEmptyUa ? `Request sent with empty User-Agent header` : `Known vulnerability scanner User-Agent detected: ${userAgent.slice(0, 30)}`);
      }
    }

    // RULE-10: Sensitive admin endpoint probes
    const adminRule = isRuleActive('RULE-10-ADMIN-ACCESS');
    if (adminRule) {
      const lower = pathOnly.toLowerCase();
      const isAdminPath =
        lower.startsWith('/admin') ||
        lower.startsWith('/actuator') ||
        lower.includes('/.env') ||
        lower.includes('/.git') ||
        lower.startsWith('/wp-admin') ||
        lower.startsWith('/phpmyadmin') ||
        lower.startsWith('/server-status');

      if (isAdminPath) {
        matchedRuleName = matchedRuleName || adminRule.name;
        this.recordThreat(adminRule, input, `Probe directed at sensitive administrative endpoint (${pathOnly})`);
      }
    }

    // RULE-03: Rate limiting
    const rateRule = isRuleActive('RULE-03-RATE-LIMIT');
    if (rateRule) {
      const timestamps = this.cleanAndGetTimestamps(this.requestsByIp, ipKey, rateRule.window_seconds, now);
      timestamps.push(now);
      if (timestamps.length >= rateRule.threshold) {
        matchedRuleName = matchedRuleName || rateRule.name;
        this.recordThreat(rateRule, input, `High request rate: ${timestamps.length} requests in ${rateRule.window_seconds}s window`);
      }
    }

    // RULE-01: Brute force login
    const bruteRule = isRuleActive('RULE-01-BRUTE-FORCE');
    if (bruteRule && input.login_result === 'fail') {
      const timestamps = this.cleanAndGetTimestamps(this.failedLoginsByIp, ipKey, bruteRule.window_seconds, now);
      timestamps.push(now);
      if (timestamps.length >= bruteRule.threshold) {
        matchedRuleName = matchedRuleName || bruteRule.name;
        this.recordThreat(bruteRule, input, `Repeated authentication failures: ${timestamps.length} failed logins in ${bruteRule.window_seconds}s`);
      }
    }

    // RULE-02: Credential stuffing
    const credRule = isRuleActive('RULE-02-CRED-STUFFING');
    if (credRule && input.login_result === 'fail' && input.user_id) {
      const userList = this.cleanAndGetItems(this.failedLoginsByUser, ipKey, credRule.window_seconds, now);
      userList.push({ time: now, user: String(input.user_id) });
      const distinctUsers = new Set(userList.map((u) => u.user));
      if (distinctUsers.size >= credRule.threshold) {
        matchedRuleName = matchedRuleName || credRule.name;
        this.recordThreat(credRule, input, `Credential stuffing pattern: failures targeting ${distinctUsers.size} distinct user accounts from single IP`);
      }
    }

    // RULE-04: Product catalog scraping
    const scrapeRule = isRuleActive('RULE-04-SCRAPING');
    if (scrapeRule && input.method === 'GET' && pathOnly.toLowerCase().startsWith('/products')) {
      const timestamps = this.cleanAndGetTimestamps(this.productRequestsByIp, ipKey, scrapeRule.window_seconds, now);
      timestamps.push(now);
      if (timestamps.length >= scrapeRule.threshold) {
        matchedRuleName = matchedRuleName || scrapeRule.name;
        this.recordThreat(scrapeRule, input, `Catalog scraping behavior: ${timestamps.length} product lookups in ${scrapeRule.window_seconds}s`);
      }
    }

    // RULE-05: IDOR / BOLA enumeration
    const idorRule = isRuleActive('RULE-05-IDOR-BOLA');
    if (idorRule) {
      const orderMatch = pathOnly.match(/\/(orders|users|customers|invoices)\/([a-zA-Z0-9_-]+)/i);
      if (orderMatch && orderMatch[2]) {
        const targetId = orderMatch[2];
        const accessList = this.cleanAndGetItems(this.orderAccessByIp, ipKey, idorRule.window_seconds, now);
        accessList.push({ time: now, id: targetId });
        const distinctIds = new Set(accessList.map((a) => a.id));
        if (distinctIds.size >= idorRule.threshold) {
          matchedRuleName = matchedRuleName || idorRule.name;
          this.recordThreat(idorRule, input, `BOLA/IDOR object enumeration: accessed ${distinctIds.size} distinct resource identifiers within window`);
        }
      }
    }

    // RULE-11: Application error spike
    const errorRule = isRuleActive('RULE-11-ERROR-SPIKE');
    if (errorRule && input.status_code >= 400) {
      const timestamps = this.cleanAndGetTimestamps(this.errorsByApp, appKey, errorRule.window_seconds, now);
      timestamps.push(now);
      if (timestamps.length >= errorRule.threshold) {
        matchedRuleName = matchedRuleName || errorRule.name;
        this.recordThreat(errorRule, input, `Spike in HTTP errors: ${timestamps.length} errors observed within ${errorRule.window_seconds}s for app ${input.app_name}`);
      }
    }

    // RULE-12: Fake account signups
    const signupRule = isRuleActive('RULE-12-FAKE-SIGNUPS');
    if (signupRule && input.method === 'POST' && (pathOnly.includes('/register') || pathOnly.includes('/signup'))) {
      const timestamps = this.cleanAndGetTimestamps(this.registrationsByIp, ipKey, signupRule.window_seconds, now);
      timestamps.push(now);
      if (timestamps.length >= signupRule.threshold) {
        matchedRuleName = matchedRuleName || signupRule.name;
        this.recordThreat(signupRule, input, `Rapid account registrations: ${timestamps.length} registration attempts within ${signupRule.window_seconds}s`);
      }
    }

    // RULE-13: Coupon / promo code abuse
    const couponRule = isRuleActive('RULE-13-COUPON-ABUSE');
    if (couponRule && input.method === 'POST' && (pathOnly.includes('/coupon') || pathOnly.includes('/promo') || pathOnly.includes('/discount'))) {
      const timestamps = this.cleanAndGetTimestamps(this.couponTriesByIp, ipKey, couponRule.window_seconds, now);
      timestamps.push(now);
      if (timestamps.length >= couponRule.threshold) {
        matchedRuleName = matchedRuleName || couponRule.name;
        this.recordThreat(couponRule, input, `Promotional code brute-forcing: ${timestamps.length} coupon validation attempts in ${couponRule.window_seconds}s`);
      }
    }

    return matchedRuleName;
  }

  /**
   * Record or de-duplicate an identified threat.
   * Same attacker + same rule = ONE threat with an increasing hit count.
   */
  private recordThreat(rule: ThreatRule, input: DetectionInput, evidenceSummary: string): void {
    const key = `${input.app_id}:${input.client_ip}:${rule.id}`;
    const nowIso = new Date().toISOString();

    const existing = this.threats.get(key);
    if (existing) {
      existing.hit_count++;
      existing.last_seen = nowIso;
      existing.evidence = `${evidenceSummary} (Hit count: ${existing.hit_count})`;

      // Send one extra alert when a threat reaches 100 hits
      if (existing.hit_count === 100 && !existing.milestone_100_alerted) {
        existing.milestone_100_alerted = true;
        alertService.notifyThreatInBackground(existing, this.getSettings(), 'milestone_100_hits');
      }

      this.saveThreats();
    } else {
      const newThreat: ThreatRecord = {
        id: `thr_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
        app_id: input.app_id,
        app_name: input.app_name,
        rule_id: rule.id,
        rule_name: rule.name,
        severity: rule.severity,
        client_ip: input.client_ip,
        hashed_user_id: input.user_id ? crypto.createHash('sha256').update(String(input.user_id)).digest('hex').slice(0, 12) : undefined,
        first_seen: nowIso,
        last_seen: nowIso,
        hit_count: 1,
        status: 'open',
        evidence: evidenceSummary,
        owasp_tag: rule.owasp_tag,
      };

      this.threats.set(key, newThreat);
      this.saveThreats();

      // Background webhook alert (severity-filtered & deduplicated)
      alertService.notifyThreatInBackground(newThreat, this.getSettings(), 'new_threat');

      // Notify listeners for high and critical threats
      if (rule.severity === 'high' || rule.severity === 'critical') {
        for (const listener of this.newThreatListeners) {
          try {
            listener(newThreat);
          } catch {
            // Ignore listener error
          }
        }
      }
    }
  }

  /**
   * Helper to clean expired timestamps and return active array
   */
  private cleanAndGetTimestamps(map: Map<string, number[]>, key: string, windowSeconds: number, now: number): number[] {
    const thresholdTime = now - windowSeconds * 1000;
    const existing = map.get(key) || [];
    const active = existing.filter((t) => t > thresholdTime);
    map.set(key, active);
    return active;
  }

  /**
   * Helper to clean expired item objects
   */
  private cleanAndGetItems<T extends { time: number }>(map: Map<string, T[]>, key: string, windowSeconds: number, now: number): T[] {
    const thresholdTime = now - windowSeconds * 1000;
    const existing = map.get(key) || [];
    const active = existing.filter((item) => item.time > thresholdTime);
    map.set(key, active);
    return active;
  }

  /**
   * Cleanup memory windows periodically
   */
  private cleanupExpiredCounters(): void {
    const now = Date.now();
    const oneHourAgo = now - 3600000;

    for (const [key, arr] of this.requestsByIp.entries()) {
      const valid = arr.filter((t) => t > oneHourAgo);
      if (valid.length === 0) this.requestsByIp.delete(key);
      else this.requestsByIp.set(key, valid);
    }
    for (const [key, arr] of this.failedLoginsByIp.entries()) {
      const valid = arr.filter((t) => t > oneHourAgo);
      if (valid.length === 0) this.failedLoginsByIp.delete(key);
      else this.failedLoginsByIp.set(key, valid);
    }
    for (const [key, arr] of this.productRequestsByIp.entries()) {
      const valid = arr.filter((t) => t > oneHourAgo);
      if (valid.length === 0) this.productRequestsByIp.delete(key);
      else this.productRequestsByIp.set(key, valid);
    }
  }

  /**
   * Threat queries and status mutations
   */
  public getThreats(filters?: { severity?: string; rule_id?: string; app_id?: string; status?: string }): ThreatRecord[] {
    let list = Array.from(this.threats.values());

    if (filters) {
      if (filters.severity && filters.severity !== 'ALL') {
        list = list.filter((t) => t.severity === filters.severity);
      }
      if (filters.rule_id && filters.rule_id !== 'ALL') {
        list = list.filter((t) => t.rule_id === filters.rule_id);
      }
      if (filters.app_id && filters.app_id !== 'ALL') {
        list = list.filter((t) => t.app_id === filters.app_id);
      }
      if (filters.status && filters.status !== 'ALL') {
        list = list.filter((t) => t.status === filters.status);
      }
    }

    return list.sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime());
  }

  public updateThreatStatus(threatId: string, status: ThreatStatus): ThreatRecord | null {
    for (const threat of this.threats.values()) {
      if (threat.id === threatId) {
        threat.status = status;
        this.saveThreats();

        // Revert matching request and feature labels to normal on false positive
        if (status === 'false_positive') {
          recorder.markFalsePositiveByThreat({
            app_id: threat.app_id,
            client_ip: threat.client_ip,
            rule_id: threat.rule_id,
            rule_name: threat.rule_name,
          });
          featureService.applyFalsePositiveCorrection({
            app_id: threat.app_id,
            client_ip: threat.client_ip,
            rule_id: threat.rule_id,
            rule_name: threat.rule_name,
          });
        }

        return threat;
      }
    }
    return null;
  }

  public getOpenThreatsSummary(appId?: string): { critical: number; high: number; medium: number; low: number; total: number } {
    let list = Array.from(this.threats.values()).filter((t) => t.status === 'open');
    if (appId && appId !== 'ALL') {
      list = list.filter((t) => t.app_id === appId);
    }

    const summary = { critical: 0, high: 0, medium: 0, low: 0, total: list.length };
    for (const t of list) {
      if (t.severity in summary) {
        (summary as any)[t.severity]++;
      }
    }
    return summary;
  }

  public onNewThreat(listener: (threat: ThreatRecord) => void): () => void {
    this.newThreatListeners.push(listener);
    return () => {
      this.newThreatListeners = this.newThreatListeners.filter((l) => l !== listener);
    };
  }

  public clearThreats(): void {
    this.threats.clear();
    this.saveThreats();
  }

  public clearAllStateForTesting(): void {
    this.threats.clear();
    this.failedLoginsByIp.clear();
    this.failedLoginsByUser.clear();
    this.requestsByIp.clear();
    this.productRequestsByIp.clear();
    this.orderAccessByIp.clear();
    this.errorsByApp.clear();
    this.registrationsByIp.clear();
    this.couponTriesByIp.clear();
    this.knownIpsByApp.clear();
    this.saveThreats();
    alertService.clearStateForTesting();
  }
}

export const threatEngine = new ThreatEngine();
