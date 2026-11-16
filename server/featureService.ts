import fs from 'fs';
import crypto from 'crypto';
import { config, hashClientIp } from './config.js';
import { recorder } from './recorder.js';
import { ruleToLabel } from './normalizer.js';
import {
  FeatureRow,
  FeatureWindowSize,
  LabelSource,
  TrafficRecord,
} from './types.js';

const WINDOW_DURATIONS_MS: Record<FeatureWindowSize, number> = {
  '1m': 60 * 1000,
  '5m': 5 * 60 * 1000,
  '1h': 60 * 60 * 1000,
};

export interface FeaturePreviewResult {
  total_rows: number;
  preview_rows: FeatureRow[];
  label_counts: Record<string, number>;
  source_counts: { rule: number; human: number };
  imbalance_warning: string | null;
}

class FeatureService {
  private featuresLogPath: string;
  private minuteJobTimer: NodeJS.Timeout | null = null;
  private cleanupJobTimer: NodeJS.Timeout | null = null;
  // Track last extracted bucket per (app_id, raw_ip, window_size) so identical idle windows are not duplicated every tick
  private lastExtractedSignature = new Map<string, string>();

  constructor(featuresLogPath: string = config.featuresLogPath) {
    this.featuresLogPath = featuresLogPath;
  }

  public getFeaturesFilePath(): string {
    return this.featuresLogPath;
  }

  /**
   * Compute a single ML feature row for one (app_id, client_ip) over a set of records in one window.
   * Uses strictly metadata (zero bodies, query values, or secrets).
   */
  public computeFeatureRow(
    records: TrafficRecord[],
    options: {
      appId: string;
      appName: string;
      clientIp: string;
      windowSize: FeatureWindowSize;
      windowEndMs: number;
      hashIps?: boolean;
      salt?: string;
    }
  ): FeatureRow {
    const sorted = [...records].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    const requestCount = sorted.length;
    let count4xx = 0;
    let count5xx = 0;
    let failedLogins = 0;
    let postCount = 0;
    let nightCount = 0;
    let totalResponseTime = 0;
    let totalRequestSize = 0;
    let maxRequestSize = 0;

    const endpoints = new Set<string>();
    const userIds = new Set<string>();
    const userAgents = new Set<string>();
    const timestampsMs: number[] = [];

    const attackLabelCounts = new Map<string, number>();
    let hasHumanCorrection = false;
    let attackHasHumanSource = false;

    for (const rec of sorted) {
      const status = Number(rec.status_code) || 0;
      if (status >= 400 && status < 500) count4xx++;
      if (status >= 500) count5xx++;

      if (rec.login_result === 'fail') failedLogins++;
      if ((rec.method || '').toUpperCase() === 'POST') postCount++;

      const tsMs = new Date(rec.timestamp).getTime();
      if (!isNaN(tsMs)) {
        timestampsMs.push(tsMs);
        const utcHour = new Date(tsMs).getUTCHours();
        if (utcHour >= 0 && utcHour < 5) {
          nightCount++;
        }
      }

      totalResponseTime += Number(rec.response_time_ms) || 0;
      const reqSize = Number(rec.request_size) || 0;
      totalRequestSize += reqSize;
      if (reqSize > maxRequestSize) maxRequestSize = reqSize;

      if (rec.normalized_path) endpoints.add(rec.normalized_path);
      if (rec.user_id_hash) userIds.add(rec.user_id_hash);
      if (rec.user_agent) userAgents.add(rec.user_agent);

      const recLabel =
        rec.label ||
        (rec.threat_rule && rec.threat_rule !== 'normal'
          ? ruleToLabel(rec.threat_rule_id || rec.threat_rule)
          : 'normal');
      const recSource: LabelSource = rec.label_source || 'rule';

      if (recSource === 'human') {
        hasHumanCorrection = true;
      }
      if (recLabel !== 'normal') {
        attackLabelCounts.set(recLabel, (attackLabelCounts.get(recLabel) || 0) + 1);
        if (recSource === 'human') {
          attackHasHumanSource = true;
        }
      }
    }

    let totalGapMs = 0;
    for (let i = 1; i < timestampsMs.length; i++) {
      totalGapMs += Math.max(0, timestampsMs[i] - timestampsMs[i - 1]);
    }
    const avgGapMs =
      timestampsMs.length > 1
        ? Math.round((totalGapMs / (timestampsMs.length - 1)) * 100) / 100
        : 0;

    let finalLabel = 'normal';
    let maxAttackCount = 0;
    for (const [lbl, cnt] of attackLabelCounts.entries()) {
      if (cnt >= maxAttackCount) {
        maxAttackCount = cnt;
        finalLabel = lbl;
      }
    }

    const finalLabelSource: LabelSource =
      finalLabel === 'normal'
        ? hasHumanCorrection
          ? 'human'
          : 'rule'
        : attackHasHumanSource
        ? 'human'
        : 'rule';

    const shouldHashIp = options.hashIps ?? config.hashIps;
    const outputIp = hashClientIp(options.clientIp, shouldHashIp, options.salt ?? config.ipHashSalt);

    const round4 = (n: number) => Math.round(n * 10000) / 10000;
    const round2 = (n: number) => Math.round(n * 100) / 100;

    return {
      feature_id: `feat_${options.windowSize}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date(options.windowEndMs).toISOString(),
      app_id: options.appId,
      app_name: options.appName,
      client_ip: outputIp,
      window_size: options.windowSize,
      request_count: requestCount,
      error_rate_4xx: requestCount > 0 ? round4(count4xx / requestCount) : 0,
      error_rate_5xx: requestCount > 0 ? round4(count5xx / requestCount) : 0,
      unique_endpoints: endpoints.size,
      unique_user_ids: userIds.size,
      failed_logins: failedLogins,
      avg_gap_between_requests_ms: avgGapMs,
      avg_response_time_ms: requestCount > 0 ? round2(totalResponseTime / requestCount) : 0,
      avg_request_size: requestCount > 0 ? round2(totalRequestSize / requestCount) : 0,
      max_request_size: maxRequestSize,
      post_ratio: requestCount > 0 ? round4(postCount / requestCount) : 0,
      night_time_ratio: requestCount > 0 ? round4(nightCount / requestCount) : 0,
      unique_user_agents: userAgents.size,
      label: finalLabel,
      label_source: finalLabelSource,
    };
  }

  /**
   * Extract feature rows across all 3 windows (1m, 5m, 1h) per (app_id, client_ip)
   */
  public extractWindowFeatures(
    records: TrafficRecord[],
    windowEndMs: number = Date.now(),
    options?: {
      hashIps?: boolean;
      salt?: string;
      windows?: FeatureWindowSize[];
      skipUnchanged?: boolean;
    }
  ): FeatureRow[] {
    const windows = options?.windows || (['1m', '5m', '1h'] as FeatureWindowSize[]);
    const rows: FeatureRow[] = [];

    for (const win of windows) {
      const windowStartMs = windowEndMs - WINDOW_DURATIONS_MS[win];

      // Group records inside [windowStartMs, windowEndMs] by (app_id, client_ip)
      const grouped = new Map<string, { appId: string; appName: string; clientIp: string; items: TrafficRecord[] }>();

      for (const rec of records) {
        const tsMs = new Date(rec.timestamp).getTime();
        if (isNaN(tsMs) || tsMs <= windowStartMs || tsMs > windowEndMs) {
          continue;
        }
        const appId = rec.app_id || 'app_fakeshop_demo';
        const appName = rec.app_name || 'Fake Shop (Demo)';
        const clientIp = rec.client_ip || '127.0.0.1';
        const key = `${appId}::${clientIp}`;

        let group = grouped.get(key);
        if (!group) {
          group = { appId, appName, clientIp, items: [] };
          grouped.set(key, group);
        }
        group.items.push(rec);
      }

      for (const [key, group] of grouped.entries()) {
        if (options?.skipUnchanged) {
          const newestTs = group.items.reduce(
            (max, r) => Math.max(max, new Date(r.timestamp).getTime() || 0),
            0
          );
          const sigKey = `${win}:${key}`;
          const signature = `${group.items.length}:${newestTs}`;
          if (this.lastExtractedSignature.get(sigKey) === signature) {
            continue;
          }
          this.lastExtractedSignature.set(sigKey, signature);
        }

        rows.push(
          this.computeFeatureRow(group.items, {
            appId: group.appId,
            appName: group.appName,
            clientIp: group.clientIp,
            windowSize: win,
            windowEndMs,
            hashIps: options?.hashIps,
            salt: options?.salt,
          })
        );
      }
    }

    return rows;
  }

  /**
   * Append computed feature rows to features.jsonl (append-only).
   */
  public appendFeatures(rows: FeatureRow[], targetFilePath: string = this.featuresLogPath): number {
    if (rows.length === 0) return 0;
    try {
      const lines = rows.map((row) => JSON.stringify(row)).join('\n') + '\n';
      fs.appendFileSync(targetFilePath, lines, 'utf8');
      return rows.length;
    } catch (err) {
      console.error('[FeatureService] Failed to append to features.jsonl:', err);
      return 0;
    }
  }

  /**
   * Run feature extraction immediately against recent in-memory records and append to features.jsonl.
   */
  public extractAndSaveNow(
    windowEndMs: number = Date.now(),
    skipUnchanged: boolean = false
  ): FeatureRow[] {
    const records = recorder.getAllRecords();
    if (records.length === 0) return [];
    const rows = this.extractWindowFeatures(records, windowEndMs, { skipUnchanged });
    this.appendFeatures(rows);
    return rows;
  }

  /**
   * Start background jobs:
   * - Feature extraction every 1 minute (60s)
   * - Retention cleanup every 24 hours
   */
  public startBackgroundJobs(getRetentionSettings: () => { rawTrafficDays: number; featureDays: number }): void {
    if (!this.minuteJobTimer) {
      this.minuteJobTimer = setInterval(() => {
        try {
          this.extractAndSaveNow(Date.now(), true);
        } catch (err) {
          console.error('[FeatureService] Minute extraction job error:', err);
        }
      }, 60 * 1000).unref();
    }

    if (!this.cleanupJobTimer) {
      // Run once shortly after boot, then daily (every 24h)
      setTimeout(() => {
        try {
          const { rawTrafficDays, featureDays } = getRetentionSettings();
          this.runRetentionCleanup(rawTrafficDays, featureDays);
        } catch (err) {
          console.error('[FeatureService] Initial retention cleanup error:', err);
        }
      }, 15 * 1000).unref();

      this.cleanupJobTimer = setInterval(() => {
        try {
          const { rawTrafficDays, featureDays } = getRetentionSettings();
          this.runRetentionCleanup(rawTrafficDays, featureDays);
        } catch (err) {
          console.error('[FeatureService] Daily retention cleanup error:', err);
        }
      }, 24 * 60 * 60 * 1000).unref();
    }
  }

  /**
   * Read stored feature rows from features.jsonl with optional filters.
   */
  public loadFeatures(
    filters?: {
      app_id?: string;
      window_size?: string;
      start_date?: string;
      end_date?: string;
    },
    targetFilePath: string = this.featuresLogPath
  ): FeatureRow[] {
    if (!fs.existsSync(targetFilePath)) {
      return [];
    }

    const raw = fs.readFileSync(targetFilePath, 'utf8');
    const lines = raw.split('\n').filter((l) => l.trim().length > 0);
    let rows: FeatureRow[] = [];

    for (const line of lines) {
      try {
        rows.push(JSON.parse(line) as FeatureRow);
      } catch {
        // Skip malformed lines
      }
    }

    if (filters) {
      if (filters.app_id && filters.app_id !== 'ALL') {
        rows = rows.filter((r) => r.app_id === filters.app_id);
      }
      if (filters.window_size && filters.window_size !== 'ALL') {
        rows = rows.filter((r) => r.window_size === filters.window_size);
      }
      if (filters.start_date) {
        const startMs = new Date(`${filters.start_date}T00:00:00.000Z`).getTime();
        if (!isNaN(startMs)) {
          rows = rows.filter((r) => new Date(r.timestamp).getTime() >= startMs);
        }
      }
      if (filters.end_date) {
        const endMs = new Date(`${filters.end_date}T23:59:59.999Z`).getTime();
        if (!isNaN(endMs)) {
          rows = rows.filter((r) => new Date(r.timestamp).getTime() <= endMs);
        }
      }
    }

    // Sort newest first
    rows.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return rows;
  }

  /**
   * Human feedback propagation: when a threat is marked "false_positive",
   * update matching stored feature rows back to label: "normal" and label_source: "human".
   */
  public applyFalsePositiveCorrection(
    threat: { app_id: string; client_ip: string; rule_id: string; rule_name: string },
    targetFilePath: string = this.featuresLogPath
  ): number {
    if (!fs.existsSync(targetFilePath)) return 0;

    const mlLabel = ruleToLabel(threat.rule_id || threat.rule_name);
    const hashedIp = hashClientIp(threat.client_ip, true);
    let corrected = 0;

    try {
      const raw = fs.readFileSync(targetFilePath, 'utf8');
      const lines = raw.split('\n').filter((l) => l.trim().length > 0);
      let changed = false;

      const updatedLines = lines.map((line) => {
        try {
          const row = JSON.parse(line) as FeatureRow;
          const matchesApp = row.app_id === threat.app_id;
          const matchesIp = row.client_ip === threat.client_ip || row.client_ip === hashedIp;
          const matchesLabel = row.label === mlLabel || row.label === threat.rule_name;

          if (matchesApp && matchesIp && matchesLabel) {
            row.label = 'normal';
            row.label_source = 'human';
            changed = true;
            corrected++;
            return JSON.stringify(row);
          }
          return line;
        } catch {
          return line;
        }
      });

      if (changed) {
        fs.writeFileSync(
          targetFilePath,
          updatedLines.join('\n') + (updatedLines.length > 0 ? '\n' : ''),
          'utf8'
        );
      }
    } catch (err) {
      console.error('[FeatureService] Failed to apply false positive label correction to features.jsonl:', err);
    }

    return corrected;
  }

  /**
   * Daily retention clean-up across features.jsonl and traffic.jsonl.
   */
  public runRetentionCleanup(
    rawTrafficDays: number = 30,
    featureDays: number = 90,
    nowMs: number = Date.now(),
    featuresFilePath: string = this.featuresLogPath,
    trafficFilePath?: string
  ): { raw_removed: number; features_removed: number; features_kept: number } {
    const safeFeatureDays = Math.max(1, Number(featureDays) || 90);
    const featureCutoffMs = nowMs - safeFeatureDays * 24 * 60 * 60 * 1000;

    let featuresRemoved = 0;
    let featuresKept = 0;

    try {
      if (fs.existsSync(featuresFilePath)) {
        const raw = fs.readFileSync(featuresFilePath, 'utf8');
        const lines = raw.split('\n').filter((l) => l.trim().length > 0);
        const keptLines: string[] = [];

        for (const line of lines) {
          try {
            const row = JSON.parse(line) as FeatureRow;
            const ts = new Date(row.timestamp).getTime();
            if (!isNaN(ts) && ts < featureCutoffMs) {
              featuresRemoved++;
            } else {
              keptLines.push(line);
            }
          } catch {
            // Skip malformed line
          }
        }

        featuresKept = keptLines.length;
        if (featuresRemoved > 0) {
          fs.writeFileSync(
            featuresFilePath,
            keptLines.join('\n') + (keptLines.length > 0 ? '\n' : ''),
            'utf8'
          );
        }
      }
    } catch (err) {
      console.error('[FeatureService] Feature retention cleanup error:', err);
    }

    const rawResult = recorder.cleanupOlderThanDays(rawTrafficDays, nowMs, trafficFilePath);

    return {
      raw_removed: rawResult.removed,
      features_removed: featuresRemoved,
      features_kept: featuresKept,
    };
  }

  /**
   * Build preview statistics, label counts, and class-imbalance warnings.
   */
  public buildPreviewSummary(rows: FeatureRow[]): FeaturePreviewResult {
    const labelCounts: Record<string, number> = {};
    const sourceCounts = { rule: 0, human: 0 };

    for (const r of rows) {
      const lbl = r.label || 'normal';
      labelCounts[lbl] = (labelCounts[lbl] || 0) + 1;
      if (r.label_source === 'human') sourceCounts.human++;
      else sourceCounts.rule++;
    }

    const total = rows.length;
    let imbalanceWarning: string | null = null;

    if (total > 0) {
      let dominantLabel = 'normal';
      let dominantCount = 0;
      for (const [lbl, cnt] of Object.entries(labelCounts)) {
        if (cnt > dominantCount) {
          dominantCount = cnt;
          dominantLabel = lbl;
        }
      }

      const dominantPct = (dominantCount / total) * 100;
      const distinctLabels = Object.keys(labelCounts).length;

      if (dominantPct >= 90) {
        imbalanceWarning = `Unbalanced dataset warning: ${dominantPct.toFixed(1)}% of rows are labeled "${dominantLabel}" (${dominantCount}/${total}). Use "Generate sample training data" or include attack traffic before training.`;
      } else if (distinctLabels === 1 && total >= 3) {
        imbalanceWarning = `Single-class dataset warning: 100% of rows are labeled "${dominantLabel}". ML classifiers need at least two label classes.`;
      }
    }

    return {
      total_rows: total,
      preview_rows: rows.slice(0, 20),
      label_counts: labelCounts,
      source_counts: sourceCounts,
      imbalance_warning: imbalanceWarning,
    };
  }

  /**
   * Export rows as RFC-4180 CSV string.
   */
  public toCsv(rows: FeatureRow[]): string {
    const headers: (keyof FeatureRow)[] = [
      'timestamp',
      'app_id',
      'app_name',
      'client_ip',
      'window_size',
      'request_count',
      'error_rate_4xx',
      'error_rate_5xx',
      'unique_endpoints',
      'unique_user_ids',
      'failed_logins',
      'avg_gap_between_requests_ms',
      'avg_response_time_ms',
      'avg_request_size',
      'max_request_size',
      'post_ratio',
      'night_time_ratio',
      'unique_user_agents',
      'label',
      'label_source',
    ];

    const escapeCsv = (val: unknown): string => {
      if (val === null || val === undefined) return '';
      const str = String(val);
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const lines = [headers.join(',')];
    for (const row of rows) {
      lines.push(headers.map((h) => escapeCsv(row[h])).join(','));
    }
    return lines.join('\n') + '\n';
  }
}

export const featureService = new FeatureService(config.featuresLogPath);
