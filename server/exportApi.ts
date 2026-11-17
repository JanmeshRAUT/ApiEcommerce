import express, { Request, Response } from 'express';
import crypto from 'crypto';
import { requireDashboardAuth } from './authService.js';
import { featureService } from './featureService.js';
import { threatEngine } from './threatEngine.js';
import { appsService } from './appsService.js';
import { recorder } from './recorder.js';
import { normalizePath, extractQueryParamNames } from './normalizer.js';
import { TrafficRecord } from './types.js';

export const exportRouter = express.Router();

// All ML Data export and simulator endpoints require dashboard admin authentication
exportRouter.use(requireDashboardAuth);

/**
 * GET /api/v1/export/features.csv
 * Download filtered ML feature rows as CSV (admin login required).
 */
exportRouter.get('/features.csv', (req: Request, res: Response) => {
  const app_id = req.query.app_id as string | undefined;
  const window_size = req.query.window_size as string | undefined;
  const start_date = req.query.start_date as string | undefined;
  const end_date = req.query.end_date as string | undefined;

  const rows = featureService.loadFeatures({ app_id, window_size, start_date, end_date });
  const csv = featureService.toCsv(rows);

  const fileSuffix = window_size && window_size !== 'ALL' ? `_${window_size}` : '_all';
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="features${fileSuffix}.csv"`);
  res.send(csv);
});

/**
 * GET /api/v1/export/features/preview
 * Preview first 20 rows, label counts, and class-imbalance warnings.
 */
exportRouter.get('/features/preview', (req: Request, res: Response) => {
  const app_id = req.query.app_id as string | undefined;
  const window_size = req.query.window_size as string | undefined;
  const start_date = req.query.start_date as string | undefined;
  const end_date = req.query.end_date as string | undefined;

  const rows = featureService.loadFeatures({ app_id, window_size, start_date, end_date });
  const summary = featureService.buildPreviewSummary(rows);

  res.json({
    ...summary,
    filters: {
      app_id: app_id || 'ALL',
      window_size: window_size || 'ALL',
      start_date: start_date || null,
      end_date: end_date || null,
    },
  });
});

/**
 * POST /api/v1/export/extract-now
 * Trigger immediate feature extraction from in-memory traffic into features.jsonl.
 */
exportRouter.post('/extract-now', (_req: Request, res: Response) => {
  const created = featureService.extractAndSaveNow(Date.now(), false);
  res.json({
    success: true,
    extracted_rows: created.length,
    message: `Extracted ${created.length} feature rows across 1m, 5m, and 1h windows.`,
  });
});

/**
 * POST /api/v1/export/cleanup-now
 * Trigger immediate retention clean-up using current Settings.
 */
exportRouter.post('/cleanup-now', (_req: Request, res: Response) => {
  const settings = threatEngine.getSettings();
  const rawDays = settings.raw_traffic_retention_days ?? 30;
  const featureDays = settings.feature_retention_days ?? 90;

  const result = featureService.runRetentionCleanup(rawDays, featureDays);
  res.json({
    success: true,
    raw_traffic_retention_days: rawDays,
    feature_retention_days: featureDays,
    ...result,
    message: `Cleanup complete: removed ${result.raw_removed} expired raw request(s) and ${result.features_removed} expired feature row(s).`,
  });
});

/**
 * POST /api/v1/export/simulate-training-data
 * Generates a balanced mix of normal traffic + attacks (brute force, SQLi, scraping, IDOR, bad bots)
 * and extracts ML feature rows across 1m, 5m, and 1h windows so export can be tested immediately.
 */
exportRouter.post('/simulate-training-data', (req: Request, res: Response) => {
  const requestedAppId = req.body?.app_id as string | undefined;
  const targetApp =
    requestedAppId && requestedAppId !== 'ALL'
      ? appsService.getAppById(requestedAppId)
      : appsService.getFirstActiveApp()?.app || null;

  if (!targetApp) {
    res.status(400).json({ error: 'Register an application before generating sample training data.' });
    return;
  }

  const appId = targetApp.id;
  const appName = targetApp.name;
  const env = targetApp.environment;

  const nowMs = Date.now();
  let totalEvents = 0;

  const pushSample = (
    offsetMs: number,
    clientIp: string,
    method: string,
    rawPathAndQuery: string,
    statusCode: number,
    userAgent: string,
    options?: {
      loginResult?: 'ok' | 'fail' | 'none';
      userId?: string;
      requestSize?: number;
      responseSize?: number;
      responseTimeMs?: number;
    }
  ) => {
    const cleanPath = rawPathAndQuery.split('?')[0].split('#')[0] || '/';
    const loginResult = options?.loginResult || 'none';
    const responseTimeMs = options?.responseTimeMs ?? Math.round((Math.random() * 25 + 4) * 10) / 10;

    const detection = threatEngine.evaluateDetailed({
      app_id: appId,
      app_name: appName,
      client_ip: clientIp,
      method,
      raw_path_and_query: rawPathAndQuery,
      status_code: statusCode,
      response_time_ms: responseTimeMs,
      user_agent: userAgent,
      user_id: options?.userId,
      login_result: loginResult,
    });

    const record: TrafficRecord = {
      request_id: `mlsim_${nowMs}_${crypto.randomBytes(4).toString('hex')}`,
      app_id: appId,
      app_name: appName,
      environment: env,
      timestamp: new Date(nowMs - offsetMs).toISOString(),
      client_ip: clientIp,
      method,
      path: cleanPath,
      normalized_path: normalizePath(cleanPath),
      query_param_names: extractQueryParamNames(rawPathAndQuery),
      status_code: statusCode,
      response_time_ms: responseTimeMs,
      request_size: options?.requestSize ?? (method === 'POST' ? 240 : 0),
      response_size: options?.responseSize ?? 420,
      user_agent: userAgent,
      user_id_hash: options?.userId
        ? crypto.createHash('sha256').update(options.userId).digest('hex').slice(0, 12)
        : undefined,
      login_result: loginResult,
      is_synthetic: true,
      threat_rule: detection.ruleName || 'normal',
      threat_rule_id: detection.ruleId || undefined,
      label: detection.label,
      label_source: 'rule',
    };

    recorder.recordSync(record, true);
    totalEvents++;
  };

  // Normal traffic samples
  const normalIps = ['192.168.10.21', '192.168.10.22', '10.10.4.15'];
  normalIps.forEach((ip, idx) => {
    const uid = `cust_normal_${idx + 1}`;
    pushSample(45_000, ip, 'GET', '/products', 200, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', { userId: uid });
    pushSample(38_000, ip, 'GET', '/products/1', 200, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', { userId: uid });
    pushSample(30_000, ip, 'POST', '/login', 200, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', {
      loginResult: 'ok',
      userId: uid,
      requestSize: 185,
    });
    pushSample(20_000, ip, 'GET', `/orders/${100 + idx}`, 200, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', {
      userId: uid,
    });
    pushSample(12_000, ip, 'POST', '/orders', 201, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', {
      userId: uid,
      requestSize: 390,
    });
  });

  // Brute force attack samples
  const bruteIp = '198.51.100.201';
  for (let i = 0; i < 6; i++) {
    pushSample(40_000 - i * 4000, bruteIp, 'POST', '/login', 401, 'Hydra/9.5', {
      loginResult: 'fail',
      requestSize: 140,
      userId: 'target_admin',
    });
  }

  // SQL injection attack samples
  const sqliIp = '198.51.100.202';
  for (let i = 0; i < 4; i++) {
    pushSample(35_000 - i * 5000, sqliIp, 'GET', "/products?category=audio' UNION SELECT username,password FROM users--", 400, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', {
      requestSize: 95,
    });
  }

  // Catalog scraping samples
  const scrapeIp = '198.51.100.203';
  for (let i = 1; i <= 14; i++) {
    pushSample(32_000 - i * 1500, scrapeIp, 'GET', `/products/${i}`, 200, 'Scrapy/2.8.0');
  }

  // IDOR / BOLA enumeration samples
  const idorIp = '203.0.113.204';
  for (let i = 301; i <= 307; i++) {
    pushSample(28_000 - (i - 301) * 2000, idorIp, 'GET', `/orders/${i}`, 200, 'Mozilla/5.0 (X11; Linux x86_64)', {
      userId: 'attacker_acct_1',
    });
  }

  // Scanner and bad bot samples
  const botIp1 = '203.0.113.205';
  for (let i = 0; i < 4; i++) {
    pushSample(25_000 - i * 3000, botIp1, 'GET', `/products/${i + 1}`, 200, 'sqlmap/1.7.2#stable');
  }
  const botIp2 = '203.0.113.206';
  for (let i = 0; i < 3; i++) {
    pushSample(22_000 - i * 3000, botIp2, 'GET', '/products', 200, '');
  }

  appsService.recordAppTraffic(appId, totalEvents);

  // Compute feature rows for 1m, 5m, and 1h windows
  const extractedRows = featureService.extractAndSaveNow(nowMs, false);

  res.json({
    success: true,
    events_generated: totalEvents,
    feature_rows_created: extractedRows.length,
    message: `Generated ${totalEvents} mixed normal & attack events and extracted ${extractedRows.length} labeled feature rows.`,
  });
});
