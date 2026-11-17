import express, { Request, Response } from 'express';
import { threatEngine } from './threatEngine.js';
import { appsService } from './appsService.js';
import { alertService } from './alertService.js';
import { ThreatStatus } from './types.js';
import { recorder } from './recorder.js';
import { normalizePath, extractQueryParamNames } from './normalizer.js';
import { config } from './config.js';

export const threatsRouter = express.Router();

/**
 * GET /api/threats/alerts/history
 * Retrieve recent webhook alert delivery logs
 */
threatsRouter.get('/alerts/history', (req: Request, res: Response) => {
  const limit = parseInt((req.query.limit as string) || '100', 10);
  const history = alertService.getAlertHistory(limit);
  res.json({ count: history.length, history });
});

/**
 * POST /api/threats/alerts/test
 * Send a safe synthetic test alert to the configured or provided webhook URL
 */
threatsRouter.post('/alerts/test', async (req: Request, res: Response) => {
  const overrideWebhookUrl = req.body?.webhook_url as string | undefined;
  const settings = threatEngine.getSettings();
  const entry = await alertService.sendTestAlert(settings, overrideWebhookUrl);

  res.json({
    success: entry.status === 'sent',
    status: entry.status,
    entry,
    message:
      entry.status === 'sent'
        ? 'Test alert delivered successfully!'
        : `Test alert failed: ${entry.error || 'Unable to reach webhook URL'}`,
  });
});

/**
 * GET /api/threats/rules
 * List all rules from rules.json
 */
threatsRouter.get('/rules', (_req: Request, res: Response) => {
  const rules = threatEngine.getRules();
  res.json({ rules });
});

/**
 * PATCH /api/threats/rules/:id
 * Toggle rule enabled or edit threshold
 */
threatsRouter.patch('/rules/:id', (req: Request, res: Response) => {
  const id = req.params.id;
  const updates = req.body || {};

  const updated = threatEngine.updateRule(id, updates);
  if (!updated) {
    res.status(404).json({ error: 'Threat rule not found.' });
    return;
  }

  res.json({
    success: true,
    message: `Rule ${updated.id} updated successfully.`,
    rule: updated,
  });
});

/**
 * GET /api/threats/settings
 * Read global shadow mode & alert settings
 */
threatsRouter.get('/settings', (_req: Request, res: Response) => {
  const settings = threatEngine.getSettings();
  res.json({
    settings,
    env_webhook_configured: Boolean(config.alertWebhookUrl),
  });
});

/**
 * PATCH /api/threats/settings
 * Update global shadow mode & alert settings
 */
threatsRouter.patch('/settings', (req: Request, res: Response) => {
  const updates = req.body || {};
  const updated = threatEngine.updateSettings(updates);
  res.json({
    success: true,
    message: 'Platform security & alert settings updated.',
    settings: updated,
    env_webhook_configured: Boolean(config.alertWebhookUrl),
  });
});

/**
 * GET /api/threats
 * Retrieve threats with optional filtering
 */
threatsRouter.get('/', (req: Request, res: Response) => {
  const severity = req.query.severity as string | undefined;
  const rule_id = req.query.rule_id as string | undefined;
  const app_id = req.query.app_id as string | undefined;
  const status = req.query.status as string | undefined;

  const threats = threatEngine.getThreats({ severity, rule_id, app_id, status });
  const openSummary = threatEngine.getOpenThreatsSummary(app_id);

  res.json({
    count: threats.length,
    threats,
    open_summary: openSummary,
  });
});

/**
 * PATCH /api/threats/:id/status
 * Update threat status (open, acknowledged, resolved, false_positive)
 */
threatsRouter.patch('/:id/status', (req: Request, res: Response) => {
  const id = req.params.id;
  const { status } = req.body || {};

  const validStatuses: ThreatStatus[] = ['open', 'acknowledged', 'resolved', 'false_positive'];
  if (!validStatuses.includes(status)) {
    res.status(400).json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` });
    return;
  }

  const updated = threatEngine.updateThreatStatus(id, status);
  if (!updated) {
    res.status(404).json({ error: 'Threat record not found.' });
    return;
  }

  res.json({
    success: true,
    message: `Threat marked as ${status}.`,
    threat: updated,
  });
});

/**
 * POST /api/threats/simulate-attack
 * Attack Simulator: Dispatches targeted payloads to trigger:
 * 1. Brute Force Login (RULE-01-BRUTE-FORCE)
 * 2. SQL Injection (RULE-06-SQL-INJECTION)
 * 3. Product Catalog Scraping (RULE-04-SCRAPING)
 * 4. Fake Signups (RULE-12-FAKE-SIGNUPS)
 * 5. Path Traversal & Command Injection (RULE-08-PATH-TRAVERSAL)
 */
threatsRouter.post('/simulate-attack', async (req: Request, res: Response) => {
  const requestedAppId = req.body?.app_id as string | undefined;
  const targetApp = requestedAppId
    ? appsService.getAppById(requestedAppId)
    : appsService.getFirstActiveApp()?.app || null;
  if (!targetApp) {
    res.status(400).json({ error: 'Register an application before using the attack simulator.' });
    return;
  }
  const targetAppId = targetApp.id;
  const targetAppName = targetApp.name;

  const firedRules: string[] = [];

  const recordEvent = (
    method: string,
    rawPathAndQuery: string,
    clientIp: string,
    statusCode: number,
    userAgent: string,
    loginResult: 'ok' | 'fail' | 'none' = 'none',
    userId?: string
  ) => {
    const detection = threatEngine.evaluateDetailed({
      app_id: targetAppId,
      app_name: targetAppName,
      client_ip: clientIp,
      method,
      raw_path_and_query: rawPathAndQuery,
      status_code: statusCode,
      response_time_ms: Math.floor(Math.random() * 20) + 5,
      user_agent: userAgent,
      login_result: loginResult,
      user_id: userId,
    });

    if (detection.ruleName && !firedRules.includes(detection.ruleName)) {
      firedRules.push(detection.ruleName);
    }

    const cleanPath = rawPathAndQuery.split('?')[0] || rawPathAndQuery;
    recorder.recordAsync({
      request_id: `atk_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      app_id: targetAppId,
      app_name: targetAppName,
      environment: 'prod',
      timestamp: new Date().toISOString(),
      client_ip: clientIp,
      method,
      path: cleanPath,
      normalized_path: normalizePath(cleanPath),
      query_param_names: extractQueryParamNames(rawPathAndQuery),
      status_code: statusCode,
      response_time_ms: Math.floor(Math.random() * 25) + 6,
      request_size: 140,
      response_size: 320,
      user_agent: userAgent,
      login_result: loginResult,
      is_synthetic: true,
      threat_rule: detection.ruleName || 'normal',
      threat_rule_id: detection.ruleId || undefined,
      label: detection.label,
      label_source: 'rule',
    });
  };

  // Brute force login attack simulation
  const bruteIp = '198.51.100.81';
  for (let i = 0; i < 6; i++) {
    recordEvent('POST', '/login', bruteIp, 401, 'Hydra/9.5 (https://github.com/vanhauser-thc/thc-hydra)', 'fail');
  }

  // SQL injection attack simulation
  recordEvent(
    'GET',
    "/products?search=shoes' UNION SELECT 1,username,password FROM users--",
    '198.51.100.42',
    200,
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
  );

  // Catalog scraping attack simulation
  const scrapeIp = '198.51.100.99';
  for (let i = 1; i <= 14; i++) {
    recordEvent('GET', `/products/${i}`, scrapeIp, 200, 'Scrapy/2.8.0 (+https://scrapy.org)');
  }

  // Fake signups attack simulation
  const spamIp = '203.0.113.55';
  for (let i = 1; i <= 4; i++) {
    recordEvent('POST', '/register', spamIp, 201, 'Python-requests/2.28.1');
  }

  // Path traversal attack simulation
  recordEvent(
    'GET',
    '/orders/../../../../etc/passwd',
    '203.0.113.72',
    400,
    'Mozilla/5.0 (X11; Linux x86_64)'
  );

  res.json({
    success: true,
    message: `Attack simulation executed against ${targetAppName}.`,
    rules_fired_count: firedRules.length,
    fired_rules: firedRules,
    open_threats_summary: threatEngine.getOpenThreatsSummary(targetAppId),
  });
});
