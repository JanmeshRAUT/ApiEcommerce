import express, { Request, Response } from 'express';
import crypto from 'crypto';
import { appsService } from './appsService.js';
import { recorder } from './recorder.js';
import { normalizePath, extractQueryParamNames, determineLoginResult } from './normalizer.js';
import { threatEngine } from './threatEngine.js';
import { TrafficRecord, IngestEvent } from './types.js';

export const ingestRouter = express.Router();

/**
 * POST /api/v1/ingest
 * High-performance, non-blocking telemetry ingestion endpoint
 */
ingestRouter.post('/', (req: Request, res: Response) => {
  const rawKey =
    (req.headers['x-api-key'] as string) ||
    (req.headers['authorization'] as string) ||
    (req.query?.api_key as string);

  if (!rawKey) {
    res.status(401).json({
      error: 'Unauthorized: Missing X-API-Key header.',
      code: 'MISSING_API_KEY',
    });
    return;
  }

  const auth = appsService.authenticateKey(rawKey);
  if (!auth.authorized || !auth.app) {
    res.status(401).json({
      error: 'Unauthorized: Invalid or disabled API key.',
      code: 'INVALID_API_KEY',
    });
    return;
  }

  if (auth.rateLimited) {
    res.status(429).json({
      error: 'Too Many Requests: Rate limit exceeded for this API key (1200 req/min).',
      code: 'RATE_LIMIT_EXCEEDED',
    });
    return;
  }

  const body = req.body;
  const rawEvents: IngestEvent[] = Array.isArray(body)
    ? body
    : Array.isArray(body?.events)
    ? body.events
    : body && typeof body === 'object'
    ? [body]
    : [];

  if (rawEvents.length === 0) {
    res.status(400).json({ error: 'Bad Request: Expected array of telemetry events.' });
    return;
  }

  const batch = rawEvents.slice(0, 100);
  const app = auth.app;

  res.status(202).json({
    accepted: true,
    app_id: app.id,
    app_name: app.name,
    count: batch.length,
    timestamp: new Date().toISOString(),
  });

  // Background telemetry ingestion
  setImmediate(() => {
    try {
      appsService.recordAppTraffic(app.id, batch.length);

      const fallbackIp =
        ((req.headers['x-forwarded-for'] as string)?.split(',')[0].trim()) ||
        req.socket?.remoteAddress ||
        '127.0.0.1';

      const fallbackUa = (req.headers['user-agent'] as string) || 'Unknown Client';

      for (const ev of batch) {
        if (!ev || typeof ev !== 'object') continue;

        const fullPath = String(ev.path || '/');
        const pathOnly = fullPath.split('?')[0].split('#')[0] || '/';
        const normalized = normalizePath(pathOnly);
        const queryParamNames = extractQueryParamNames(fullPath);

        const statusCode = Number(ev.status) || 200;
        const responseTimeMs = Math.round((Number(ev.response_time_ms) || 0) * 10) / 10;

        let userIdHash: string | undefined = undefined;
        if (ev.user_id) {
          userIdHash = crypto.createHash('sha256').update(String(ev.user_id)).digest('hex').slice(0, 12);
        }

        const loginResult = ev.login_result || determineLoginResult(normalized, statusCode);

        let isoTimestamp = new Date().toISOString();
        if (ev.timestamp) {
          try {
            const parsed = new Date(ev.timestamp);
            if (!isNaN(parsed.getTime())) {
              isoTimestamp = parsed.toISOString();
            }
          } catch {
          }
        }

        const detection = threatEngine.evaluateDetailed({
          app_id: app.id,
          app_name: app.name,
          client_ip: ev.client_ip ? String(ev.client_ip).trim() : fallbackIp,
          method: (ev.method || 'GET').toUpperCase(),
          raw_path_and_query: fullPath,
          status_code: statusCode,
          response_time_ms: responseTimeMs,
          user_agent: ev.user_agent ? String(ev.user_agent) : fallbackUa,
          user_id: ev.user_id,
          login_result: loginResult,
        });

        const record: TrafficRecord = {
          request_id: `req_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
          app_id: app.id,
          app_name: app.name,
          environment: app.environment,
          timestamp: isoTimestamp,
          client_ip: ev.client_ip ? String(ev.client_ip).trim() : fallbackIp,
          method: (ev.method || 'GET').toUpperCase(),
          path: pathOnly,
          normalized_path: normalized,
          query_param_names: queryParamNames,
          status_code: statusCode,
          response_time_ms: responseTimeMs,
          request_size: Number(ev.request_size) || 0,
          response_size: Number(ev.response_size) || 0,
          user_agent: ev.user_agent ? String(ev.user_agent) : fallbackUa,
          user_id_hash: userIdHash,
          login_result: loginResult,
          threat_rule: detection.ruleName || 'normal',
          threat_rule_id: detection.ruleId || undefined,
          label: detection.label,
          label_source: 'rule',
        };

        recorder.recordAsync(record);
      }
    } catch (err) {
      console.error('[Ingest API] Background processing error:', err);
    }
  });
});
