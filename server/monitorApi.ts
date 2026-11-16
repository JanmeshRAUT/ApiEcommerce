import express, { Request, Response } from 'express';
import fs from 'fs';
import { recorder } from './recorder.js';
import { config } from './config.js';

export const monitorRouter = express.Router();

// GET /api/monitor/records
monitorRouter.get('/records', (req: Request, res: Response) => {
  const limit = parseInt((req.query.limit as string) || '50', 10);
  const method = req.query.method as string | undefined;
  const status = req.query.status as string | undefined;
  const loginResult = req.query.loginResult as string | undefined;
  const search = req.query.search as string | undefined;
  const appId = req.query.app_id as string | undefined;

  const records = recorder.getRecent(limit, { method, status, loginResult, search, appId });
  res.json({
    count: records.length,
    records,
  });
});

// GET /api/monitor/config
monitorRouter.get('/config', (_req: Request, res: Response) => {
  res.json({
    port: config.port,
    trafficLogPath: config.trafficLogPath,
    maxInMemoryRecords: config.maxInMemoryRecords,
  });
});

// POST /api/monitor/clear
monitorRouter.post('/clear', (_req: Request, res: Response) => {
  recorder.clearInMemory();
  res.json({ success: true, message: 'In-memory telemetry buffer cleared.' });
});

// GET /api/monitor/export
monitorRouter.get('/export', (_req: Request, res: Response) => {
  const filePath = recorder.getLogFilePath();
  if (fs.existsSync(filePath)) {
    res.setHeader('Content-Disposition', 'attachment; filename="traffic.jsonl"');
    res.setHeader('Content-Type', 'application/x-jsonlines');
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.status(404).json({ error: 'traffic.jsonl file has not been created yet.' });
  }
});
