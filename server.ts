import express from 'express';
import { createServer as createViteServer } from 'vite';
import { monitorRouter } from './server/monitorApi.js';
import { statsRouter, authRouter } from './server/statsApi.js';
import { ingestRouter } from './server/ingestApi.js';
import { appsRouter } from './server/appsApi.js';
import { appsService } from './server/appsService.js';
import { threatsRouter } from './server/threatsApi.js';
import { exportRouter } from './server/exportApi.js';
import { featureService } from './server/featureService.js';
import { threatEngine } from './server/threatEngine.js';
import { config } from './server/config.js';

async function bootstrap() {
  console.log('[Gatekeeper] Initializing API Security Monitoring Platform...');

  // Background ML feature extraction and retention cleanup
  featureService.startBackgroundJobs(() => {
    const s = threatEngine.getSettings();
    return {
      rawTrafficDays: s.raw_traffic_retention_days ?? 30,
      featureDays: s.feature_retention_days ?? 90,
    };
  });

  const app = express();

  // Ingest API
  app.use('/api/v1/ingest', express.json({ limit: '2mb' }), ingestRouter);

  // ML Feature Export & Training Simulator API
  app.use('/api/v1/export', express.json(), exportRouter);

  // Threats & Rules Management API
  app.use('/api/threats', express.json(), threatsRouter);

  // Applications Management API
  app.use('/api/apps', express.json(), appsRouter);

  // Stats and Auth APIs
  app.use('/api/stats', express.json(), statsRouter);
  app.use('/api/auth', express.json(), authRouter);

  // Monitor API
  app.use('/api/monitor', express.json(), monitorRouter);

  // Vite frontend middleware or static build serving
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (_req, res) => {
      res.sendFile('index.html', { root: 'dist' });
    });
  }

  const appCount = appsService.listApps().length;
  app.listen(config.port, '0.0.0.0', () => {
    console.log(`[Gatekeeper] Ready! Dashboard live at http://0.0.0.0:${config.port}`);
    console.log(`[Gatekeeper] Active Applications: ${appCount} registered`);
  });
}

bootstrap().catch((err) => {
  console.error('[Gatekeeper] Fatal startup error:', err);
  process.exit(1);
});
