import express, { Request, Response } from 'express';
import { appsService } from './appsService.js';

export const appsRouter = express.Router();

/**
 * GET /api/apps
 * List all registered applications
 */
appsRouter.get('/', (_req: Request, res: Response) => {
  const apps = appsService.listApps();
  res.json({ apps });
});

/**
 * POST /api/apps
 * Register a new application
 * Generates API key, returns plain key ONCE
 */
appsRouter.post('/', (req: Request, res: Response) => {
  const { name, environment } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim()) {
    res.status(400).json({ error: 'Application name is required.' });
    return;
  }

  const env = environment === 'prod' ? 'prod' : 'dev';
  const { app, plainKey } = appsService.registerApp(name.trim(), env);

  res.status(201).json({
    success: true,
    message: 'Application registered successfully.',
    app: { ...app, key_hash: '[SECURED_HASH]' },
    plain_api_key: plainKey, // Returned once upon registration
  });
});

/**
 * POST /api/apps/:id/regenerate-key
 * Regenerate API key for an application
 */
appsRouter.post('/:id/regenerate-key', (req: Request, res: Response) => {
  const id = req.params.id;
  const result = appsService.regenerateKey(id);

  if (!result) {
    res.status(404).json({ error: 'Application not found.' });
    return;
  }

  res.json({
    success: true,
    message: 'New API key generated. Please copy and store it safely.',
    app: { ...result.app, key_hash: '[SECURED_HASH]' },
    plain_api_key: result.plainKey, // Returned once upon regeneration
  });
});

/**
 * POST /api/apps/:id/toggle-status
 * Enable or disable an application
 */
appsRouter.post('/:id/toggle-status', (req: Request, res: Response) => {
  const id = req.params.id;
  const app = appsService.toggleStatus(id);

  if (!app) {
    res.status(404).json({ error: 'Application not found.' });
    return;
  }

  res.json({
    success: true,
    message: `Application is now ${app.status}.`,
    app: { ...app, key_hash: '[SECURED_HASH]' },
  });
});

/**
 * DELETE /api/apps/:id
 * Delete an application
 */
appsRouter.delete('/:id', (req: Request, res: Response) => {
  const id = req.params.id;
  const success = appsService.deleteApp(id);

  if (!success) {
    res.status(404).json({ error: 'Application not found.' });
    return;
  }

  res.json({
    success: true,
    message: 'Application deleted successfully.',
  });
});
