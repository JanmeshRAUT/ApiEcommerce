import express, { Request, Response } from 'express';
import { calculateDashboardStats } from './statsService.js';
import { authenticateAdminWithRateLimit, verifySessionToken, revokeSessionToken } from './authService.js';
import { config, isWeakAdminPassword } from './config.js';

export const statsRouter = express.Router();
export const authRouter = express.Router();

// GET /api/stats - Telemetry metrics endpoint
statsRouter.get('/', (req: Request, res: Response) => {
  const appId = req.query.app_id as string | undefined;
  const stats = calculateDashboardStats(appId);
  res.json(stats);
});

// Auth routes: Login, verify, and logout
authRouter.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body || {};
  const clientIp =
    ((req.headers['x-forwarded-for'] as string)?.split(',')[0].trim()) ||
    req.ip ||
    req.socket?.remoteAddress ||
    '127.0.0.1';

  const result = authenticateAdminWithRateLimit(username, password, clientIp);

  if (result.blocked) {
    res.status(429).json({
      success: false,
      blocked: true,
      retry_after_seconds: result.retryAfterSeconds,
      error: `Too many failed login attempts. This IP is blocked for 15 minutes (${Math.ceil((result.retryAfterSeconds || 900) / 60)}m remaining).`,
    });
    return;
  }

  if (!result.success || !result.token) {
    res.status(401).json({
      success: false,
      remaining_attempts: result.remainingAttempts,
      error: `Invalid username or password (${result.remainingAttempts} attempts remaining before 15m IP block).`,
    });
    return;
  }

  res.json({
    success: true,
    token: result.token,
    weak_admin_password: isWeakAdminPassword(),
    user: {
      username,
      role: 'admin',
    },
  });
});

authRouter.get('/check', (req: Request, res: Response) => {
  const authHeader = req.headers['authorization'];
  const isValid = verifySessionToken(authHeader);

  res.json({
    authenticated: isValid,
    weak_admin_password: isValid ? isWeakAdminPassword() : false,
    user: isValid ? { username: config.adminUser, role: 'admin' } : null,
  });
});

authRouter.post('/logout', (req: Request, res: Response) => {
  const authHeader = req.headers['authorization'];
  revokeSessionToken(authHeader);
  res.json({ success: true, message: 'Logged out successfully' });
});
