import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { config, isWeakAdminPassword } from './config.js';

interface Session {
  username: string;
  createdAt: number;
}

interface LoginAttemptState {
  failures: number;
  blockedUntil: number | null;
  lastAttemptAt: number;
}

const MAX_FAILED_LOGINS = 5;
const BLOCK_DURATION_MS = 15 * 60 * 1000;

const activeSessions = new Map<string, Session>();
const loginRateLimits = new Map<string, LoginAttemptState>();

export interface LoginAuthResult {
  success: boolean;
  token?: string;
  blocked?: boolean;
  retryAfterSeconds?: number;
  remainingAttempts?: number;
  weakAdminPassword?: boolean;
}

export function authenticateAdmin(username: string, pass: string): string | null {
  if (!username || !pass) return null;

  if (username === config.adminUser && pass === config.adminPass) {
    const token = `sess_${crypto.randomBytes(24).toString('hex')}`;
    activeSessions.set(token, {
      username,
      createdAt: Date.now(),
    });
    return token;
  }

  return null;
}

export function authenticateAdminWithRateLimit(
  username: string,
  pass: string,
  clientIp: string,
  now: number = Date.now()
): LoginAuthResult {
  const ipKey = (clientIp || '127.0.0.1').trim();
  let state = loginRateLimits.get(ipKey);

  if (state?.blockedUntil) {
    if (now < state.blockedUntil) {
      return {
        success: false,
        blocked: true,
        retryAfterSeconds: Math.ceil((state.blockedUntil - now) / 1000),
        remainingAttempts: 0,
      };
    } else {
      state = { failures: 0, blockedUntil: null, lastAttemptAt: now };
      loginRateLimits.set(ipKey, state);
    }
  }

  const token = authenticateAdmin(username, pass);
  if (token) {
    loginRateLimits.delete(ipKey);
    return {
      success: true,
      token,
      weakAdminPassword: isWeakAdminPassword(),
    };
  }

  if (!state) {
    state = { failures: 1, blockedUntil: null, lastAttemptAt: now };
  } else {
    state.failures += 1;
    state.lastAttemptAt = now;
  }

  if (state.failures >= MAX_FAILED_LOGINS) {
    state.blockedUntil = now + BLOCK_DURATION_MS;
    loginRateLimits.set(ipKey, state);
    return {
      success: false,
      blocked: true,
      retryAfterSeconds: Math.ceil(BLOCK_DURATION_MS / 1000),
      remainingAttempts: 0,
    };
  }

  loginRateLimits.set(ipKey, state);
  return {
    success: false,
    blocked: false,
    remainingAttempts: MAX_FAILED_LOGINS - state.failures,
  };
}

export function clearLoginRateLimitsForTesting(): void {
  loginRateLimits.clear();
}

export function verifySessionToken(token: string | undefined): boolean {
  if (!token) return false;
  const cleanToken = token.replace(/^Bearer\s+/i, '').trim();
  const session = activeSessions.get(cleanToken);
  if (!session) return false;

  // Session valid for 24 hours
  const isExpired = Date.now() - session.createdAt > 24 * 60 * 60 * 1000;
  if (isExpired) {
    activeSessions.delete(cleanToken);
    return false;
  }

  return true;
}

export function revokeSessionToken(token: string | undefined): void {
  if (!token) return;
  const cleanToken = token.replace(/^Bearer\s+/i, '').trim();
  activeSessions.delete(cleanToken);
}

/**
 * Optional protection middleware for API endpoints
 */
export function requireDashboardAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization'];
  if (!verifySessionToken(authHeader)) {
    res.status(401).json({ error: 'Unauthorized: Admin authentication required.' });
    return;
  }
  next();
}
