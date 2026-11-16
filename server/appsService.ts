import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { RegisteredApp } from './types.js';

const APPS_FILE = path.resolve(process.cwd(), 'apps.json');

class AppsService {
  private apps: Map<string, RegisteredApp> = new Map();
  private rateLimits: Map<string, { count: number; resetAt: number }> = new Map();
  private maxRequestsPerMinute = 1200;

  constructor() {
    this.loadFromDisk();
    this.ensureDemoApp();
  }

  private hashKey(key: string): string {
    return crypto.createHash('sha256').update(key.trim()).digest('hex');
  }

  private loadFromDisk() {
    try {
      if (fs.existsSync(APPS_FILE)) {
        const raw = fs.readFileSync(APPS_FILE, 'utf8');
        const list: any[] = JSON.parse(raw);
        let strippedLegacyPlainKey = false;
        for (const item of list) {
          if ('_initialPlainKey' in item) {
            delete item._initialPlainKey;
            strippedLegacyPlainKey = true;
          }
          this.apps.set(item.id, item as RegisteredApp);
        }
        if (strippedLegacyPlainKey) {
          this.saveToDisk();
        }
      }
    } catch (err) {
      console.warn('[AppsService] Could not load apps.json, starting fresh:', err);
    }
  }

  private saveToDisk() {
    try {
      const list = Array.from(this.apps.values()).map((app) => {
        const sanitized = { ...app } as any;
        delete sanitized._initialPlainKey;
        return sanitized;
      });
      fs.writeFileSync(APPS_FILE, JSON.stringify(list, null, 2), 'utf8');
    } catch (err) {
      console.error('[AppsService] Failed to save apps to apps.json:', err);
    }
  }

  /**
   * Ensures at least one demo app exists on initial launch.
   * Prints the demo API key ONCE in server console on first start only.
   */
  private ensureDemoApp() {
    if (this.apps.size === 0) {
      const demoKey = 'sk_live_demo_' + crypto.randomBytes(24).toString('hex');
      const keyHash = this.hashKey(demoKey);
      const demoApp: RegisteredApp = {
        id: 'app_fakeshop_demo',
        name: 'Fake Shop (Demo)',
        environment: 'dev',
        key_prefix: `${demoKey.slice(0, 14)}...${demoKey.slice(-6)}`,
        key_hash: keyHash,
        status: 'active',
        created_at: new Date().toISOString(),
        last_seen_at: new Date().toISOString(),
        total_requests: 0,
      };
      this.apps.set(demoApp.id, demoApp);
      this.saveToDisk();
      console.log('====================================================================');
      console.log('[AppsService] First start: Created default demo app "Fake Shop (Demo)"');
      console.log(`[AppsService] Demo API Key (shown ONCE): ${demoKey}`);
      console.log('====================================================================');
    }
  }

  /**
   * Generates a secure API key with prefix and random entropy
   */
  public generateApiKey(environment: 'dev' | 'prod' = 'dev'): string {
    const prefix = environment === 'prod' ? 'sk_live_' : 'sk_test_';
    const randomEntropy = crypto.randomBytes(24).toString('hex');
    return `${prefix}${randomEntropy}`;
  }

  /**
   * Register a new application
   * Returns the app object AND the unhashed plain key (to show once)
   */
  public registerApp(name: string, environment: 'dev' | 'prod'): { app: RegisteredApp; plainKey: string } {
    const appId = `app_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const plainKey = this.generateApiKey(environment);
    const keyHash = this.hashKey(plainKey);
    const keyPrefix = `${plainKey.slice(0, 14)}...${plainKey.slice(-6)}`;

    const newApp: RegisteredApp = {
      id: appId,
      name: name.trim(),
      environment,
      key_prefix: keyPrefix,
      key_hash: keyHash,
      status: 'active',
      created_at: new Date().toISOString(),
      last_seen_at: null,
      total_requests: 0,
    };

    this.apps.set(appId, newApp);
    this.saveToDisk();

    return { app: newApp, plainKey };
  }

  /**
   * Regenerate API key for an existing application
   * Returns the new unhashed plain key (to show once)
   */
  public regenerateKey(appId: string): { app: RegisteredApp; plainKey: string } | null {
    const app = this.apps.get(appId);
    if (!app) return null;

    const plainKey = this.generateApiKey(app.environment);
    const keyHash = this.hashKey(plainKey);
    const keyPrefix = `${plainKey.slice(0, 14)}...${plainKey.slice(-6)}`;

    app.key_hash = keyHash;
    app.key_prefix = keyPrefix;
    this.saveToDisk();

    return { app, plainKey };
  }

  /**
   * Toggle status between active and disabled
   */
  public toggleStatus(appId: string): RegisteredApp | null {
    const app = this.apps.get(appId);
    if (!app) return null;

    app.status = app.status === 'active' ? 'disabled' : 'active';
    this.saveToDisk();
    return app;
  }

  /**
   * Delete an application
   */
  public deleteApp(appId: string): boolean {
    const deleted = this.apps.delete(appId);
    if (deleted) {
      this.saveToDisk();
    }
    return deleted;
  }

  /**
   * List all registered applications (without revealing key_hash)
   */
  public listApps(): RegisteredApp[] {
    return Array.from(this.apps.values()).map((app) => ({
      ...app,
      key_hash: '[SECURED_HASH]',
    }));
  }

  public getAppById(appId: string): RegisteredApp | null {
    const app = this.apps.get(appId);
    if (!app) return null;
    return { ...app, key_hash: '[SECURED_HASH]' };
  }

  /**
   * Authenticate incoming request by API key
   */
  public authenticateKey(rawKey: string): { authorized: boolean; app?: RegisteredApp; rateLimited?: boolean } {
    if (!rawKey || typeof rawKey !== 'string') {
      return { authorized: false };
    }

    const cleanKey = rawKey.replace(/^Bearer\s+/i, '').trim();
    const hash = this.hashKey(cleanKey);

    let matchedApp: RegisteredApp | undefined;
    for (const app of this.apps.values()) {
      if (app.key_hash === hash) {
        matchedApp = app;
        break;
      }
    }

    if (!matchedApp || matchedApp.status !== 'active') {
      return { authorized: false };
    }

    // Rate Limiting Check (1,200 req/min per key)
    const now = Date.now();
    let rl = this.rateLimits.get(hash);
    if (!rl || now > rl.resetAt) {
      rl = { count: 1, resetAt: now + 60000 };
      this.rateLimits.set(hash, rl);
    } else {
      rl.count++;
      if (rl.count > this.maxRequestsPerMinute) {
        return { authorized: true, app: matchedApp, rateLimited: true };
      }
    }

    return { authorized: true, app: matchedApp, rateLimited: false };
  }

  /**
   * Record traffic ingestion for an app
   */
  public recordAppTraffic(appId: string, eventCount: number): void {
    const app = this.apps.get(appId);
    if (app) {
      app.total_requests += eventCount;
      app.last_seen_at = new Date().toISOString();
      this.saveToDisk();
    }
  }

  /**
   * Get first active registered application (without exposing key hashes or plain keys)
   */
  public getFirstActiveApp(): { app: RegisteredApp } | null {
    const first = Array.from(this.apps.values()).find((a) => a.status === 'active') || Array.from(this.apps.values())[0];
    if (!first) return null;
    return {
      app: { ...first, key_hash: '[SECURED_HASH]' },
    };
  }
}

export const appsService = new AppsService();
