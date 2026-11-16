import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { alertService } from '../server/alertService.js';
import { threatEngine } from '../server/threatEngine.js';
import { authenticateAdminWithRateLimit, clearLoginRateLimitsForTesting } from '../server/authService.js';
import { config, isWeakAdminPassword } from '../server/config.js';
import { PlatformSettings, ThreatRecord } from '../server/types.js';

function makeThreat(overrides: Partial<ThreatRecord> = {}): ThreatRecord {
  const now = new Date().toISOString();
  return {
    id: overrides.id || `thr_test_${Math.random().toString(36).slice(2, 8)}`,
    app_id: overrides.app_id || 'app_test',
    app_name: overrides.app_name || 'Test Storefront',
    rule_id: overrides.rule_id || 'RULE-06-SQL-INJECTION',
    rule_name: overrides.rule_name || 'SQL Injection Pattern',
    severity: overrides.severity || 'critical',
    client_ip: overrides.client_ip || '198.51.100.42',
    first_seen: now,
    last_seen: now,
    hit_count: overrides.hit_count ?? 1,
    status: 'open',
    evidence: overrides.evidence || 'SQL injection pattern matched in request URI parameters',
    owasp_tag: 'API8:2023 - Security Misconfiguration',
  };
}

function makeSettings(overrides: Partial<PlatformSettings> = {}): PlatformSettings {
  return {
    mode: 'shadow',
    notify_on_high_critical: true,
    alert_webhook_url: overrides.alert_webhook_url ?? '',
    alert_min_severity: overrides.alert_min_severity ?? 'high',
    alert_dedup_minutes: overrides.alert_dedup_minutes ?? 30,
  };
}

test('Step 4 Security Fixes & Alert System Suite', async (t) => {
  const originalSettings = threatEngine.getSettings();
  alertService.clearStateForTesting();
  threatEngine.clearAllStateForTesting();
  clearLoginRateLimitsForTesting();

  t.after(() => {
    alertService.clearStateForTesting();
    threatEngine.clearAllStateForTesting();
    clearLoginRateLimitsForTesting();
    threatEngine.updateSettings({
      mode: originalSettings.mode,
      notify_on_high_critical: originalSettings.notify_on_high_critical,
      alert_webhook_url: originalSettings.alert_webhook_url === config.alertWebhookUrl ? '' : originalSettings.alert_webhook_url,
      alert_min_severity: originalSettings.alert_min_severity,
      alert_dedup_minutes: originalSettings.alert_dedup_minutes,
    });
  });

  await t.test('Severity Filter: respects minimum severity threshold (default high)', () => {
    alertService.clearStateForTesting();
    const settingsHigh = makeSettings({ alert_min_severity: 'high' });

    assert.equal(alertService.meetsSeverityThreshold('low', 'high'), false);
    assert.equal(alertService.meetsSeverityThreshold('medium', 'high'), false);
    assert.equal(alertService.meetsSeverityThreshold('high', 'high'), true);
    assert.equal(alertService.meetsSeverityThreshold('critical', 'high'), true);

    const lowThreat = makeThreat({ severity: 'low', rule_id: 'RULE-09-BAD-BOTS' });
    const medThreat = makeThreat({ severity: 'medium', rule_id: 'RULE-04-SCRAPING' });
    const highThreat = makeThreat({ severity: 'high', rule_id: 'RULE-01-BRUTE-FORCE' });
    const critThreat = makeThreat({ severity: 'critical', rule_id: 'RULE-06-SQL-INJECTION' });

    assert.deepEqual(alertService.shouldAlertForNewThreat(lowThreat, settingsHigh), {
      shouldSend: false,
      reason: 'below_min_severity',
    });
    assert.deepEqual(alertService.shouldAlertForNewThreat(medThreat, settingsHigh), {
      shouldSend: false,
      reason: 'below_min_severity',
    });
    assert.deepEqual(alertService.shouldAlertForNewThreat(highThreat, settingsHigh), {
      shouldSend: true,
    });
    assert.deepEqual(alertService.shouldAlertForNewThreat(critThreat, settingsHigh), {
      shouldSend: true,
    });

    // Stricter threshold: critical only
    const settingsCritical = makeSettings({ alert_min_severity: 'critical' });
    assert.equal(alertService.shouldAlertForNewThreat(highThreat, settingsCritical).shouldSend, false);
    assert.equal(alertService.shouldAlertForNewThreat(critThreat, settingsCritical).shouldSend, true);

    // Permissive threshold: low and above
    const settingsLow = makeSettings({ alert_min_severity: 'low' });
    assert.equal(alertService.shouldAlertForNewThreat(lowThreat, settingsLow).shouldSend, true);
  });

  await t.test('Alert De-duplication: same attacker + same rule alerts once per 30 minutes', () => {
    alertService.clearStateForTesting();
    const settings = makeSettings({ alert_min_severity: 'high', alert_dedup_minutes: 30 });
    const t0 = 1_700_000_000_000;

    const threat1 = makeThreat({
      app_id: 'app_shop',
      client_ip: '203.0.113.55',
      rule_id: 'RULE-06-SQL-INJECTION',
      severity: 'critical',
    });

    // First hit sends alert
    assert.equal(alertService.shouldAlertForNewThreat(threat1, settings, t0).shouldSend, true);
    alertService.markAlertDispatched(threat1, t0);

    // Same attacker + same rule 10 minutes later is deduplicated
    const threatSameWindow = makeThreat({
      app_id: 'app_shop',
      client_ip: '203.0.113.55',
      rule_id: 'RULE-06-SQL-INJECTION',
      severity: 'critical',
    });
    assert.deepEqual(alertService.shouldAlertForNewThreat(threatSameWindow, settings, t0 + 10 * 60 * 1000), {
      shouldSend: false,
      reason: 'deduplicated',
    });

    // Different rule from same attacker is NOT deduplicated
    const threatDiffRule = makeThreat({
      app_id: 'app_shop',
      client_ip: '203.0.113.55',
      rule_id: 'RULE-07-XSS',
      severity: 'high',
    });
    assert.equal(alertService.shouldAlertForNewThreat(threatDiffRule, settings, t0 + 10 * 60 * 1000).shouldSend, true);

    // Different attacker on same rule is NOT deduplicated
    const threatDiffIp = makeThreat({
      app_id: 'app_shop',
      client_ip: '203.0.113.99',
      rule_id: 'RULE-06-SQL-INJECTION',
      severity: 'critical',
    });
    assert.equal(alertService.shouldAlertForNewThreat(threatDiffIp, settings, t0 + 10 * 60 * 1000).shouldSend, true);

    // After 30 minutes expire, same attacker + same rule can alert again
    assert.equal(
      alertService.shouldAlertForNewThreat(threatSameWindow, settings, t0 + 30 * 60 * 1000 + 1).shouldSend,
      true
    );

    // Setting dedup to 0 disables cooldown
    const noDedupSettings = makeSettings({ alert_min_severity: 'high', alert_dedup_minutes: 0 });
    assert.equal(alertService.shouldAlertForNewThreat(threatSameWindow, noDedupSettings, t0 + 1000).shouldSend, true);
  });

  await t.test('100-Hit Milestone: sends one extra alert when threat hits 100 occurrences', async () => {
    alertService.clearStateForTesting();
    threatEngine.clearAllStateForTesting();

    const receivedPayloads: any[] = [];
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        try {
          receivedPayloads.push(JSON.parse(body));
        } catch {
          // ignore
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const port = (server.address() as AddressInfo).port;

    try {
      threatEngine.updateSettings({
        alert_webhook_url: `http://127.0.0.1:${port}/webhook`,
        alert_min_severity: 'high',
        alert_dedup_minutes: 30,
      });

      // Trigger 105 hits of SQL injection from same attacker
      for (let i = 0; i < 105; i++) {
        threatEngine.evaluate({
          app_id: 'milestone_app',
          app_name: 'Milestone Store',
          client_ip: '198.51.100.77',
          method: 'GET',
          raw_path_and_query: "/products?category=audio' UNION SELECT 1,2,3--&secret_token=supersecret123",
          status_code: 200,
          response_time_ms: 4,
          user_agent: 'Mozilla/5.0',
        });
      }

      // Allow setImmediate + fetch callbacks to complete
      await new Promise((r) => setTimeout(r, 250));

      assert.equal(receivedPayloads.length, 2, 'Should send 1 alert for new threat and 1 extra alert at 100 hits');
      assert.equal(receivedPayloads[0].trigger_reason, 'new_threat');
      assert.equal(receivedPayloads[1].trigger_reason, 'milestone_100_hits');
      assert.equal(receivedPayloads[1].hit_count, 100);
      assert.equal(receivedPayloads[1].app_name, 'Milestone Store');
      assert.equal(receivedPayloads[1].client_ip, '198.51.100.77');
      assert.ok(receivedPayloads[1].dashboard_link.includes('?tab=threats&threat_id='));

      // Ensure query values / secrets never appear in alert payloads
      const serialized = JSON.stringify(receivedPayloads);
      assert.equal(serialized.includes('supersecret123'), false);
    } finally {
      server.close();
    }
  });

  await t.test('Webhook Delivery: retries up to 2 times on failure and respects timeout', async () => {
    alertService.clearStateForTesting();
    let callCount = 0;

    // Server fails first 2 requests (500) and succeeds on the 3rd attempt (200)
    const retryServer = http.createServer((_req, res) => {
      callCount++;
      if (callCount < 3) {
        res.writeHead(500);
        res.end('Internal error');
      } else {
        res.writeHead(200);
        res.end('OK');
      }
    });

    await new Promise<void>((resolve) => retryServer.listen(0, '127.0.0.1', () => resolve()));
    const retryPort = (retryServer.address() as AddressInfo).port;

    try {
      const threat = makeThreat();
      const entry = await alertService.deliverWebhookWithRetry(
        `http://127.0.0.1:${retryPort}/hook`,
        threat,
        'new_threat',
        { timeoutMs: 1000, maxRetries: 2, retryDelayMs: 10 }
      );

      assert.equal(entry.status, 'sent');
      assert.equal(entry.attempts, 3);
      assert.equal(callCount, 3);
    } finally {
      retryServer.close();
    }

    // Slow endpoint triggers timeout + 2 retries = 3 failed attempts
    let slowCount = 0;
    const slowServer = http.createServer((_req, res) => {
      slowCount++;
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200);
          res.end('too late');
        }
      }, 250);
    });

    await new Promise<void>((resolve) => slowServer.listen(0, '127.0.0.1', () => resolve()));
    const slowPort = (slowServer.address() as AddressInfo).port;

    try {
      const threat = makeThreat();
      const entry = await alertService.deliverWebhookWithRetry(
        `http://127.0.0.1:${slowPort}/slow`,
        threat,
        'new_threat',
        { timeoutMs: 50, maxRetries: 2, retryDelayMs: 5 }
      );

      assert.equal(entry.status, 'failed');
      assert.equal(entry.attempts, 3);
      assert.equal(slowCount, 3);
      assert.ok(entry.error?.includes('Timeout'));
    } finally {
      slowServer.close();
    }
  });

  await t.test('Security Fixes: login rate limiting (5 fails -> 15 min block) & weak password check', () => {
    clearLoginRateLimitsForTesting();
    const attackerIp = '203.0.113.250';
    const baseTime = 1_700_000_000_000;

    // Attempts 1..4 fail without blocking
    for (let i = 1; i <= 4; i++) {
      const res = authenticateAdminWithRateLimit(config.adminUser, 'wrong_pass', attackerIp, baseTime + i * 1000);
      assert.equal(res.success, false);
      assert.equal(res.blocked, false);
      assert.equal(res.remainingAttempts, 5 - i);
    }

    // Attempt 5 triggers 15 minute block
    const fifth = authenticateAdminWithRateLimit(config.adminUser, 'wrong_pass', attackerIp, baseTime + 5000);
    assert.equal(fifth.success, false);
    assert.equal(fifth.blocked, true);
    assert.equal(fifth.retryAfterSeconds, 15 * 60);

    // Even valid credentials are rejected while IP is blocked
    const blockedValid = authenticateAdminWithRateLimit(
      config.adminUser,
      config.adminPass,
      attackerIp,
      baseTime + 60_000
    );
    assert.equal(blockedValid.success, false);
    assert.equal(blockedValid.blocked, true);

    // After 15 minutes pass, valid login succeeds
    const afterBlock = authenticateAdminWithRateLimit(
      config.adminUser,
      config.adminPass,
      attackerIp,
      baseTime + 5000 + 15 * 60 * 1000 + 1
    );
    assert.equal(afterBlock.success, true);
    assert.ok(afterBlock.token);

    // Weak password detector checks
    assert.equal(isWeakAdminPassword('admin123'), true);
    assert.equal(isWeakAdminPassword('short12'), true);
    assert.equal(isWeakAdminPassword('StrongPass!2026'), false);
  });
});
