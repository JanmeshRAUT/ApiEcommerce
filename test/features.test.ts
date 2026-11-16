import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { featureService } from '../server/featureService.js';
import { recorder } from '../server/recorder.js';
import { threatEngine } from '../server/threatEngine.js';
import { hashClientIp } from '../server/config.js';
import { TrafficRecord } from '../server/types.js';

function makeRecord(overrides: Partial<TrafficRecord> = {}): TrafficRecord {
  return {
    request_id: overrides.request_id || `req_${Math.random().toString(36).slice(2, 8)}`,
    app_id: overrides.app_id || 'app_ml_test',
    app_name: overrides.app_name || 'ML Test App',
    environment: 'dev',
    timestamp: overrides.timestamp || new Date().toISOString(),
    client_ip: overrides.client_ip || '198.51.100.10',
    method: overrides.method || 'GET',
    path: overrides.path || '/products',
    normalized_path: overrides.normalized_path || '/products',
    query_param_names: overrides.query_param_names || [],
    status_code: overrides.status_code ?? 200,
    response_time_ms: overrides.response_time_ms ?? 10,
    request_size: overrides.request_size ?? 0,
    response_size: overrides.response_size ?? 200,
    user_agent: overrides.user_agent || 'Mozilla/5.0',
    user_id_hash: overrides.user_id_hash,
    login_result: overrides.login_result || 'none',
    threat_rule: overrides.threat_rule || 'normal',
    threat_rule_id: overrides.threat_rule_id,
    label: overrides.label || 'normal',
    label_source: overrides.label_source || 'rule',
  };
}

test('Step 5 ML Labels, Features, Retention & Export Suite', async (t) => {
  const originalSettings = threatEngine.getSettings();
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatekeeper-ml-test-'));

  t.after(() => {
    threatEngine.clearAllStateForTesting();
    threatEngine.updateSettings(originalSettings);
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  await t.test('Feature Calculation: computes all 13 metadata features, windows, night ratio, and IP hashing', () => {
    // Fixed base timestamp at 02:00:00 UTC (inside night_time_ratio window 00:00-05:00)
    const nightBaseMs = Date.parse('2026-11-13T02:00:00.000Z');
    const dayOffsetMs = 12 * 60 * 60 * 1000; // 14:00 UTC

    const records: TrafficRecord[] = [
      makeRecord({
        timestamp: new Date(nightBaseMs).toISOString(),
        method: 'GET',
        normalized_path: '/products',
        status_code: 200,
        response_time_ms: 10,
        request_size: 0,
        user_id_hash: 'uid_hash_1',
        user_agent: 'Chrome/120',
        login_result: 'none',
      }),
      makeRecord({
        timestamp: new Date(nightBaseMs + 1000).toISOString(),
        method: 'POST',
        normalized_path: '/login',
        status_code: 401,
        response_time_ms: 20,
        request_size: 120,
        user_id_hash: 'uid_hash_1',
        user_agent: 'Chrome/120',
        login_result: 'fail',
      }),
      makeRecord({
        timestamp: new Date(nightBaseMs + 4000).toISOString(),
        method: 'GET',
        normalized_path: '/orders/{id}',
        status_code: 500,
        response_time_ms: 30,
        request_size: 50,
        user_id_hash: 'uid_hash_2',
        user_agent: 'Firefox/115',
        login_result: 'none',
      }),
      makeRecord({
        timestamp: new Date(nightBaseMs + 7000).toISOString(),
        method: 'POST',
        normalized_path: '/orders',
        status_code: 201,
        response_time_ms: 40,
        request_size: 300,
        user_id_hash: 'uid_hash_2',
        user_agent: 'Firefox/115',
        login_result: 'none',
      }),
    ];

    const row = featureService.computeFeatureRow(records, {
      appId: 'app_ml_test',
      appName: 'ML Test App',
      clientIp: '198.51.100.10',
      windowSize: '1m',
      windowEndMs: nightBaseMs + 10_000,
      hashIps: false,
    });

    assert.equal(row.request_count, 4);
    assert.equal(row.error_rate_4xx, 0.25);
    assert.equal(row.error_rate_5xx, 0.25);
    assert.equal(row.unique_endpoints, 4);
    assert.equal(row.unique_user_ids, 2);
    assert.equal(row.failed_logins, 1);
    assert.equal(row.avg_gap_between_requests_ms, 2333.33);
    assert.equal(row.avg_response_time_ms, 25);
    assert.equal(row.avg_request_size, 117.5);
    assert.equal(row.max_request_size, 300);
    assert.equal(row.post_ratio, 0.5);
    assert.equal(row.night_time_ratio, 1);
    assert.equal(row.unique_user_agents, 2);
    assert.equal(row.label, 'normal');
    assert.equal(row.label_source, 'rule');
    assert.equal(row.client_ip, '198.51.100.10');

    // Mixed day & night timestamps -> night_time_ratio = 0.5
    const mixedRecords = [
      makeRecord({ timestamp: new Date(nightBaseMs).toISOString() }),
      makeRecord({ timestamp: new Date(nightBaseMs + dayOffsetMs).toISOString() }),
    ];
    const mixedRow = featureService.computeFeatureRow(mixedRecords, {
      appId: 'app_ml_test',
      appName: 'ML Test App',
      clientIp: '198.51.100.10',
      windowSize: '5m',
      windowEndMs: nightBaseMs + dayOffsetMs + 1000,
      hashIps: true,
      salt: 'unit_test_secret_salt',
    });
    assert.equal(mixedRow.night_time_ratio, 0.5);
    assert.ok(mixedRow.client_ip.startsWith('ip_'));
    assert.notEqual(mixedRow.client_ip, '198.51.100.10');
    assert.equal(mixedRow.client_ip, hashClientIp('198.51.100.10', true, 'unit_test_secret_salt'));

    // Multi-window extraction (1m, 5m, 1h)
    const nowMs = Date.parse('2026-11-13T12:00:00.000Z');
    const windowRecords: TrafficRecord[] = [
      makeRecord({ timestamp: new Date(nowMs - 20_000).toISOString() }), // in 1m, 5m, 1h
      makeRecord({ timestamp: new Date(nowMs - 180_000).toISOString() }), // in 5m, 1h
      makeRecord({ timestamp: new Date(nowMs - 1_800_000).toISOString() }), // in 1h only
    ];
    const extracted = featureService.extractWindowFeatures(windowRecords, nowMs, { hashIps: false });
    const w1m = extracted.find((r) => r.window_size === '1m');
    const w5m = extracted.find((r) => r.window_size === '5m');
    const w1h = extracted.find((r) => r.window_size === '1h');
    assert.equal(w1m?.request_count, 1);
    assert.equal(w5m?.request_count, 2);
    assert.equal(w1h?.request_count, 3);
  });

  await t.test('Label Correction: marking threat as false_positive reverts request & feature labels to normal with label_source=human', () => {
    threatEngine.clearAllStateForTesting();
    const attackerIp = '203.0.113.188';
    const appId = 'app_fp_test';

    const detection = threatEngine.evaluateDetailed({
      app_id: appId,
      app_name: 'False Positive Store',
      client_ip: attackerIp,
      method: 'GET',
      raw_path_and_query: "/products?search=shoes' UNION SELECT 1,2,3--",
      status_code: 200,
      response_time_ms: 8,
      user_agent: 'Mozilla/5.0',
    });

    assert.equal(detection.label, 'sqli_suspected');
    assert.equal(detection.ruleId, 'RULE-06-SQL-INJECTION');

    const reqId = `req_fp_${Date.now()}`;
    const ts = new Date().toISOString();
    recorder.recordSync(
      makeRecord({
        request_id: reqId,
        app_id: appId,
        app_name: 'False Positive Store',
        client_ip: attackerIp,
        timestamp: ts,
        threat_rule: detection.ruleName || 'normal',
        threat_rule_id: detection.ruleId || undefined,
        label: detection.label,
        label_source: 'rule',
      }),
      false
    );

    // Write matching feature row to isolated temp features.jsonl
    const tempFeaturesFile = path.join(tempDir, 'fp_features.jsonl');
    const preRecords = recorder.getAllRecords().filter((r) => r.app_id === appId && r.client_ip === attackerIp);
    const featRow = featureService.computeFeatureRow(preRecords, {
      appId,
      appName: 'False Positive Store',
      clientIp: attackerIp,
      windowSize: '1m',
      windowEndMs: Date.now() + 1000,
      hashIps: false,
    });
    assert.equal(featRow.label, 'sqli_suspected');
    assert.equal(featRow.label_source, 'rule');
    featureService.appendFeatures([featRow], tempFeaturesFile);

    // Find created threat & mark false_positive
    const threats = threatEngine.getThreats({ app_id: appId });
    assert.equal(threats.length, 1);
    const updatedThreat = threatEngine.updateThreatStatus(threats[0].id, 'false_positive');
    assert.equal(updatedThreat?.status, 'false_positive');

    // Verify stored request in recorder reverted to normal + human
    const storedReq = recorder.getAllRecords().find((r) => r.request_id === reqId);
    assert.equal(storedReq?.label, 'normal');
    assert.equal(storedReq?.label_source, 'human');
    assert.equal(storedReq?.threat_rule, 'normal');

    // Verify feature correction against isolated tempFeaturesFile
    const correctedFeatCount = featureService.applyFalsePositiveCorrection(
      {
        app_id: appId,
        client_ip: attackerIp,
        rule_id: threats[0].rule_id,
        rule_name: threats[0].rule_name,
      },
      tempFeaturesFile
    );
    assert.equal(correctedFeatCount, 1);

    const correctedRows = featureService.loadFeatures(undefined, tempFeaturesFile);
    assert.equal(correctedRows.length, 1);
    assert.equal(correctedRows[0].label, 'normal');
    assert.equal(correctedRows[0].label_source, 'human');

    // Also re-computing features from corrected raw records produces normal + human
    const recomputedRow = featureService.computeFeatureRow([storedReq!], {
      appId,
      appName: 'False Positive Store',
      clientIp: attackerIp,
      windowSize: '1m',
      windowEndMs: Date.now() + 1000,
      hashIps: false,
    });
    assert.equal(recomputedRow.label, 'normal');
    assert.equal(recomputedRow.label_source, 'human');
  });

  await t.test('Retention Clean-up: removes expired raw traffic (>30d) and feature rows (>90d)', () => {
    const tempTrafficFile = path.join(tempDir, 'retention_traffic.jsonl');
    const tempFeaturesFile = path.join(tempDir, 'retention_features.jsonl');
    const nowMs = Date.parse('2026-11-13T12:00:00.000Z');
    const dayMs = 24 * 60 * 60 * 1000;

    // Raw traffic: 1 old (45 days) + 1 fresh (5 days)
    const oldRaw = makeRecord({
      request_id: 'raw_old',
      timestamp: new Date(nowMs - 45 * dayMs).toISOString(),
    });
    const freshRaw = makeRecord({
      request_id: 'raw_fresh',
      timestamp: new Date(nowMs - 5 * dayMs).toISOString(),
    });
    fs.writeFileSync(
      tempTrafficFile,
      JSON.stringify(oldRaw) + '\n' + JSON.stringify(freshRaw) + '\n',
      'utf8'
    );

    // Features: 1 old (120 days) + 1 fresh (10 days)
    const oldFeature = featureService.computeFeatureRow([oldRaw], {
      appId: 'app_ret',
      appName: 'Retention App',
      clientIp: '192.0.2.1',
      windowSize: '1h',
      windowEndMs: nowMs - 120 * dayMs,
      hashIps: false,
    });
    const freshFeature = featureService.computeFeatureRow([freshRaw], {
      appId: 'app_ret',
      appName: 'Retention App',
      clientIp: '192.0.2.1',
      windowSize: '1h',
      windowEndMs: nowMs - 10 * dayMs,
      hashIps: false,
    });
    featureService.appendFeatures([oldFeature, freshFeature], tempFeaturesFile);

    const cleanupRes = featureService.runRetentionCleanup(
      30,
      90,
      nowMs,
      tempFeaturesFile,
      tempTrafficFile
    );

    assert.equal(cleanupRes.raw_removed, 1);
    assert.equal(cleanupRes.features_removed, 1);
    assert.equal(cleanupRes.features_kept, 1);

    const remainingTraffic = fs
      .readFileSync(tempTrafficFile, 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as TrafficRecord);
    assert.equal(remainingTraffic.length, 1);
    assert.equal(remainingTraffic[0].request_id, 'raw_fresh');

    const remainingFeatures = featureService.loadFeatures(undefined, tempFeaturesFile);
    assert.equal(remainingFeatures.length, 1);
    assert.equal(remainingFeatures[0].feature_id, freshFeature.feature_id);
  });

  await t.test('Export Preview & CSV: detects class imbalance warning (99% normal) and formats valid CSV', () => {
    const baseMs = Date.now();
    const rows = Array.from({ length: 100 }, (_, idx) =>
      featureService.computeFeatureRow(
        [
          makeRecord({
            label: idx === 0 ? 'sqli_suspected' : 'normal',
            label_source: 'rule',
          }),
        ],
        {
          appId: 'app_imb',
          appName: 'Imbalance App',
          clientIp: `192.0.2.${idx + 1}`,
          windowSize: '1m',
          windowEndMs: baseMs,
          hashIps: false,
        }
      )
    );

    const summary = featureService.buildPreviewSummary(rows);
    assert.equal(summary.total_rows, 100);
    assert.equal(summary.preview_rows.length, 20);
    assert.equal(summary.label_counts['normal'], 99);
    assert.equal(summary.label_counts['sqli_suspected'], 1);
    assert.ok(summary.imbalance_warning?.includes('99.0%'));

    const csv = featureService.toCsv(summary.preview_rows);
    const lines = csv.trim().split('\n');
    assert.equal(lines.length, 21); // header + 20 preview rows
    assert.ok(lines[0].includes('request_count,error_rate_4xx,error_rate_5xx'));
    assert.ok(lines[0].includes('night_time_ratio,unique_user_agents,label,label_source'));
  });
});
