import test from 'node:test';
import assert from 'node:assert/strict';
import { threatEngine } from '../server/threatEngine.js';

test('Security Threat Detection Rules Suite (13 Rules)', async (t) => {
  // Clear any existing state and sliding window counters
  threatEngine.clearAllStateForTesting();

  await t.test('RULE-01-BRUTE-FORCE: should trigger on 5 failed logins from single IP', () => {
    const ip = '192.0.2.101';
    let fired: string | null = null;

    for (let i = 0; i < 5; i++) {
      fired = threatEngine.evaluate({
        app_id: 'test_app',
        app_name: 'Test App',
        client_ip: ip,
        method: 'POST',
        raw_path_and_query: '/login',
        status_code: 401,
        response_time_ms: 5,
        user_agent: 'Mozilla/5.0',
        login_result: 'fail',
      });
    }

    assert.equal(fired, 'Brute Force Login');
  });

  await t.test('RULE-02-CRED-STUFFING: should trigger on failed logins across 3 distinct users', () => {
    const ip = '192.0.2.102';
    let fired: string | null = null;

    ['user_a', 'user_b', 'user_c'].forEach((uid) => {
      fired = threatEngine.evaluate({
        app_id: 'test_app',
        app_name: 'Test App',
        client_ip: ip,
        method: 'POST',
        raw_path_and_query: '/login',
        status_code: 401,
        response_time_ms: 6,
        user_agent: 'Mozilla/5.0',
        login_result: 'fail',
        user_id: uid,
      });
    });

    assert.equal(fired, 'Credential Stuffing');
  });

  await t.test('RULE-03-RATE-LIMIT: should trigger on high request volume from single IP', () => {
    const ip = '192.0.2.103';
    let fired: string | null = null;

    for (let i = 0; i < 60; i++) {
      fired = threatEngine.evaluate({
        app_id: 'test_app',
        app_name: 'Test App',
        client_ip: ip,
        method: 'GET',
        raw_path_and_query: '/api/items',
        status_code: 200,
        response_time_ms: 2,
        user_agent: 'Mozilla/5.0',
      });
    }

    assert.equal(fired, 'Rate Limit Exceeded');
  });

  await t.test('RULE-04-SCRAPING: should trigger on rapid product catalog scanning', () => {
    const ip = '192.0.2.104';
    let fired: string | null = null;

    for (let i = 1; i <= 12; i++) {
      fired = threatEngine.evaluate({
        app_id: 'test_app',
        app_name: 'Test App',
        client_ip: ip,
        method: 'GET',
        raw_path_and_query: `/products/${i}`,
        status_code: 200,
        response_time_ms: 3,
        user_agent: 'CustomScraper/1.0',
      });
    }

    assert.equal(fired, 'E-Commerce Scraping');
  });

  await t.test('RULE-05-IDOR-BOLA: should trigger on iterating over multiple order IDs', () => {
    const ip = '192.0.2.105';
    let fired: string | null = null;

    for (let i = 201; i <= 206; i++) {
      fired = threatEngine.evaluate({
        app_id: 'test_app',
        app_name: 'Test App',
        client_ip: ip,
        method: 'GET',
        raw_path_and_query: `/orders/${i}`,
        status_code: 200,
        response_time_ms: 4,
        user_agent: 'Mozilla/5.0',
      });
    }

    assert.equal(fired, 'IDOR / BOLA Enumeration');
  });

  await t.test('RULE-06-SQL-INJECTION: should detect SQL injection keywords in path or query', () => {
    const fired = threatEngine.evaluate({
      app_id: 'test_app',
      app_name: 'Test App',
      client_ip: '192.0.2.106',
      method: 'GET',
      raw_path_and_query: "/products?category=audio' UNION SELECT 1,2,3--",
      status_code: 200,
      response_time_ms: 5,
      user_agent: 'Mozilla/5.0',
    });

    assert.equal(fired, 'SQL Injection Pattern');
  });

  await t.test('RULE-07-XSS: should detect Cross-Site Scripting payloads in query', () => {
    const fired = threatEngine.evaluate({
      app_id: 'test_app',
      app_name: 'Test App',
      client_ip: '192.0.2.107',
      method: 'GET',
      raw_path_and_query: '/search?q=<script>alert(document.cookie)</script>',
      status_code: 200,
      response_time_ms: 4,
      user_agent: 'Mozilla/5.0',
    });

    assert.equal(fired, 'Cross-Site Scripting (XSS)');
  });

  await t.test('RULE-08-PATH-TRAVERSAL: should detect directory traversal or command tokens', () => {
    const fired = threatEngine.evaluate({
      app_id: 'test_app',
      app_name: 'Test App',
      client_ip: '192.0.2.108',
      method: 'GET',
      raw_path_and_query: '/files/download?file=../../../../etc/passwd',
      status_code: 400,
      response_time_ms: 3,
      user_agent: 'Mozilla/5.0',
    });

    assert.equal(fired, 'Path Traversal & Command Injection');
  });

  await t.test('RULE-09-BAD-BOTS: should detect scanner user agent and empty UA', () => {
    const scannerFired = threatEngine.evaluate({
      app_id: 'test_app',
      app_name: 'Test App',
      client_ip: '192.0.2.109',
      method: 'GET',
      raw_path_and_query: '/products',
      status_code: 200,
      response_time_ms: 2,
      user_agent: 'sqlmap/1.6.4#stable',
    });

    assert.equal(scannerFired, 'Malicious Scanner / Empty Bot');

    const emptyUaFired = threatEngine.evaluate({
      app_id: 'test_app',
      app_name: 'Test App',
      client_ip: '192.0.2.110',
      method: 'GET',
      raw_path_and_query: '/products',
      status_code: 200,
      response_time_ms: 2,
      user_agent: '',
    });

    assert.equal(emptyUaFired, 'Malicious Scanner / Empty Bot');
  });

  await t.test('RULE-10-ADMIN-ACCESS: should detect sensitive administrative file access', () => {
    const fired = threatEngine.evaluate({
      app_id: 'test_app',
      app_name: 'Test App',
      client_ip: '192.0.2.111',
      method: 'GET',
      raw_path_and_query: '/.env',
      status_code: 404,
      response_time_ms: 2,
      user_agent: 'Mozilla/5.0',
    });

    assert.equal(fired, 'Sensitive Admin Endpoint Probe');
  });

  await t.test('RULE-11-ERROR-SPIKE: should trigger on 8+ errors within 1 minute', () => {
    let fired: string | null = null;

    for (let i = 0; i < 8; i++) {
      fired = threatEngine.evaluate({
        app_id: 'error_spike_app',
        app_name: 'Spike App',
        client_ip: `192.0.2.${120 + i}`,
        method: 'GET',
        raw_path_and_query: '/bad-route',
        status_code: 500,
        response_time_ms: 4,
        user_agent: 'Mozilla/5.0',
      });
    }

    assert.equal(fired, 'Application Error Spike');
  });

  await t.test('RULE-12-FAKE-SIGNUPS: should trigger on 4 registration attempts from single IP', () => {
    const ip = '192.0.2.125';
    let fired: string | null = null;

    for (let i = 0; i < 4; i++) {
      fired = threatEngine.evaluate({
        app_id: 'test_app',
        app_name: 'Test App',
        client_ip: ip,
        method: 'POST',
        raw_path_and_query: '/register',
        status_code: 201,
        response_time_ms: 15,
        user_agent: 'Mozilla/5.0',
      });
    }

    assert.equal(fired, 'Spam Account Registration');
  });

  await t.test('RULE-13-COUPON-ABUSE: should trigger on 5 promo validation attempts from single IP', () => {
    threatEngine.clearAllStateForTesting();
    const ip = '192.0.2.126';
    let fired: string | null = null;

    for (let i = 0; i < 5; i++) {
      fired = threatEngine.evaluate({
        app_id: 'test_app',
        app_name: 'Test App',
        client_ip: ip,
        method: 'POST',
        raw_path_and_query: '/coupon/apply',
        status_code: 400,
        response_time_ms: 8,
        user_agent: 'Mozilla/5.0',
      });
    }

    assert.equal(fired, 'Promo / Coupon Brute-Forcing');
  });

  await t.test('BENIGN TRAFFIC: should not trigger threats for standard browsing', () => {
    const fired = threatEngine.evaluate({
      app_id: 'test_app',
      app_name: 'Test App',
      client_ip: '192.0.2.200',
      method: 'GET',
      raw_path_and_query: '/products?category=audio&sort=price_asc',
      status_code: 200,
      response_time_ms: 3,
      user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    });

    assert.equal(fired, null);
  });
});
