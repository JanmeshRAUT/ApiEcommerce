# API Security Monitoring Platform — Central Ingestion & Multi-Tenant Dashboard

## What Is This?

This platform is a **central API Security Monitoring hub**. Many different backend applications (Java, Python, PHP, .NET, Go, Node.js) connect to it over a high-performance **Ingest API** (`POST /api/v1/ingest`).

Instead of relying on a single hardcoded target URL, any backend sends background telemetry batches using its own secure API key.

```
[ Node Express App ]  ──┐
[ Python FastAPI App] ──┼──► POST /api/v1/ingest (Header: X-API-Key)
[ Java Spring Boot ]  ──┤         │
[ PHP Storefront ]    ──┘         ▼
                           Fast 202 Response
                                  │
                                  ▼ Background Ingest
                           ┌───────────────────────────────┐
                           │    Gatekeeper Central Hub     │
                           │  - Path normalization         │
                           │  - Zero secrets/queries saved │
                           │  - In-memory ring buffer      │
                           │  - Append to traffic.jsonl    │
                           └───────────────────────────────┘
                                  │
                                  ▼
                           Multi-Tenant Blue/White Dashboard
                           (App Filter, Recharts, 5s Auto-refresh)
```

---

## 1. Applications & Key Management

- **Register Application**: Choose app name and environment (`dev` or `prod`).
- **One-Time Key Generation**: Generates a random 32+ character key prefixed with `sk_live_` (or `sk_test_`). Shown **only once** upon creation.
- **Hashed Storage**: The platform stores **only the SHA-256 hash** of the key. Plain keys are never stored on disk.
- **Lifecycle Actions**:
  - **Regenerate Key**: Invalidates old key and issues a new one.
  - **Disable / Enable**: Instantly blocks or re-enables traffic from an application.
  - **Delete**: Removes application and its telemetry.

---

## 2. Ingest API (`POST /api/v1/ingest`)

### Endpoint Details
- **URL**: `POST /api/v1/ingest`
- **Header**: `X-API-Key: sk_live_...`
- **Response**: Immediate `202 Accepted` (background processing).
- **Rate Limit**: 1,200 requests/min per API key.

### Batch Event Payload (Array up to 100 events)
```json
[
  {
    "timestamp": "2026-11-07T05:50:00.000Z",
    "method": "GET",
    "path": "/products?category=audio&sort=price_asc",
    "status": 200,
    "response_time_ms": 4.5,
    "request_size": 0,
    "response_size": 280,
    "client_ip": "192.168.1.10",
    "user_agent": "Mozilla/5.0...",
    "user_id": "usr_8492"
  }
]
```

### Safety & Privacy Guarantees
- **Path Normalization**: `/orders/123` $\rightarrow$ `/orders/{id}`, `/products/42` $\rightarrow$ `/products/{id}`.
- **Zero Secrets / Bodies**: Passwords, tokens, credit card numbers, OTPs, and API keys are never stored.
- **Query Parameter Names Only**: `?category=audio&sort=asc` is stored strictly as `["category", "sort"]`. Parameter values are discarded.
- **Hashed User IDs**: If `user_id` is passed, it is hashed with SHA-256.

---

## 3. Real-Time Dashboard (Blue & White)

Access the dashboard at `http://localhost:3000`:
- **App Selector**: Filter analytics across "All Applications" or isolate one specific app.
- **4 Top KPI Cards**: Total requests, error rate percentage (`4xx` and `5xx`), failed logins count, and average response time.
- **Recharts Line Chart**: Throughput and error curves over the last 30 minutes.
- **Recharts Bar Chart**: Top 10 endpoints by volume using normalized paths.
- **Status Breakdown Chart**: Real-time breakdown of `2xx`, `3xx`, `4xx`, and `5xx` responses.
- **Top Client IPs & Slowest Endpoints Tables**: Instant security and bottleneck identification.
- **Live 50-Request Table**: Filterable by Method (`ALL`, `GET`, `POST`), Status Code (`ALL`, `2xx`, `4xx`, `5xx`), and search keywords.
- **5-Second Auto-Refresh**: Seamless live telemetry polling.
- **Admin Authentication**: Login protected via `ADMIN_USER` and `ADMIN_PASS` environment variables (default: `admin` / `admin123`).

---

## 4. Connect Guide (Copy-Paste Snippets)

The dashboard includes a dedicated **Connect Guide** tab with pre-filled snippets for:
1. **Node.js / Express**: Non-blocking middleware with 2s / 50-event background queue and 800ms abort timeout.
2. **Python (FastAPI / Flask)**: Async background task using `httpx`.
3. **Java (Spring Boot)**: `OncePerRequestFilter` with background scheduled executor batching.
4. **PHP**: `fastcgi_finish_request()` and async cURL execution.

All snippets:
- Send events in the background in batches.
- Use a short timeout (<1s).
- Never break or slow down the backend. If the dashboard is down, events are dropped silently.
- Skip `/health` checks and static assets.
- Only send metadata (zero request/response bodies).

---

## 5. How to Test

### In the Web Dashboard
1. Open `http://localhost:3000`.
2. Sign in with `admin` / `admin123`.
3. Click the blue **"Send Test Traffic (20 events)"** button at the top right.
4. Watch the cards, line chart, bar chart, and table update in real time.
5. Switch between **Dashboard**, **Applications**, and **Connect Guide** tabs.

### Testing Ingest via `curl`
```bash
# Send a test telemetry batch using your API key
curl -X POST "http://localhost:3000/api/v1/ingest" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk_live_demo_test" \
  -d '[
    {
      "method": "POST",
      "path": "/login",
      "status": 401,
      "response_time_ms": 7.2,
      "client_ip": "45.132.88.12",
      "login_result": "fail"
    },
    {
      "method": "GET",
      "path": "/orders/101",
      "status": 200,
      "response_time_ms": 3.4,
      "client_ip": "192.168.1.10"
    }
  ]'
```
Response: `202 Accepted` immediately.

---

## 6. Rule-Based Threat Detection (Step 3)

### Shadow Mode
All rules operate in **Shadow Mode** by default. Detection runs asynchronously in the background after the `202 Accepted` response. It never adds latency to ingest and **never blocks user traffic**. You can toggle between **Shadow Mode** and **Alert-Only Mode** in **Settings**.

### 13 E-Commerce Threat Rules (`rules.json`)
Rules are defined in `rules.json` and can be edited or toggled at runtime without code deployment:
1. **RULE-01-BRUTE-FORCE**: Multiple failed logins from a single IP (OWASP API2:2023 - Broken Authentication).
2. **RULE-02-CRED-STUFFING**: Single IP failing logins across multiple distinct user accounts.
3. **RULE-03-RATE-LIMIT**: Request volume exceeding threshold from one IP within a 1-minute window.
4. **RULE-04-SCRAPING**: Rapid consecutive product catalog enumeration (`/products/:id`).
5. **RULE-05-IDOR-BOLA**: Single client probing multiple distinct order IDs (`/orders/:id`).
6. **RULE-06-SQL-INJECTION**: Pattern-based detection of SQL injection keywords in path or query string.
7. **RULE-07-XSS**: Detection of Cross-Site Scripting (`<script>`, `javascript:`, event handlers).
8. **RULE-08-PATH-TRAVERSAL**: Directory traversal (`../`, `%2e%2e`, `/etc/passwd`) and command injection tokens.
9. **RULE-09-BAD-BOTS**: Known scanner user-agents (`sqlmap`, `nikto`, `dirbuster`, `nmap`) or empty User-Agent.
10. **RULE-10-ADMIN-ACCESS**: Sensitive administrative endpoint probes (`/.env`, `/.git`, `/actuator`, `/admin`).
11. **RULE-11-ERROR-SPIKE**: Sudden surge in 4xx/5xx error responses for an application.
12. **RULE-12-FAKE-SIGNUPS**: Rapid repeated account registration attempts (`POST /register`).
13. **RULE-13-COUPON-ABUSE**: Repeated coupon code testing/brute-forcing (`POST /coupon` or `/promo`).

### Threat De-duplication & Safe Storage
- **De-duplication**: Same attacker IP + same rule = **ONE** threat record with an incrementing `hit_count` (e.g. `×6 hits`).
- **Zero Secrets**: Query values, request bodies, and passwords are never stored. Only the rule ID and safe count evidence are saved into `threats.json`.

### Threats Dashboard & Rules Management
- **Threats Page**: Filter by severity (`critical`, `high`, `medium`, `low`), rule, application, and lifecycle status (`open`, `acknowledged`, `resolved`, `false_positive`). Click any threat to inspect and update its status.
- **Rules Page**: View all 13 rules, toggle rules ON/OFF, and edit detection thresholds live.
- **Attack Simulator**: Click the red **"Attack Simulator"** button in the top navigation to fire 5 sample attacks (brute force, SQLi, scraping, fake signups, path traversal) and observe live alerts.
- **Live Toasts**: High and Critical threats trigger pop-up alert toasts in the top-right corner.
- **Live Table Threat Labels**: Requests in the live table are labeled `normal` or with their detected threat rule badge.

### Running Unit Tests
Unit tests covering all 13 threat rules, alert de-duplication, severity filters, webhook retries, and login rate limiting are included:
```bash
npm test
```

---

## 7. Security Fixes & Webhook Alerts (Step 4)

### Security Fixes
- **No Plain Keys Saved to Disk**: Plain API keys (including `_initialPlainKey`) are never saved to `apps.json`. Only SHA-256 hashes are stored. On first server start, the demo app key is printed once in the server console.
- **Default Password Warning**: If `ADMIN_PASS` is `"admin123"` or shorter than 8 characters, a red **"Change the default password"** warning banner appears at the top of the dashboard.
- **Dashboard Login Rate Limiting**: After 5 failed login attempts from the same IP address, that IP is blocked from logging in for 15 minutes (`HTTP 429`).

### Webhook Alerts
- **Settings Page -> Alerts Section**:
  - **Webhook URL**: Paste any Slack, Discord, Telegram, or custom HTTP webhook URL (or set `ALERT_WEBHOOK_URL` in your environment).
  - **Minimum Severity**: Choose the minimum threat level (`low`, `medium`, `high`, or `critical`) that triggers alerts (default: `high`).
  - **De-duplication Window**: Same attacker IP + same rule sends only **1 alert per 30 minutes** (editable). Extra hits only increase the hit counter.
  - **100-Hit Milestone**: Sends **1 extra alert** when an active threat reaches 100 hits.
  - **Send Test Alert**: Click **"Send test alert"** in Settings to test your webhook URL right away.
- **Safe & Non-Blocking**: Alerts run in the background with a 3-second timeout and up to 2 retries. Failures never slow down API ingest or threat detection. No secrets, passwords, query values, or request bodies are ever included in alerts.
- **Alert History Table**: View recent sent and failed alerts (time, threat, and `sent` / `failed` status) at the bottom of the **Threats** page.

---

## 8. ML Training Data, Labels & Retention (Step 5)

### Labels & Human Corrections
- Every stored request has a `label` (such as `"normal"`, `"sqli_suspected"`, `"brute_force"`, `"scraping"`, `"idor_bola"`, or `"bad_bot"`) and a `label_source` (`"rule"` or `"human"`).
- When you mark a threat as **False Positive** on the **Threats** page, its matching requests and feature rows automatically change back to `label: "normal"` with `label_source: "human"`.

### Automated Feature Extraction (Every 1 Minute)
A background job runs every minute and creates one summary row per **application + client IP** for **1-minute (`1m`), 5-minute (`5m`), and 1-hour (`1h`)** windows, saved append-only to `features.jsonl`:
- `request_count`, `error_rate_4xx`, `error_rate_5xx`, `unique_endpoints`, `unique_user_ids`, `failed_logins`, `avg_gap_between_requests_ms`, `avg_response_time_ms`, `avg_request_size`, `max_request_size`, `post_ratio`, `night_time_ratio` (`00:00–05:00 UTC`), `unique_user_agents`, `label`, `label_source`.
- Set `HASH_IPS="true"` and `IP_HASH_SALT="..."` in your environment to hash client IPs in exported features. No request bodies, query values, or secrets are ever stored.

### Retention & Daily Clean-up
- In **Settings -> Data Retention & Daily Clean-up**, configure how many days to keep raw traffic (default `30` days) and ML features (default `90` days).
- A daily background clean-up job automatically deletes expired records. You can also click **"Run cleanup now"**.

### Exporting Training Data (`ML Data` Page)
1. Open the **ML Data** tab in the dashboard.
2. Click **"Generate sample training data"** to send a balanced mix of normal traffic and attacks (`brute_force`, `sqli_suspected`, `scraping`, `idor_bola`, `bad_bot`).
3. Choose application, window size (`1m` / `5m` / `1h`), date range, and preview the first 20 rows, label counts, and class-imbalance warnings.
4. Click **"Export training data"** (or call `GET /api/v1/export/features.csv` with your admin `Authorization: Bearer <token>` header) to download the CSV.


