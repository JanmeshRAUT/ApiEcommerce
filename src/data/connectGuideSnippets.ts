export type GuideLanguage = 'node' | 'python' | 'java' | 'php';

export const snippets = {
    node: `// Node.js Express Middleware (Node 18+; sends metadata in the background)
// Install first: npm install dotenv

import 'dotenv/config';

let eventQueue = [];
let flushTimer = null;

function getGatekeeperUrl() {
  const rawUrl = (process.env.MONITOR_URL || '').replace(/\/+$/, '');
  const normalized = rawUrl.replace('//localhost:', '//127.0.0.1:');
  return \`\${normalized || rawUrl}/api/v1/ingest\`;
}

function flushQueue() {
  if (eventQueue.length === 0) return;
  const apiKey = process.env.MONITOR_API_KEY;
  const monitorUrl = process.env.MONITOR_URL;
  if (!apiKey || !monitorUrl) {
    eventQueue = [];
    return;
  }
  const batch = eventQueue.splice(0, 100);

  // Send in background with short 800ms timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 800);

  fetch(getGatekeeperUrl(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': apiKey,
    },
    body: JSON.stringify(batch),
    signal: controller.signal,
  })
    .then((res) => {
      if (!res.ok) {
        console.warn(\`[security-reporter] Ingest failed: HTTP \${res.status}\`);
      }
    })
    .catch((err) => {
      if (err.name !== 'AbortError') {
        console.warn('[security-reporter] Ingest network error:', err.message || err);
      }
    })
    .finally(() => clearTimeout(timeoutId));
}

// Ingest middleware
export function securityMonitorMiddleware(req, res, next) {
  // Skip health checks and static files
  if (req.path === '/health' || req.path.startsWith('/static')) {
    return next();
  }

  const startTime = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startTime;

    // Queue metadata only (no passwords, query values, or bodies)
    eventQueue.push({
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      status: res.statusCode,
      response_time_ms: duration,
      request_size: Number(req.headers['content-length'] || 0),
      client_ip: req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress,
      user_agent: req.headers['user-agent'] || 'Unknown',
    });

    // Flush batch every 2 seconds or when 50 events are buffered
    if (eventQueue.length >= 50) {
      flushQueue();
    } else if (!flushTimer) {
      flushTimer = setTimeout(() => {
        flushTimer = null;
        flushQueue();
      }, 2000);
    }
  });

  next();
}`,
    python: `# Python FastAPI / Flask Middleware (Async Background Batch)
import time
import asyncio
import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

import os

GATEKEEPER_URL = os.environ["MONITOR_URL"] + "/api/v1/ingest"
API_KEY = os.environ["MONITOR_API_KEY"]

event_queue = []

async def flush_batch():
    global event_queue
    if not event_queue:
        return
    batch, event_queue = event_queue[:100], event_queue[100:]
    try:
        async with httpx.AsyncClient(timeout=0.8) as client:
            await client.post(
                GATEKEEPER_URL,
                headers={"X-API-Key": API_KEY},
                json=batch,
            )
    except Exception:
        pass  # Never break or slow down the application

class SecurityMonitorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip health check & static assets
        if request.url.path in ["/health", "/favicon.ico"]:
            return await call_next(request)

        start_time = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 1)

        event = {
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "response_time_ms": duration_ms,
            "client_ip": request.client.host if request.client else "127.0.0.1",
            "user_agent": request.headers.get("user-agent", "Unknown"),
        }
        event_queue.append(event)

        if len(event_queue) >= 50:
            asyncio.create_task(flush_batch())

        return response`,
    java: `// Java Spring Boot 3 / Spring MVC filter
// File: src/main/java/com/yourcompany/security/SecurityMonitorFilter.java
package com.yourcompany.security;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

@Component
public class SecurityMonitorFilter extends OncePerRequestFilter {

    private final String gatekeeperUrl;
    private final String apiKey;
    private final boolean enabled;

    private final Queue<Map<String, Object>> eventQueue = new ConcurrentLinkedQueue<>();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(800))
            .build();
    private final ObjectMapper objectMapper;
    private final ScheduledExecutorService scheduler;

    public SecurityMonitorFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        Properties properties = new Properties();
        String configuredUrl = null;
        String configuredApiKey = null;
        try (var input = Files.newInputStream(Path.of("monitoring.properties"))) {
            properties.load(input);
            configuredUrl = properties.getProperty("monitor.url");
            configuredApiKey = properties.getProperty("monitor.apiKey");
        } catch (IOException ignored) {
            // Monitoring stays disabled when its separate config file is unavailable.
        }

        enabled = configuredUrl != null && !configuredUrl.isBlank()
                && configuredApiKey != null && !configuredApiKey.isBlank();
        gatekeeperUrl = enabled ? configuredUrl.replaceAll("/+$", "") + "/api/v1/ingest" : null;
        apiKey = enabled ? configuredApiKey : null;
        scheduler = enabled ? Executors.newSingleThreadScheduledExecutor() : null;
        if (scheduler != null) {
            scheduler.scheduleAtFixedRate(this::flushEvents, 2, 2, TimeUnit.SECONDS);
        }
    }

    @PreDestroy
    public void stopReporter() {
        if (scheduler != null) scheduler.shutdownNow();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!enabled) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        if (path.equals("/health") || path.startsWith("/static")) {
            filterChain.doFilter(request, response);
            return;
        }

        long start = System.currentTimeMillis();
        try {
            filterChain.doFilter(request, response);
        } finally {
            long duration = System.currentTimeMillis() - start;
            Map<String, Object> event = new HashMap<>();
            event.put("method", request.getMethod());
            event.put("path", path);
            event.put("status", response.getStatus());
            event.put("response_time_ms", duration);
            event.put("client_ip", request.getRemoteAddr());
            event.put("user_agent", request.getHeader("User-Agent"));

            eventQueue.add(event);
        }
    }

    private void flushEvents() {
        if (eventQueue.isEmpty()) return;
        List<Map<String, Object>> batch = new ArrayList<>();
        while (!eventQueue.isEmpty() && batch.size() < 100) {
            batch.add(eventQueue.poll());
        }
        try {
            String json = objectMapper.writeValueAsString(batch);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(gatekeeperUrl))
                    .timeout(Duration.ofMillis(800))
                    .header("Content-Type", "application/json")
                    .header("X-API-Key", apiKey)
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();
            httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .exceptionally(error -> null);
        } catch (Exception ignored) {
            // Monitoring must never affect the application.
        }
    }
}`,
    php: `<?php
// PHP Ingest Integration (FastCGI Finish Request / cURL non-blocking)

    function loadMonitoringConfig(): array {
        $path = __DIR__ . '/monitoring.env';
        if (!is_file($path)) return [];

        $config = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $parts = explode('=', $line, 2);
            if (count($parts) !== 2) continue;
            $config[trim($parts[0])] = trim($parts[1]);
        }
        return $config;
    }

    $monitoringConfig = loadMonitoringConfig();
    $monitorUrl = $monitoringConfig['MONITOR_URL'] ?? null;
    $apiKey = $monitoringConfig['MONITOR_API_KEY'] ?? null;
    $monitoringEnabled = is_string($monitorUrl) && $monitorUrl !== ''
        && is_string($apiKey) && $apiKey !== '';

    register_shutdown_function(function() use ($monitoringEnabled, $monitorUrl, $apiKey) {
        if (!$monitoringEnabled) return;

    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if ($path === '/health') return;

    // Flush response to user first so monitoring adds ZERO delay
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }

    $event = [
        'timestamp' => gmdate('c'),
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'path' => $path,
        'status' => http_response_code(),
        'response_time_ms' => round((microtime(true) - $_SERVER['REQUEST_TIME_FLOAT']) * 1000, 1),
        'client_ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
    ];

    // Fire non-blocking curl with short timeout (800ms)
    $ch = curl_init(rtrim($monitorUrl, '/') . '/api/v1/ingest');
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([$event]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'X-API-Key: ' . $apiKey
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT_MS, 800);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
});
?>`,
};

export const guideSetup = {
    node: {
      file: 'security-reporter.js in the same folder as your server.js or app.js',
      main: "In server.js/app.js near the top: import { securityMonitorMiddleware } from './security-reporter.js'; Then after creating your Express app: app.use(securityMonitorMiddleware);",
      install: 'Run: npm install dotenv (Node 18 or newer is required for fetch).',
      env: `MONITOR_URL=http://127.0.0.1:3000
MONITOR_API_KEY={{guideApiKeyPlaceholder}}`,
      note: 'This reports request metadata only; it never reads request bodies, passwords, or query values.',
    },
    python: {
      file: 'security_reporter.py in the same folder as your main.py or app.py',
      main: 'In main.py/app.py after creating the app: app.add_middleware(SecurityMonitorMiddleware)',
      install: 'Run: pip install httpx starlette python-dotenv.',
      env: `MONITOR_URL={{platformUrl}}
MONITOR_API_KEY={{guideApiKeyPlaceholder}}`,
      note: 'This reports request metadata only; it never reads request bodies, passwords, or query values.',
    },
    java: {
      file: 'SecurityMonitorFilter.java in your Spring Boot source package, plus monitoring.properties in your project root (the same folder where you run the jar)',
      main: 'The @Component annotation turns the filter on automatically. Add the file to your Spring Boot source package. Create monitoring.properties in your project\'s root folder (the same folder you run the jar from), with monitor.url=... and monitor.apiKey=... Delete this file to turn monitoring off.',
      install: 'Use Spring Boot 3 (Java 11+). Your existing spring-boot-starter-web already provides ObjectMapper.',
      env: `monitor.url={{platformUrl}}
monitor.apiKey={{guideApiKeyPlaceholder}}`,
      note: 'This reports request metadata only; it never reads request bodies, passwords, or query values. Monitoring reads its own separate config file — it does not use this project\'s normal config/settings and never needs OS-level environment variables set.',
    },
    php: {
      file: 'security-reporter.php and monitoring.env in the same folder as your front controller (often public/index.php)',
      main: 'In public/index.php near the top, add: require_once __DIR__ . \'/security-reporter.php\'; Create monitoring.env in the same folder as security-reporter.php, with MONITOR_URL=... and MONITOR_API_KEY=... Delete this file to turn monitoring off.',
      install: 'Enable the PHP cURL extension. No Composer package is required.',
      env: `MONITOR_URL={{platformUrl}}
MONITOR_API_KEY={{guideApiKeyPlaceholder}}`,
      note: 'This reports request metadata only; it never reads request bodies, passwords, or query values. Monitoring reads its own separate config file — it does not use this project\'s normal config/settings and never needs OS-level environment variables set.',
    },
} as const;
