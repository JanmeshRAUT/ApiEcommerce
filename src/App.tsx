import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Shield,
  RefreshCw,
  Download,
  Search,
  ExternalLink,
  Copy,
  Check,
  Server,
  Zap,
  Lock,
  LogOut,
  AlertTriangle,
  Clock,
  Activity,
  Globe,
  Layers,
  X,
  User,
  Key,
  Plus,
  Trash2,
  RotateCw,
  Power,
  Code2,
  LayoutDashboard,
  CheckCircle2,
  FileText,
  ChevronDown,
  ShieldAlert,
  SlidersHorizontal,
  Flame,
  Sliders,
  Database,
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import { ThreatsView } from './components/ThreatsView';
import { RulesView } from './components/RulesView';
import { SettingsView } from './components/SettingsView';
import { SettingsModal } from './components/SettingsModal';
import { MlDataView } from './components/MlDataView';
import { ToastNotifications } from './components/ToastNotifications';
import { ThreatRecord, PlatformSettings, OpenThreatsSummary } from './types/threats';

interface RegisteredApp {
  id: string;
  name: string;
  environment: 'dev' | 'prod';
  key_prefix: string;
  status: 'active' | 'disabled';
  created_at: string;
  last_seen_at: string | null;
  total_requests: number;
}

interface TrafficRecord {
  request_id: string;
  app_id?: string;
  app_name?: string;
  environment?: 'dev' | 'prod';
  timestamp: string;
  client_ip: string;
  method: string;
  path: string;
  normalized_path: string;
  query_param_names: string[];
  status_code: number;
  response_time_ms: number;
  request_size: number;
  response_size: number;
  user_agent: string;
  user_id_hash?: string;
  login_result: 'ok' | 'fail' | 'none';
  threat_rule?: string;
  label?: string;
  label_source?: 'rule' | 'human';
}

interface MinuteMetric {
  time: string;
  timestamp: number;
  requests: number;
  errors: number;
}

interface EndpointMetric {
  endpoint: string;
  count: number;
  percentage: number;
}

interface ClientIpMetric {
  ip: string;
  count: number;
  percentage: number;
}

interface SlowestEndpointMetric {
  endpoint: string;
  avg_response_time_ms: number;
  count: number;
}

interface DashboardStats {
  total_requests: number;
  error_rate: number;
  failed_logins: number;
  avg_response_time_ms: number;
  status_code_breakdown: {
    '2xx': number;
    '3xx': number;
    '4xx': number;
    '5xx': number;
  };
  requests_per_minute: MinuteMetric[];
  top_endpoints: EndpointMetric[];
  top_client_ips: ClientIpMetric[];
  slowest_endpoints: SlowestEndpointMetric[];
  generated_at: string;
  selected_app_id: string | null;
  open_threats_by_severity?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

export default function App() {
  // Navigation: 'dashboard' | 'threats' | 'rules' | 'applications' | 'guide' | 'ml' | 'settings'
  const [activeTab, setActiveTab] = useState<'dashboard' | 'threats' | 'rules' | 'applications' | 'guide' | 'ml' | 'settings'>(() => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const tab = params.get('tab');
      if (tab === 'threats' || tab === 'rules' || tab === 'applications' || tab === 'guide' || tab === 'ml' || tab === 'settings') {
        return tab;
      }
    }
    return 'dashboard';
  });

  const [initialThreatId, setInitialThreatId] = useState<string | null>(() => {
    if (typeof window !== 'undefined') {
      return new URLSearchParams(window.location.search).get('threat_id');
    }
    return null;
  });

  // Threat Detection & Simulator State
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [platformSettings, setPlatformSettings] = useState<PlatformSettings>({ mode: 'shadow', notify_on_high_critical: true });
  const [toasts, setToasts] = useState<ThreatRecord[]>([]);
  const [isSimulatingAttack, setIsSimulatingAttack] = useState(false);
  const [attackResultModal, setAttackResultModal] = useState<{ count: number; rules: string[] } | null>(null);

  // Authentication State
  const [authToken, setAuthToken] = useState<string | null>(() => localStorage.getItem('gatekeeper_admin_token'));
  const [currentUser, setCurrentUser] = useState<string | null>(null);
  const [weakAdminPassword, setWeakAdminPassword] = useState<boolean>(false);
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // Applications & Multi-Tenant State
  const [apps, setApps] = useState<RegisteredApp[]>([]);
  const [selectedAppId, setSelectedAppId] = useState<string>('ALL');
  const [newKeyModal, setNewKeyModal] = useState<{ appName: string; plainKey: string } | null>(null);
  const [isRegisteringApp, setIsRegisteringApp] = useState(false);
  const [newAppName, setNewAppName] = useState('');
  const [newAppEnv, setNewAppEnv] = useState<'dev' | 'prod'>('dev');

  // Telemetry Data State
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [records, setRecords] = useState<TrafficRecord[]>([]);

  // Auto Refresh State (5 seconds)
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [secondsUntilRefresh, setSecondsUntilRefresh] = useState(5);

  // Filter States for Live Table
  const [methodFilter, setMethodFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Inspection Drawer
  const [selectedRecord, setSelectedRecord] = useState<TrafficRecord | null>(null);
  const [copiedId, setCopiedId] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);

  // Connect Guide state
  const [guideLanguage, setGuideLanguage] = useState<'node' | 'python' | 'java' | 'php'>('node');
  const [guideSelectedAppId, setGuideSelectedAppId] = useState<string>('');

  // Host URL for snippets
  const platformUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';

  // Verify auth session
  useEffect(() => {
    async function verifyAuth() {
      if (!authToken) return;
      try {
        const res = await fetch('/api/auth/check', {
          headers: { Authorization: `Bearer ${authToken}` },
        });
        const data = await res.json();
        if (data.authenticated) {
          setCurrentUser(data.user?.username || 'admin');
          setWeakAdminPassword(Boolean(data.weak_admin_password));
        } else {
          localStorage.removeItem('gatekeeper_admin_token');
          setAuthToken(null);
        }
      } catch {
      }
    }
    verifyAuth();
  }, [authToken]);

  // Fetch list of registered applications
  const fetchApps = useCallback(async () => {
    try {
      const res = await fetch('/api/apps');
      if (res.ok) {
        const data = await res.json();
        setApps(data.apps || []);
        if (!guideSelectedAppId && data.apps?.length > 0) {
          setGuideSelectedAppId(data.apps[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch apps:', err);
    }
  }, [guideSelectedAppId]);

  // Fetch Dashboard Stats from GET /api/stats?app_id=...
  const fetchStats = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (selectedAppId && selectedAppId !== 'ALL') {
        params.append('app_id', selectedAppId);
      }
      const res = await fetch(`/api/stats?${params.toString()}`);
      if (res.ok) {
        const data: DashboardStats = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch /api/stats:', err);
    }
  }, [selectedAppId]);

  // Fetch Latest 50 Requests with filters & app_id
  const fetchRecords = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: '50' });
      if (selectedAppId && selectedAppId !== 'ALL') params.append('app_id', selectedAppId);
      if (methodFilter !== 'ALL') params.append('method', methodFilter);
      if (statusFilter !== 'ALL') params.append('status', statusFilter);
      if (searchQuery.trim()) params.append('search', searchQuery.trim());

      const res = await fetch(`/api/monitor/records?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setRecords(data.records || []);
      }
    } catch (err) {
      console.error('Failed to fetch records:', err);
    }
  }, [selectedAppId, methodFilter, statusFilter, searchQuery]);

  // Fetch Platform Settings (Shadow mode)
  const fetchSettings = useCallback(async () => {
    try {
      const res = await fetch('/api/threats/settings');
      if (res.ok) {
        const data = await res.json();
        if (data.settings) setPlatformSettings(data.settings);
      }
    } catch (err) {
      console.error('Failed to load settings:', err);
    }
  }, []);

  // Attack Simulator: Fires 5 sample attacks
  const handleSimulateAttack = async () => {
    setIsSimulatingAttack(true);
    try {
      const targetAppId = selectedAppId !== 'ALL' ? selectedAppId : undefined;
      const res = await fetch('/api/threats/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_id: targetAppId }),
      });
      if (res.ok) {
        const data = await res.json();
        setAttackResultModal({
          count: data.rules_fired_count || 0,
          rules: data.fired_rules || [],
        });

        // Trigger toasts for high/critical threats if enabled
        if (platformSettings.notify_on_high_critical) {
          const threatsRes = await fetch('/api/threats');
          if (threatsRes.ok) {
            const threatsData = await threatsRes.json();
            const alerts: ThreatRecord[] = (threatsData.threats || [])
              .filter((t: ThreatRecord) => t.severity === 'critical' || t.severity === 'high')
              .slice(0, 3);
            setToasts(alerts);
          }
        }

        fetchStats();
        fetchRecords();
      }
    } catch (err) {
      console.error('Failed to run attack simulator:', err);
    } finally {
      setIsSimulatingAttack(false);
    }
  };

  // Initial load
  useEffect(() => {
    if (authToken) {
      fetchApps();
      fetchStats();
      fetchRecords();
      fetchSettings();
    }
  }, [authToken, fetchApps, fetchStats, fetchRecords, fetchSettings]);

  // 5-Second Auto Refresh Timer
  useEffect(() => {
    if (!autoRefresh || !authToken) return;

    const interval = setInterval(() => {
      setSecondsUntilRefresh((prev) => {
        if (prev <= 1) {
          fetchStats();
          fetchRecords();
          fetchApps();
          return 5;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [autoRefresh, authToken, fetchStats, fetchRecords, fetchApps]);

  // Handle Login
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setIsLoggingIn(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginUsername.trim(),
          password: loginPassword,
        }),
      });

      const data = await res.json();
      if (res.ok && data.success && data.token) {
        localStorage.setItem('gatekeeper_admin_token', data.token);
        setAuthToken(data.token);
        setCurrentUser(data.user?.username || loginUsername);
        setWeakAdminPassword(Boolean(data.weak_admin_password));
      } else {
        setLoginError(data.error || 'Invalid credentials. Check ADMIN_USER and ADMIN_PASS environment variables.');
      }
    } catch (err: any) {
      setLoginError(err.message || 'Unable to connect to authentication server.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  // Handle Logout
  const handleLogout = async () => {
    try {
      if (authToken) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${authToken}` },
        });
      }
    } catch {
    }
    localStorage.removeItem('gatekeeper_admin_token');
    setAuthToken(null);
    setCurrentUser(null);
  };

  // Register New App
  const handleRegisterApp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAppName.trim()) return;

    try {
      const res = await fetch('/api/apps', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newAppName.trim(),
          environment: newAppEnv,
        }),
      });

      const data = await res.json();
      if (res.ok && data.plain_api_key) {
        setNewKeyModal({
          appName: data.app.name,
          plainKey: data.plain_api_key,
        });
        setNewAppName('');
        setIsRegisteringApp(false);
        await fetchApps();
      }
    } catch (err) {
      console.error('App registration error:', err);
    }
  };

  // Regenerate App API Key
  const handleRegenerateKey = async (app: RegisteredApp) => {
    if (!confirm(`Regenerate API key for "${app.name}"? Any backend using the old key will be rejected immediately.`)) {
      return;
    }

    try {
      const res = await fetch(`/api/apps/${app.id}/regenerate-key`, { method: 'POST' });
      const data = await res.json();
      if (res.ok && data.plain_api_key) {
        setNewKeyModal({
          appName: app.name,
          plainKey: data.plain_api_key,
        });
        await fetchApps();
      }
    } catch (err) {
      console.error('Key regeneration error:', err);
    }
  };

  // Toggle App Status (active/disabled)
  const handleToggleStatus = async (app: RegisteredApp) => {
    try {
      await fetch(`/api/apps/${app.id}/toggle-status`, { method: 'POST' });
      await fetchApps();
    } catch (err) {
      console.error('Toggle status error:', err);
    }
  };

  // Delete App
  const handleDeleteApp = async (app: RegisteredApp) => {
    if (!confirm(`Are you sure you want to delete "${app.name}"? This action cannot be undone.`)) {
      return;
    }

    try {
      await fetch(`/api/apps/${app.id}`, { method: 'DELETE' });
      if (selectedAppId === app.id) setSelectedAppId('ALL');
      await fetchApps();
      await fetchStats();
      await fetchRecords();
    } catch (err) {
      console.error('Delete app error:', err);
    }
  };

  // Copy raw JSON to clipboard
  const handleCopyJson = (record: TrafficRecord) => {
    navigator.clipboard.writeText(JSON.stringify(record, null, 2));
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  // Recharts Data Prep
  const topEndpointsChartData = useMemo(() => {
    if (!stats?.top_endpoints) return [];
    return stats.top_endpoints.slice(0, 8).map((item) => ({
      name: item.endpoint.length > 20 ? item.endpoint.slice(0, 18) + '…' : item.endpoint,
      fullName: item.endpoint,
      requests: item.count,
      percentage: item.percentage,
    }));
  }, [stats]);

  const requestsPerMinuteChartData = useMemo(() => {
    if (!stats?.requests_per_minute) return [];
    return stats.requests_per_minute.map((item) => ({
      time: item.time,
      requests: item.requests,
      errors: item.errors,
    }));
  }, [stats]);

  const statusBreakdownData = useMemo(() => {
    if (!stats?.status_code_breakdown) return [];
    return [
      { name: '2xx (OK)', count: stats.status_code_breakdown['2xx'] || 0, fill: '#10b981' },
      { name: '3xx (Redirect)', count: stats.status_code_breakdown['3xx'] || 0, fill: '#64748b' },
      { name: '4xx (Client)', count: stats.status_code_breakdown['4xx'] || 0, fill: '#f59e0b' },
      { name: '5xx (Server)', count: stats.status_code_breakdown['5xx'] || 0, fill: '#ef4444' },
    ];
  }, [stats]);

  // Selected App for Connect Guide
  const guideApp = apps.find((a) => a.id === guideSelectedAppId) || apps[0];
  const guideApiKeyPlaceholder = guideApp ? `${guideApp.key_prefix}` : 'sk_live_YOUR_API_KEY';

  // Code Snippets for Connect Guide
  const snippets = {
    node: `// Node.js Express Middleware (Zero Latency, Background Batching)
// npm install node-fetch (or use Node 18+ built-in fetch)

const GATEKEEPER_URL = '${platformUrl}/api/v1/ingest';
const API_KEY = '${guideApiKeyPlaceholder}';

let eventQueue = [];
let flushTimer = null;

function flushQueue() {
  if (eventQueue.length === 0) return;
  const batch = eventQueue.splice(0, 100);

  // Send in background with short 800ms timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 800);

  fetch(GATEKEEPER_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
    },
    body: JSON.stringify(batch),
    signal: controller.signal,
  })
    .catch(() => {}) // Never break or slow the app if platform is unreachable
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

GATEKEEPER_URL = "${platformUrl}/api/v1/ingest"
API_KEY = "${guideApiKeyPlaceholder}"

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
    java: `// Java Spring Boot Servlet Filter (Non-blocking Scheduled Ingest)
package com.example.security;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

@Component
public class SecurityMonitorFilter extends OncePerRequestFilter {

    private static final String GATEKEEPER_URL = "${platformUrl}/api/v1/ingest";
    private static final String API_KEY = "${guideApiKeyPlaceholder}";

    private final Queue<Map<String, Object>> eventQueue = new ConcurrentLinkedQueue<>();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(800))
            .build();

    public SecurityMonitorFilter() {
        // Background batch dispatcher runs every 2 seconds
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(
            this::flushEvents, 2, 2, TimeUnit.SECONDS
        );
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

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
        // Send JSON batch to GATEKEEPER_URL with X-API-Key header (async)
    }
}`,
    php: `<?php
// PHP Ingest Integration (FastCGI Finish Request / cURL non-blocking)

define('GATEKEEPER_URL', '${platformUrl}/api/v1/ingest');
define('API_KEY', '${guideApiKeyPlaceholder}');

register_shutdown_function(function() {
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
    $ch = curl_init(GATEKEEPER_URL);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([$event]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'X-API-Key: ' . API_KEY
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT_MS, 800);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
});
?>`,
  };

  // ----------------------------------------------------
  // LOGIN SCREEN (If not authenticated)
  // ----------------------------------------------------
  if (!authToken) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6 text-slate-900 antialiased">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-xl shadow-lg shadow-slate-200/50 p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-md shadow-blue-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-900 tracking-tight">API Security Platform</h1>
              <p className="text-xs text-slate-500">Central Monitoring & Telemetry Ingest</p>
            </div>
          </div>

          <div className="mb-6 p-3.5 bg-blue-50 border border-blue-100 rounded-lg text-xs text-blue-900">
            <div className="font-semibold text-blue-950 mb-1 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-blue-600" />
              <span>Admin Authentication</span>
            </div>
            <p className="text-blue-700/90 leading-relaxed">
              Authenticate using credentials configured via <code className="font-mono bg-blue-100/60 px-1 rounded">ADMIN_USER</code> and <code className="font-mono bg-blue-100/60 px-1 rounded">ADMIN_PASS</code>.
            </p>
          </div>

          {loginError && (
            <div className="mb-4 p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-700 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <span>{loginError}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Admin Username
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  required
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  placeholder="Enter username"
                  className="w-full pl-9 pr-3 py-2 text-sm bg-white border border-slate-300 rounded-lg focus:border-blue-600 focus:ring-1 focus:ring-blue-600 focus:outline-none text-slate-900"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Admin Password
              </label>
              <div className="relative">
                <Key className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="password"
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full pl-9 pr-3 py-2 text-sm bg-white border border-slate-300 rounded-lg focus:border-blue-600 focus:ring-1 focus:ring-blue-600 focus:outline-none text-slate-900"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoggingIn}
              className="w-full py-2.5 px-4 mt-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50 rounded-lg transition-colors shadow-sm shadow-blue-500/20 flex items-center justify-center gap-2 cursor-pointer"
            >
              <Lock className="w-4 h-4" />
              <span>{isLoggingIn ? 'Verifying...' : 'Sign In to Platform'}</span>
            </button>
          </form>
        </div>
      </div>
    );
  }

  // ----------------------------------------------------
  // MAIN CENTRAL PLATFORM UI
  // ----------------------------------------------------
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col antialiased">
      {/* 1. TOP HEADER & NAVIGATION */}
      <header className="bg-white border-b border-slate-200 px-6 py-3 flex flex-wrap items-center justify-between gap-4 sticky top-0 z-40">
        {/* Brand & Tabs */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-sm shadow-blue-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-slate-900 text-sm tracking-tight flex items-center gap-2">
                <span>Gatekeeper Security Platform</span>
                <span className="text-[10px] font-mono font-medium text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                  CENTRAL INGEST
                </span>
              </div>
              <div className="text-[11px] text-slate-500">
                Ingest API: <code className="font-mono text-blue-600">POST /api/v1/ingest</code>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                activeTab === 'dashboard'
                  ? 'bg-white text-blue-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              <span>Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('threats')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                activeTab === 'threats'
                  ? 'bg-white text-blue-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
              <span>Threats</span>
              {stats?.open_threats_by_severity && stats.open_threats_by_severity.total > 0 && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-rose-600 text-white leading-none">
                  {stats.open_threats_by_severity.total}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('rules')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                activeTab === 'rules'
                  ? 'bg-white text-blue-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Shield className="w-3.5 h-3.5 text-blue-600" />
              <span>Rules (13)</span>
            </button>

            <button
              onClick={() => setActiveTab('applications')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                activeTab === 'applications'
                  ? 'bg-white text-blue-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Applications ({apps.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('guide')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                activeTab === 'guide'
                  ? 'bg-white text-blue-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Connect Guide</span>
            </button>

            <button
              onClick={() => setActiveTab('ml')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                activeTab === 'ml'
                  ? 'bg-white text-blue-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Database className="w-3.5 h-3.5 text-blue-600" />
              <span>ML Data</span>
            </button>

            <button
              onClick={() => setActiveTab('settings')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                activeTab === 'settings'
                  ? 'bg-white text-blue-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Sliders className="w-3.5 h-3.5 text-slate-600" />
              <span>Settings</span>
            </button>
          </nav>
        </div>

        {/* Global Controls & Actions */}
        <div className="flex items-center gap-2.5">
          {/* Mode Indicator & Settings trigger */}
          <button
            onClick={() => setActiveTab('settings')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 transition-colors cursor-pointer"
            title="Open Settings & Alerts Configuration"
          >
            <Shield className="w-3.5 h-3.5 text-blue-600" />
            <span>Mode: {platformSettings.mode === 'shadow' ? 'Shadow' : 'Alert-Only'}</span>
            <Sliders className="w-3 h-3 text-blue-500 ml-0.5" />
          </button>

          {/* Auto Refresh Toggle (5s) */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 transition-colors cursor-pointer"
            title="Auto-refresh every 5 seconds"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-blue-600 ${autoRefresh ? 'animate-spin-slow' : 'opacity-40'}`} />
            <span className="font-mono tabular-nums">{autoRefresh ? `5s` : 'Paused'}</span>
          </button>

          {/* Attack Simulator Button */}
          <button
            onClick={handleSimulateAttack}
            disabled={isSimulatingAttack}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-rose-700 bg-rose-50 hover:bg-rose-100 active:bg-rose-200 border border-rose-200 rounded-lg transition-all shadow-xs cursor-pointer disabled:opacity-50 whitespace-nowrap"
            title="Fires 5 sample attacks (brute force, SQLi, scraping, fake signups, path traversal)"
          >
            <Flame className={`w-3.5 h-3.5 text-rose-600 ${isSimulatingAttack ? 'animate-spin' : ''}`} />
            <span>{isSimulatingAttack ? 'Simulating Attacks...' : 'Attack Simulator'}</span>
          </button>

          {/* User Profile & Logout */}
          <div className="flex items-center gap-2 pl-2 border-l border-slate-200">
            <span className="text-xs font-medium text-slate-700 hidden sm:inline">{currentUser}</span>
            <button
              onClick={handleLogout}
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 border border-slate-200 transition-colors cursor-pointer"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* SECURITY WARNING BANNER FOR DEFAULT OR WEAK ADMIN PASSWORD */}
      {weakAdminPassword && (
        <div className="bg-rose-600 text-white px-6 py-2.5 text-xs font-medium flex items-center justify-center gap-2.5 shadow-xs">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span className="font-bold">Change the default password</span>
          <span className="opacity-90 hidden sm:inline">
            — ADMIN_PASS is currently set to an insecure default or is shorter than 8 characters. Set a strong ADMIN_PASS in your environment variables.
          </span>
        </div>
      )}

      {/* 2. BODY CONTENT ROUTED BY ACTIVE TAB */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 flex flex-col gap-6">
        {/* ========================================================================= */}
        {/* TAB 1: DASHBOARD VIEW */}
        {/* ========================================================================= */}
        {activeTab === 'dashboard' && (
          <>
            {/* APP SELECTOR BAR */}
            <div className="bg-white border border-slate-200 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-xs">
              <div className="flex items-center gap-3">
                <span className="text-xs font-semibold text-slate-700">Filter By Application:</span>
                <div className="relative">
                  <select
                    value={selectedAppId}
                    onChange={(e) => setSelectedAppId(e.target.value)}
                    className="pl-3 pr-8 py-1.5 text-xs font-medium bg-slate-50 border border-slate-300 rounded-lg text-slate-800 focus:border-blue-600 focus:outline-none cursor-pointer appearance-none"
                  >
                    <option value="ALL">All Connected Applications ({apps.length})</option>
                    {apps.map((app) => (
                      <option key={app.id} value={app.id}>
                        {app.name} ({app.environment}) - {app.status}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-500 absolute right-2.5 top-2.5 pointer-events-none" />
                </div>
              </div>

              <div className="text-xs text-slate-500 flex items-center gap-3">
                <span>Ingest Endpoint:</span>
                <code className="font-mono bg-slate-100 text-blue-700 px-2 py-0.5 rounded border border-slate-200 font-medium">
                  POST /api/v1/ingest
                </code>
                <span className="text-slate-300">·</span>
                <span>Header: <code className="font-mono text-slate-700 font-semibold">X-API-Key</code></span>
              </div>
            </div>

            {/* ROW 1: TOP 5 METRIC CARDS (INCLUDING OPEN THREATS BY SEVERITY) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              {/* Card 1: Total Requests */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
                <div className="flex items-center justify-between text-slate-500 mb-2">
                  <span className="text-xs font-semibold tracking-wide uppercase text-slate-500">Total Requests</span>
                  <div className="p-1.5 rounded-md bg-blue-50 text-blue-600">
                    <Layers className="w-4 h-4" />
                  </div>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold font-mono text-slate-900 tabular-nums">
                    {stats?.total_requests ?? 0}
                  </span>
                  <span className="text-xs text-slate-500">ingested</span>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                  <span>Scope:</span>
                  <span className="font-medium text-slate-700 truncate max-w-[100px]">
                    {selectedAppId === 'ALL' ? 'All Apps' : apps.find((a) => a.id === selectedAppId)?.name || 'Filtered'}
                  </span>
                </div>
              </div>

              {/* Card 2: Open Threats by Severity (STEP 3 KPI CARD) */}
              <div
                onClick={() => setActiveTab('threats')}
                className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs hover:border-blue-400 hover:shadow-sm cursor-pointer transition-all group"
              >
                <div className="flex items-center justify-between text-slate-500 mb-2">
                  <span className="text-xs font-semibold tracking-wide uppercase text-slate-500 group-hover:text-blue-600">
                    Open Threats
                  </span>
                  <div className={`p-1.5 rounded-md ${(stats?.open_threats_by_severity?.total ?? 0) > 0 ? 'bg-rose-50 text-rose-600' : 'bg-emerald-50 text-emerald-600'}`}>
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className={`text-3xl font-bold font-mono tabular-nums ${(stats?.open_threats_by_severity?.total ?? 0) > 0 ? 'text-rose-600' : 'text-emerald-600'}`}>
                    {stats?.open_threats_by_severity?.total ?? 0}
                  </span>
                  <span className="text-xs text-slate-500">detected</span>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] font-mono">
                  <span className="text-rose-700 font-bold">{stats?.open_threats_by_severity?.critical ?? 0} crit</span>
                  <span className="text-orange-700 font-bold">{stats?.open_threats_by_severity?.high ?? 0} high</span>
                  <span className="text-amber-700">{stats?.open_threats_by_severity?.medium ?? 0} med</span>
                  <span className="text-blue-700">{stats?.open_threats_by_severity?.low ?? 0} low</span>
                </div>
              </div>

              {/* Card 3: Error Rate */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
                <div className="flex items-center justify-between text-slate-500 mb-2">
                  <span className="text-xs font-semibold tracking-wide uppercase text-slate-500">Error Rate</span>
                  <div className={`p-1.5 rounded-md ${(stats?.error_rate ?? 0) > 15 ? 'bg-amber-50 text-amber-600' : 'bg-blue-50 text-blue-600'}`}>
                    <AlertTriangle className="w-4 h-4" />
                  </div>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className={`text-3xl font-bold font-mono tabular-nums ${(stats?.error_rate ?? 0) > 20 ? 'text-rose-600' : (stats?.error_rate ?? 0) > 5 ? 'text-amber-600' : 'text-blue-600'}`}>
                    {stats?.error_rate ?? 0}%
                  </span>
                  <span className="text-xs text-slate-500">4xx / 5xx</span>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                  <span>Breakdown:</span>
                  <span className="font-mono text-slate-700">
                    {stats?.status_code_breakdown['4xx'] ?? 0} / {stats?.status_code_breakdown['5xx'] ?? 0}
                  </span>
                </div>
              </div>

              {/* Card 4: Failed Logins */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
                <div className="flex items-center justify-between text-slate-500 mb-2">
                  <span className="text-xs font-semibold tracking-wide uppercase text-slate-500">Failed Logins</span>
                  <div className="p-1.5 rounded-md bg-rose-50 text-rose-600">
                    <Lock className="w-4 h-4" />
                  </div>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold font-mono text-rose-600 tabular-nums">
                    {stats?.failed_logins ?? 0}
                  </span>
                  <span className="text-xs text-slate-500">rejections</span>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                  <span>Status:</span>
                  <span className="text-slate-600 text-[11px]">Credential-safe</span>
                </div>
              </div>

              {/* Card 5: Average Latency */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
                <div className="flex items-center justify-between text-slate-500 mb-2">
                  <span className="text-xs font-semibold tracking-wide uppercase text-slate-500">Avg Latency</span>
                  <div className="p-1.5 rounded-md bg-blue-50 text-blue-600">
                    <Clock className="w-4 h-4" />
                  </div>
                </div>
                <div className="flex items-baseline gap-1.5">
                  <span className="text-3xl font-bold font-mono text-blue-600 tabular-nums">
                    {stats?.avg_response_time_ms ?? 0}
                  </span>
                  <span className="text-xs font-semibold text-slate-500 font-mono">ms</span>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                  <span>Response:</span>
                  <span className="font-mono text-slate-700 font-medium">Real backend</span>
                </div>
              </div>
            </div>

            {/* ROW 2: CHARTS (Line Chart: Throughput + Bar Chart: Top Endpoints + Status Breakdown) */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Chart 1: Requests Per Minute (2 Columns) */}
              <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 tracking-tight">Requests Per Minute</h3>
                    <p className="text-xs text-slate-500">Live throughput over the last 30 minutes</p>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-blue-600"></span>
                      <span className="text-slate-600 font-medium">All Requests</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
                      <span className="text-slate-600 font-medium">Errors (4xx/5xx)</span>
                    </div>
                  </div>
                </div>

                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={requestsPerMinuteChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                      <XAxis
                        dataKey="time"
                        stroke="#94a3b8"
                        fontSize={11}
                        tickLine={false}
                        axisLine={{ stroke: '#cbd5e1' }}
                        interval={4}
                      />
                      <YAxis
                        stroke="#94a3b8"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                        allowDecimals={false}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#ffffff',
                          borderColor: '#cbd5e1',
                          borderRadius: '8px',
                          fontSize: '12px',
                          boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                        }}
                        formatter={(value: any, name: any) => [
                          value,
                          name === 'requests' ? 'Total Requests' : 'Errors',
                        ]}
                        labelFormatter={(label) => `Time: ${label}`}
                      />
                      <Line
                        type="monotone"
                        dataKey="requests"
                        stroke="#2563eb"
                        strokeWidth={2.5}
                        dot={{ r: 2, fill: '#2563eb' }}
                        activeDot={{ r: 5, stroke: '#1d4ed8', strokeWidth: 2 }}
                      />
                      <Line
                        type="monotone"
                        dataKey="errors"
                        stroke="#ef4444"
                        strokeWidth={1.5}
                        strokeDasharray="4 4"
                        dot={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Chart 2: Status Breakdown Chart (1 Column) */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 tracking-tight">Status Breakdown</h3>
                    <p className="text-xs text-slate-500">Distribution by response code</p>
                  </div>
                </div>

                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={statusBreakdownData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                      <YAxis stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#ffffff',
                          borderColor: '#cbd5e1',
                          borderRadius: '8px',
                          fontSize: '12px',
                        }}
                      />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* ROW 3: TOP ENDPOINTS + TOP CLIENT IPs & 5 SLOWEST ENDPOINTS */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Top Endpoints Bar Chart (1 Column) */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 tracking-tight">Top 10 Endpoints</h3>
                    <p className="text-xs text-slate-500">Normalized URI path distribution</p>
                  </div>
                </div>

                <div className="h-72 w-full">
                  {topEndpointsChartData.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-xs text-slate-400">
                      No endpoint data recorded yet
                    </div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={topEndpointsChartData}
                        layout="vertical"
                        margin={{ top: 5, right: 25, left: 35, bottom: 5 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#e2e8f0" />
                        <XAxis type="number" stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                        <YAxis dataKey="name" type="category" stroke="#475569" fontSize={11} tickLine={false} axisLine={false} width={95} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#ffffff',
                            borderColor: '#cbd5e1',
                            borderRadius: '8px',
                            fontSize: '12px',
                          }}
                          formatter={(val: any, _name: any, item: any) => [
                            `${val} requests (${item.payload.percentage}%)`,
                            item.payload.fullName,
                          ]}
                        />
                        <Bar dataKey="requests" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={14} />
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </div>

              {/* Table A: Top Client IPs (1 Column) */}
              <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs flex flex-col">
                <div className="px-5 py-3.5 border-b border-slate-200 bg-slate-50/60 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-blue-600" />
                    <h3 className="text-sm font-bold text-slate-900 tracking-tight">Top Client IPs</h3>
                  </div>
                  <span className="text-xs text-slate-500 font-mono">By Volume</span>
                </div>

                <div className="overflow-x-auto flex-1">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-500 font-medium bg-white">
                        <th className="py-2.5 px-3">#</th>
                        <th className="py-2.5 px-3">Client IP</th>
                        <th className="py-2.5 px-3 text-right">Calls</th>
                        <th className="py-2.5 px-3 text-right">%</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono">
                      {!stats?.top_client_ips || stats.top_client_ips.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="py-8 text-center text-slate-400 font-sans">
                            No IP traffic recorded
                          </td>
                        </tr>
                      ) : (
                        stats.top_client_ips.slice(0, 7).map((item, index) => (
                          <tr key={item.ip} className="hover:bg-slate-50 transition-colors">
                            <td className="py-2 px-3 text-slate-400">{index + 1}</td>
                            <td className="py-2 px-3 font-semibold text-slate-900 truncate max-w-[120px]">
                              {item.ip}
                            </td>
                            <td className="py-2 px-3 text-right tabular-nums text-slate-700 font-medium">
                              {item.count}
                            </td>
                            <td className="py-2 px-3 text-right tabular-nums text-slate-500">
                              {item.percentage}%
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Table B: 5 Slowest Endpoints (1 Column) */}
              <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs flex flex-col">
                <div className="px-5 py-3.5 border-b border-slate-200 bg-slate-50/60 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-blue-600" />
                    <h3 className="text-sm font-bold text-slate-900 tracking-tight">5 Slowest Endpoints</h3>
                  </div>
                  <span className="text-xs text-slate-500 font-mono">Latency</span>
                </div>

                <div className="overflow-x-auto flex-1">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-500 font-medium bg-white">
                        <th className="py-2.5 px-3">#</th>
                        <th className="py-2.5 px-3">Endpoint</th>
                        <th className="py-2.5 px-3 text-right">Avg</th>
                        <th className="py-2.5 px-3 text-right">Calls</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono">
                      {!stats?.slowest_endpoints || stats.slowest_endpoints.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="py-8 text-center text-slate-400 font-sans">
                            No endpoint latency data
                          </td>
                        </tr>
                      ) : (
                        stats.slowest_endpoints.map((item, index) => (
                          <tr key={item.endpoint} className="hover:bg-slate-50 transition-colors">
                            <td className="py-2 px-3 text-slate-400">{index + 1}</td>
                            <td className="py-2 px-3 font-semibold text-blue-700 truncate max-w-[130px]" title={item.endpoint}>
                              {item.endpoint}
                            </td>
                            <td className="py-2 px-3 text-right tabular-nums text-slate-900 font-bold">
                              {item.avg_response_time_ms} ms
                            </td>
                            <td className="py-2 px-3 text-right tabular-nums text-slate-500">
                              {item.count}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* ROW 4: LIVE TABLE OF LATEST 50 REQUESTS WITH FILTERS */}
            <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs flex flex-col">
              {/* Table Header and Filters */}
              <div className="p-4 border-b border-slate-200 bg-slate-50/50 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4 text-blue-600" />
                    <h3 className="text-sm font-bold text-slate-900 tracking-tight">Live Ingested Requests</h3>
                    <span className="text-xs text-slate-500">·</span>
                    <span className="text-xs text-slate-500 font-mono">Latest 50 (auto-refresh 5s)</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">Click any row to inspect sanitized JSON payload</p>
                </div>

                {/* Filter Controls */}
                <div className="flex flex-wrap items-center gap-2.5 text-xs">
                  {/* Endpoint Search */}
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                    <input
                      type="text"
                      placeholder="Search endpoint, app, ID, IP..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-8 pr-3 py-1.5 text-xs bg-white border border-slate-300 rounded-lg focus:border-blue-600 focus:outline-none text-slate-900 placeholder:text-slate-400 w-44 sm:w-56"
                    />
                  </div>

                  {/* Method Filter */}
                  <div className="flex items-center bg-white p-0.5 rounded-lg border border-slate-200">
                    {['ALL', 'GET', 'POST'].map((m) => (
                      <button
                        key={m}
                        onClick={() => setMethodFilter(m)}
                        className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer ${
                          methodFilter === m ? 'bg-blue-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>

                  {/* Status Code Filter */}
                  <div className="flex items-center bg-white p-0.5 rounded-lg border border-slate-200">
                    {['ALL', '2xx', '4xx', '5xx'].map((s) => (
                      <button
                        key={s}
                        onClick={() => setStatusFilter(s)}
                        className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer ${
                          statusFilter === s ? 'bg-blue-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>

                  {/* Export JSONL */}
                  <a
                    href="/api/monitor/export"
                    download="traffic.jsonl"
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 rounded-lg transition-colors shadow-xs"
                    title="Download raw traffic.jsonl"
                  >
                    <Download className="w-3.5 h-3.5 text-slate-500" />
                    <span>Export JSONL</span>
                  </a>
                </div>
              </div>

              {/* Table Data */}
              <div className="overflow-x-auto flex-1">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-semibold text-[11px]">
                      <th className="py-2.5 px-3 whitespace-nowrap">Time</th>
                      <th className="py-2.5 px-3 whitespace-nowrap">App</th>
                      <th className="py-2.5 px-3 whitespace-nowrap">Method</th>
                      <th className="py-2.5 px-3 whitespace-nowrap">Normalized Path</th>
                      <th className="py-2.5 px-3 whitespace-nowrap">Query Keys</th>
                      <th className="py-2.5 px-3 whitespace-nowrap">Status</th>
                      <th className="py-2.5 px-3 text-right whitespace-nowrap">Latency</th>
                      <th className="py-2.5 px-3 text-right whitespace-nowrap">Client IP</th>
                      <th className="py-2.5 px-3 whitespace-nowrap">Login Result</th>
                      <th className="py-2.5 px-3 whitespace-nowrap">Threat Analysis</th>
                      <th className="py-2.5 px-3 text-center whitespace-nowrap">Inspect</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono">
                    {records.length === 0 ? (
                      <tr>
                        <td colSpan={11} className="py-12 text-center text-slate-400 font-sans">
                          <div className="max-w-sm mx-auto flex flex-col items-center gap-3">
                            <div className="w-10 h-10 rounded-full bg-blue-50 text-blue-600 flex items-center justify-center">
                              <Activity className="w-5 h-5" />
                            </div>
                            <div className="font-semibold text-slate-800">No requests match criteria</div>
                            <p className="text-xs text-slate-500">
                              Click &quot;Send Test Traffic&quot; or &quot;Attack Simulator&quot; to generate incoming events.
                            </p>
                          </div>
                        </td>
                      </tr>
                    ) : (
                      records.map((r) => {
                        const statusColor =
                          r.status_code >= 200 && r.status_code < 300
                            ? 'text-emerald-700 bg-emerald-50 border-emerald-200'
                            : r.status_code >= 400 && r.status_code < 500
                            ? 'text-amber-700 bg-amber-50 border-amber-200'
                            : 'text-rose-700 bg-rose-50 border-rose-200';

                        const methodColor =
                          r.method === 'GET'
                            ? 'text-blue-700 bg-blue-50'
                            : r.method === 'POST'
                            ? 'text-indigo-700 bg-indigo-50'
                            : 'text-slate-700 bg-slate-100';

                        return (
                          <tr
                            key={r.request_id}
                            onClick={() => setSelectedRecord(r)}
                            className="hover:bg-blue-50/50 cursor-pointer transition-colors"
                          >
                            {/* Time */}
                            <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap tabular-nums">
                              {r.timestamp.split('T')[1]?.replace('Z', '').slice(0, 8)}
                            </td>

                            {/* App Name */}
                            <td className="py-2.5 px-3 whitespace-nowrap">
                              <span className="font-sans text-[11px] font-semibold text-slate-800 bg-slate-100 px-1.5 py-0.5 rounded">
                                {r.app_name || 'Fake Shop'}
                              </span>
                            </td>

                            {/* Method */}
                            <td className="py-2.5 px-3 whitespace-nowrap">
                              <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${methodColor}`}>
                                {r.method}
                              </span>
                            </td>

                            {/* Normalized Path */}
                            <td className="py-2.5 px-3 text-blue-700 font-semibold whitespace-nowrap max-w-[170px] truncate" title={r.path}>
                              {r.normalized_path}
                            </td>

                            {/* Query Keys (names only) */}
                            <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap text-[11px]">
                              {r.query_param_names && r.query_param_names.length > 0 ? (
                                <span className="text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">
                                  [{r.query_param_names.join(', ')}]
                                </span>
                              ) : (
                                <span className="text-slate-300">-</span>
                              )}
                            </td>

                            {/* Status Code */}
                            <td className="py-2.5 px-3 whitespace-nowrap">
                              <span className={`px-1.5 py-0.5 rounded border text-[11px] font-bold tabular-nums ${statusColor}`}>
                                {r.status_code}
                              </span>
                            </td>

                            {/* Latency */}
                            <td className="py-2.5 px-3 text-right whitespace-nowrap tabular-nums text-slate-800 font-medium">
                              {r.response_time_ms} ms
                            </td>

                            {/* Client IP */}
                            <td className="py-2.5 px-3 text-right whitespace-nowrap tabular-nums text-slate-500 text-[11px]">
                              {r.client_ip}
                            </td>

                            {/* Login Result */}
                            <td className="py-2.5 px-3 whitespace-nowrap">
                              {r.login_result === 'ok' ? (
                                <span className="text-emerald-700 font-semibold">ok</span>
                              ) : r.login_result === 'fail' ? (
                                <span className="text-rose-600 font-semibold">fail</span>
                              ) : (
                                <span className="text-slate-300">none</span>
                              )}
                            </td>

                            {/* Threat Detection & ML Label */}
                            <td className="py-2.5 px-3 whitespace-nowrap font-sans">
                              {r.threat_rule && r.threat_rule !== 'normal' ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                                  <AlertTriangle className="w-3 h-3 text-rose-600 shrink-0" />
                                  <span>{r.label || r.threat_rule}</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                                  <CheckCircle2 className="w-3 h-3 text-emerald-600 shrink-0" />
                                  <span>{r.label || 'normal'}</span>
                                  {r.label_source === 'human' && (
                                    <span className="ml-1 px-1 rounded bg-indigo-100 text-indigo-700 font-mono text-[9px]">
                                      human
                                    </span>
                                  )}
                                </span>
                              )}
                            </td>

                            {/* Inspect Action */}
                            <td className="py-2.5 px-3 text-center whitespace-nowrap">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedRecord(r);
                                }}
                                className="p-1 rounded text-slate-400 hover:text-blue-600 hover:bg-blue-50 transition-colors cursor-pointer"
                                title="Inspect JSON record"
                              >
                                <ExternalLink className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: THREATS REGISTRY (STEP 3) */}
        {/* ========================================================================= */}
        {activeTab === 'threats' && (
          <ThreatsView
            apps={apps}
            selectedAppId={selectedAppId}
            onSelectApp={setSelectedAppId}
            initialThreatId={initialThreatId}
            onThreatsUpdated={() => {
              fetchStats();
            }}
          />
        )}

        {/* ========================================================================= */}
        {/* TAB 3: THREAT DETECTION RULES (STEP 3) */}
        {/* ========================================================================= */}
        {activeTab === 'rules' && <RulesView />}

        {/* ========================================================================= */}
        {/* TAB 4: APPLICATIONS MANAGEMENT */}
        {/* ========================================================================= */}
        {activeTab === 'applications' && (
          <div className="flex flex-col gap-6">
            {/* Header + Register Button */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-slate-900 tracking-tight">Connected Applications</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Manage backends authorized to push security telemetry via <code className="font-mono text-blue-600">POST /api/v1/ingest</code>
                </p>
              </div>

              <button
                onClick={() => setIsRegisteringApp(true)}
                className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm shadow-blue-500/20 cursor-pointer transition-colors"
              >
                <Plus className="w-4 h-4" />
                <span>Register Application</span>
              </button>
            </div>

            {/* Applications Table */}
            <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-semibold text-[11px]">
                      <th className="py-3 px-4">Application Name</th>
                      <th className="py-3 px-4">Environment</th>
                      <th className="py-3 px-4">API Key Prefix</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Last Seen</th>
                      <th className="py-3 px-4 text-right">Total Ingested</th>
                      <th className="py-3 px-4 text-center">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {apps.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-8 text-center text-slate-400">
                          No applications registered yet. Click &quot;Register Application&quot; to add one.
                        </td>
                      </tr>
                    ) : (
                      apps.map((app) => (
                        <tr key={app.id} className="hover:bg-slate-50 transition-colors">
                          <td className="py-3 px-4 font-semibold text-slate-900 flex items-center gap-2">
                            <Layers className="w-4 h-4 text-blue-600 shrink-0" />
                            <span>{app.name}</span>
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={`px-2 py-0.5 rounded text-[11px] font-semibold uppercase font-mono ${
                                app.environment === 'prod'
                                  ? 'bg-purple-50 text-purple-700 border border-purple-200'
                                  : 'bg-blue-50 text-blue-700 border border-blue-200'
                              }`}
                            >
                              {app.environment}
                            </span>
                          </td>

                          <td className="py-3 px-4 font-mono text-slate-600 text-[11px]">
                            {app.key_prefix}
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium ${
                                app.status === 'active'
                                  ? 'bg-emerald-50 text-emerald-700'
                                  : 'bg-slate-100 text-slate-500'
                              }`}
                            >
                              <span className={`w-1.5 h-1.5 rounded-full ${app.status === 'active' ? 'bg-emerald-500' : 'bg-slate-400'}`}></span>
                              <span>{app.status === 'active' ? 'Active' : 'Disabled'}</span>
                            </span>
                          </td>

                          <td className="py-3 px-4 text-slate-500 text-[11px]">
                            {app.last_seen_at ? new Date(app.last_seen_at).toLocaleTimeString() : 'Never'}
                          </td>

                          <td className="py-3 px-4 text-right font-mono font-bold text-slate-800 tabular-nums">
                            {app.total_requests}
                          </td>

                          <td className="py-3 px-4 text-center">
                            <div className="flex items-center justify-center gap-2">
                              {/* Regenerate Key */}
                              <button
                                onClick={() => handleRegenerateKey(app)}
                                className="p-1.5 rounded-md text-slate-500 hover:text-blue-600 hover:bg-blue-50 transition-colors cursor-pointer"
                                title="Regenerate API Key"
                              >
                                <RotateCw className="w-3.5 h-3.5" />
                              </button>

                              {/* Toggle Status */}
                              <button
                                onClick={() => handleToggleStatus(app)}
                                className={`p-1.5 rounded-md transition-colors cursor-pointer ${
                                  app.status === 'active'
                                    ? 'text-slate-500 hover:text-amber-600 hover:bg-amber-50'
                                    : 'text-emerald-600 hover:bg-emerald-50'
                                }`}
                                title={app.status === 'active' ? 'Disable Application' : 'Enable Application'}
                              >
                                <Power className="w-3.5 h-3.5" />
                              </button>

                              {/* Delete App */}
                              <button
                                onClick={() => handleDeleteApp(app)}
                                className="p-1.5 rounded-md text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                                title="Delete Application"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 3: CONNECT GUIDE PAGE */}
        {/* ========================================================================= */}
        {activeTab === 'guide' && (
          <div className="flex flex-col gap-6">
            <div>
              <h2 className="text-lg font-bold text-slate-900 tracking-tight">Connect Any Backend (Integration Guide)</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Copy and paste these pre-configured background middleware snippets into your Node, Python, Java, or PHP apps.
              </p>
            </div>

            {/* Application Pre-filler Dropdown */}
            <div className="bg-white border border-slate-200 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-xs">
              <div className="flex items-center gap-3">
                <span className="text-xs font-semibold text-slate-700">Customize snippet for application:</span>
                <select
                  value={guideSelectedAppId}
                  onChange={(e) => setGuideSelectedAppId(e.target.value)}
                  className="px-3 py-1.5 text-xs font-medium bg-slate-50 border border-slate-300 rounded-lg text-slate-800 focus:border-blue-600 focus:outline-none cursor-pointer"
                >
                  {apps.map((app) => (
                    <option key={app.id} value={app.id}>
                      {app.name} ({app.environment})
                    </option>
                  ))}
                </select>
              </div>

              <div className="text-xs text-slate-500">
                Snippets automatically fill <code className="font-mono text-blue-700 font-semibold">{platformUrl}/api/v1/ingest</code>
              </div>
            </div>

            {/* Language Tabs & Snippet Box */}
            <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs flex flex-col">
              <div className="px-5 py-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
                {/* Language Switcher */}
                <div className="flex items-center gap-1.5">
                  {[
                    { id: 'node', label: 'Node.js / Express' },
                    { id: 'python', label: 'Python (FastAPI / Flask)' },
                    { id: 'java', label: 'Java (Spring Boot Filter)' },
                    { id: 'php', label: 'PHP' },
                  ].map((lang) => (
                    <button
                      key={lang.id}
                      onClick={() => setGuideLanguage(lang.id as any)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                        guideLanguage === lang.id
                          ? 'bg-blue-600 text-white shadow-xs'
                          : 'bg-white text-slate-600 hover:text-slate-900 border border-slate-200'
                      }`}
                    >
                      {lang.label}
                    </button>
                  ))}
                </div>

                {/* Copy Snippet Button */}
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(snippets[guideLanguage]);
                    setCopiedKey(true);
                    setTimeout(() => setCopiedKey(false), 2000);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg shadow-xs cursor-pointer transition-colors"
                >
                  {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey ? 'Copied Snippet!' : 'Copy Code'}</span>
                </button>
              </div>

              {/* Safety Rules Reminder Banner */}
              <div className="px-5 py-2.5 bg-blue-50/70 border-b border-blue-100 text-xs text-blue-900 flex flex-wrap items-center gap-x-6 gap-y-1">
                <span className="flex items-center gap-1 text-blue-950 font-semibold">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-600" /> Safe by Design:
                </span>
                <span>• Dispatched in background batches</span>
                <span>• Short 800ms timeout</span>
                <span>• Drops events if dashboard is down (zero impact on users)</span>
                <span>• Skips static files & /health</span>
                <span>• Only sends metadata, zero bodies or sensitive headers</span>
              </div>

              {/* Code Pre Box */}
              <div className="p-4 bg-slate-950 overflow-x-auto">
                <pre className="text-xs font-mono text-slate-100 leading-relaxed">
                  {snippets[guideLanguage]}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 6: ML TRAINING DATA & EXPORT PAGE (STEP 5) */}
        {/* ========================================================================= */}
        {activeTab === 'ml' && (
          <MlDataView
            apps={apps}
            selectedAppId={selectedAppId}
            authToken={authToken}
            onDataGenerated={() => {
              fetchStats();
              fetchRecords();
              fetchApps();
            }}
          />
        )}

        {/* ========================================================================= */}
        {/* TAB 7: SETTINGS & ALERTS & RETENTION PAGE */}
        {/* ========================================================================= */}
        {activeTab === 'settings' && (
          <SettingsView
            authToken={authToken}
            onSaved={(newSettings) => setPlatformSettings(newSettings)}
          />
        )}
      </main>

      {/* MODAL: REGISTER APP FORM */}
      {isRegisteringApp && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-xl max-w-md w-full p-6 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 mb-4">
              <h3 className="font-bold text-slate-900 text-sm">Register New Application</h3>
              <button
                onClick={() => setIsRegisteringApp(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-600"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleRegisterApp} className="space-y-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Application Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Payments Microservice, Mobile Storefront"
                  value={newAppName}
                  onChange={(e) => setNewAppName(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-lg focus:border-blue-600 focus:outline-none text-slate-900"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Environment</label>
                <div className="grid grid-cols-2 gap-3">
                  <label
                    className={`flex items-center gap-2 p-2.5 rounded-lg border cursor-pointer ${
                      newAppEnv === 'dev' ? 'border-blue-600 bg-blue-50/50 text-blue-900' : 'border-slate-200 text-slate-700'
                    }`}
                  >
                    <input
                      type="radio"
                      name="env"
                      checked={newAppEnv === 'dev'}
                      onChange={() => setNewAppEnv('dev')}
                      className="text-blue-600"
                    />
                    <div>
                      <div className="font-semibold">Development (dev)</div>
                      <div className="text-[10px] text-slate-500">Local or staging backends</div>
                    </div>
                  </label>

                  <label
                    className={`flex items-center gap-2 p-2.5 rounded-lg border cursor-pointer ${
                      newAppEnv === 'prod' ? 'border-blue-600 bg-blue-50/50 text-blue-900' : 'border-slate-200 text-slate-700'
                    }`}
                  >
                    <input
                      type="radio"
                      name="env"
                      checked={newAppEnv === 'prod'}
                      onChange={() => setNewAppEnv('prod')}
                      className="text-blue-600"
                    />
                    <div>
                      <div className="font-semibold">Production (prod)</div>
                      <div className="text-[10px] text-slate-500">Live production cluster</div>
                    </div>
                  </label>
                </div>
              </div>

              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-slate-500 text-[11px] leading-relaxed">
                A 32+ character random API key (<code className="font-mono text-slate-700">sk_live_...</code>) will be generated. The system stores only its SHA-256 hash. The plain key will be revealed to you once.
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsRegisteringApp(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-50 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-xs"
                >
                  Generate Key & Register
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: NEW API KEY (SHOWN ONCE) */}
      {newKeyModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0">
                <Key className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-slate-900 text-sm">Save Your API Key</h3>
                <p className="text-xs text-slate-500">Generated for &quot;{newKeyModal.appName}&quot;</p>
              </div>
            </div>

            <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900 mb-4 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
              <span>
                <strong>Important:</strong> Please copy this API key now. For your security, this key is hashed with SHA-256 and will <strong>never be shown again</strong>.
              </span>
            </div>

            <div className="mb-4">
              <label className="block text-xs font-semibold text-slate-700 mb-1">API Key</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={newKeyModal.plainKey}
                  className="w-full font-mono text-xs px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg select-all text-slate-900 font-semibold"
                />
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(newKeyModal.plainKey);
                    setCopiedKey(true);
                    setTimeout(() => setCopiedKey(false), 2000);
                  }}
                  className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shrink-0 flex items-center gap-1.5 cursor-pointer"
                >
                  {copiedKey ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setNewKeyModal(null)}
                className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
              >
                I have safely stored this key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* INSPECT RECORD MODAL */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-xl">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-900 text-sm flex items-center gap-2 font-mono">
                  <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-bold">{selectedRecord.method}</span>
                  <span className="text-slate-800">{selectedRecord.path}</span>
                  <span className="text-slate-500">({selectedRecord.status_code})</span>
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  Trace ID: <span className="font-mono text-slate-700">{selectedRecord.request_id}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopyJson(selectedRecord)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 transition-colors cursor-pointer"
                >
                  {copiedId ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedId ? 'Copied' : 'Copy JSON'}</span>
                </button>

                <button
                  onClick={() => setSelectedRecord(null)}
                  className="p-1 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3 bg-slate-50 p-4 rounded-lg border border-slate-200 text-[11px]">
                <div>
                  <span className="text-slate-500">Application:</span>{' '}
                  <span className="text-slate-900 font-bold">{selectedRecord.app_name || 'Fake Shop'}</span>
                </div>
                <div>
                  <span className="text-slate-500">Normalized Path:</span>{' '}
                  <span className="text-blue-700 font-semibold">{selectedRecord.normalized_path}</span>
                </div>
                <div>
                  <span className="text-slate-500">Client IP:</span>{' '}
                  <span className="text-slate-800">{selectedRecord.client_ip}</span>
                </div>
                <div>
                  <span className="text-slate-500">Response Latency:</span>{' '}
                  <span className="text-slate-800 font-bold">{selectedRecord.response_time_ms} ms</span>
                </div>
                <div>
                  <span className="text-slate-500">Login Result:</span>{' '}
                  <span className="font-semibold text-slate-800">{selectedRecord.login_result}</span>
                </div>
                <div>
                  <span className="text-slate-500">Threat Rule Flag:</span>{' '}
                  <span className={selectedRecord.threat_rule ? 'text-rose-600 font-bold' : 'text-emerald-600 font-semibold'}>
                    {selectedRecord.threat_rule || 'Normal (No threat)'}
                  </span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-500">Query Param Keys Only:</span>{' '}
                  <span className="text-slate-800">
                    {selectedRecord.query_param_names.length > 0
                      ? selectedRecord.query_param_names.join(', ')
                      : 'None'}
                  </span>
                </div>
                <div className="col-span-2 truncate">
                  <span className="text-slate-500">User Agent:</span>{' '}
                  <span className="text-slate-600">{selectedRecord.user_agent}</span>
                </div>
              </div>

              <div>
                <div className="text-[11px] font-sans font-semibold text-slate-700 mb-1.5 flex items-center justify-between">
                  <span>Exact Recorded Telemetry Object</span>
                  <span className="text-slate-400 font-normal">No passwords, tokens, or query values</span>
                </div>
                <pre className="p-4 bg-slate-900 text-slate-100 rounded-lg overflow-x-auto text-[11px] leading-relaxed">
                  {JSON.stringify(selectedRecord, null, 2)}
                </pre>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3.5 border-t border-slate-200 bg-slate-50 flex justify-end">
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-1.5 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ATTACK SIMULATION RESULTS MODAL */}
      {attackResultModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-xl max-w-md w-full p-6 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-rose-50 text-rose-600 flex items-center justify-center shrink-0">
                <Flame className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-slate-900 text-sm">Attack Simulation Dispatched</h3>
                <p className="text-xs text-slate-500">5 targeted attack scenarios executed</p>
              </div>
            </div>

            <p className="text-xs text-slate-600 mb-4 leading-relaxed">
              The platform dispatched simulated brute force, SQL injection, scraping, fake signup, and path traversal requests. All rules evaluated in memory under <strong>Shadow Mode</strong>.
            </p>

            <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 mb-4">
              <div className="text-[11px] font-bold text-slate-700 uppercase tracking-wider mb-2">
                Fired Threat Rules ({attackResultModal.count}):
              </div>
              <div className="space-y-1.5">
                {attackResultModal.rules.map((ruleName, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs font-semibold text-rose-700">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-600"></span>
                    <span>{ruleName}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
              <button
                onClick={() => setAttackResultModal(null)}
                className="px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-100 rounded-lg transition-colors cursor-pointer"
              >
                Dismiss
              </button>
              <button
                onClick={() => {
                  setAttackResultModal(null);
                  setActiveTab('threats');
                }}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-xs transition-colors cursor-pointer flex items-center gap-1.5"
              >
                <span>View in Threats Registry</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SETTINGS MODAL */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onSaved={(newSettings) => setPlatformSettings(newSettings)}
      />

      {/* REAL-TIME TOAST NOTIFICATIONS */}
      <ToastNotifications
        toasts={toasts}
        onDismiss={(id) => setToasts((prev) => prev.filter((t) => t.id !== id))}
        onViewThreat={() => setActiveTab('threats')}
      />

      {/* FOOTER */}
      <footer className="border-t border-slate-200 bg-white px-6 py-3 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2 shrink-0">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
          <span>Central API Security Ingest Platform Active</span>
          <span aria-hidden="true">·</span>
          <span>Shadow Mode Enabled</span>
          <span aria-hidden="true">·</span>
          <span>{apps.length} Applications Registered</span>
        </div>
        <div className="flex items-center gap-3">
          <span>Auto-refresh: 5s</span>
          <span aria-hidden="true">·</span>
          <span>Rule-Based Detection (13 Rules)</span>
        </div>
      </footer>
    </div>
  );
}
