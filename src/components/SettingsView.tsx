import React, { useState, useEffect } from 'react';
import {
  Sliders,
  Shield,
  Bell,
  Webhook,
  Send,
  Check,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Info,
  Database,
  Trash2,
  Flame,
  Sparkles,
} from 'lucide-react';
import { PlatformSettings, ThreatSeverity, AlertHistoryEntry } from '../types/threats';

interface SettingsViewProps {
  authToken?: string | null;
  onSaved?: (settings: PlatformSettings) => void;
  onAlertSent?: () => void;
  selectedAppId?: string;
  onSimulateAttack?: () => Promise<void>;
  onTestingDataGenerated?: () => void;
}

export function SettingsView({
  authToken,
  onSaved,
  onAlertSent,
  selectedAppId = 'ALL',
  onSimulateAttack,
  onTestingDataGenerated,
}: SettingsViewProps) {
  const [settings, setSettings] = useState<PlatformSettings>({
    mode: 'shadow',
    notify_on_high_critical: true,
    alert_webhook_url: '',
    alert_min_severity: 'high',
    alert_dedup_minutes: 30,
    raw_traffic_retention_days: 30,
    feature_retention_days: 90,
  });
  const [isRunningCleanup, setIsRunningCleanup] = useState(false);
  const [cleanupMessage, setCleanupMessage] = useState<string | null>(null);
  const [envWebhookConfigured, setEnvWebhookConfigured] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [isTestingAlert, setIsTestingAlert] = useState(false);
  const [testAlertResult, setTestAlertResult] = useState<{
    success: boolean;
    message: string;
    entry?: AlertHistoryEntry;
  } | null>(null);
  const [isGeneratingSampleData, setIsGeneratingSampleData] = useState(false);
  const [testingToolsMessage, setTestingToolsMessage] = useState<string | null>(null);

  useEffect(() => {
    async function loadSettings() {
      try {
        const res = await fetch('/api/threats/settings');
        if (res.ok) {
          const data = await res.json();
          if (data.settings) {
            setSettings({
              mode: data.settings.mode || 'shadow',
              notify_on_high_critical: data.settings.notify_on_high_critical !== false,
              alert_webhook_url: data.settings.alert_webhook_url || '',
              alert_min_severity: data.settings.alert_min_severity || 'high',
              alert_dedup_minutes:
                data.settings.alert_dedup_minutes !== undefined
                  ? data.settings.alert_dedup_minutes
                  : 30,
              raw_traffic_retention_days:
                data.settings.raw_traffic_retention_days !== undefined
                  ? data.settings.raw_traffic_retention_days
                  : 30,
              feature_retention_days:
                data.settings.feature_retention_days !== undefined
                  ? data.settings.feature_retention_days
                  : 90,
            });
          }
          setEnvWebhookConfigured(Boolean(data.env_webhook_configured));
        }
      } catch (err) {
        console.error('Failed to load settings:', err);
      }
    }
    loadSettings();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSaveMessage(null);
    try {
      const res = await fetch('/api/threats/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      if (res.ok) {
        const data = await res.json();
        setSettings(data.settings);
        setSaveMessage('Settings saved successfully.');
        if (onSaved) onSaved(data.settings);
        setTimeout(() => setSaveMessage(null), 3000);
      }
    } catch (err) {
      console.error('Failed to save settings:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleSendTestAlert = async () => {
    setIsTestingAlert(true);
    setTestAlertResult(null);
    try {
      const res = await fetch('/api/threats/alerts/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          webhook_url: settings.alert_webhook_url,
        }),
      });
      const data = await res.json();
      setTestAlertResult({
        success: Boolean(data.success),
        message: data.message || (data.success ? 'Test alert sent!' : 'Test alert failed.'),
        entry: data.entry,
      });
      if (onAlertSent) onAlertSent();
    } catch (err: any) {
      setTestAlertResult({
        success: false,
        message: err?.message || 'Failed to send test alert.',
      });
    } finally {
      setIsTestingAlert(false);
    }
  };

  const handleRunCleanupNow = async () => {
    if (!authToken) return;
    setIsRunningCleanup(true);
    setCleanupMessage(null);
    try {
      const res = await fetch('/api/v1/export/cleanup-now', {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` },
      });
      const data = await res.json();
      if (res.ok) {
        setCleanupMessage(data.message || 'Retention cleanup completed.');
      } else {
        setCleanupMessage(data.error || 'Cleanup failed.');
      }
    } catch (err: any) {
      setCleanupMessage(err?.message || 'Cleanup failed.');
    } finally {
      setIsRunningCleanup(false);
    }
  };

  const handleGenerateSampleData = async () => {
    if (!authToken) return;
    setIsGeneratingSampleData(true);
    setTestingToolsMessage(null);
    try {
      const res = await fetch('/api/v1/export/simulate-training-data', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({ app_id: selectedAppId }),
      });
      const data = await res.json();
      if (!res.ok) {
        setTestingToolsMessage(data.error || 'Failed to generate sample training data.');
        return;
      }
      setTestingToolsMessage(data.message || 'Generated sample training data.');
      onTestingDataGenerated?.();
    } catch (err: any) {
      setTestingToolsMessage(err?.message || 'Unable to generate sample training data.');
    } finally {
      setIsGeneratingSampleData(false);
    }
  };

  return (
    <form onSubmit={handleSave} className="flex flex-col gap-6 max-w-4xl">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="w-5 h-5 text-blue-600" />
            <h2 className="text-lg font-bold text-slate-900 tracking-tight">Platform Settings</h2>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Configure global threat detection mode and automated webhook alerting. Stored in <code className="font-mono text-slate-700">settings.json</code>.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {saveMessage && (
            <span className="text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-1.5 rounded-lg flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{saveMessage}</span>
            </span>
          )}
          <button
            type="submit"
            disabled={isSaving}
            className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg shadow-xs transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <Check className="w-3.5 h-3.5" />
            <span>{isSaving ? 'Saving...' : 'Save Settings'}</span>
          </button>
        </div>
      </div>

      {/* SECTION 1: ALERTS CONFIGURATION */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/70 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Webhook className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 tracking-tight">Alerts & Webhook Notifications</h3>
              <p className="text-[11px] text-slate-500">
                Dispatches background alerts (3s timeout, up to 2 retries) for new threats & 100-hit milestones
              </p>
            </div>
          </div>
        </div>

        <div className="p-5 flex flex-col gap-5 text-xs">
          {/* Webhook URL */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="font-bold text-slate-800">
                Webhook URL (Slack, Discord, Telegram, or any HTTP endpoint)
              </label>
              {envWebhookConfigured && (
                <span className="text-[10px] font-mono font-medium text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                  ALERT_WEBHOOK_URL env detected
                </span>
              )}
            </div>
            <div className="flex flex-col sm:flex-row gap-2.5">
              <input
                type="url"
                value={settings.alert_webhook_url || ''}
                onChange={(e) => setSettings((prev) => ({ ...prev, alert_webhook_url: e.target.value }))}
                placeholder="https://hooks.slack.com/services/... or https://discord.com/api/webhooks/..."
                className="flex-1 px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white text-slate-900 placeholder:text-slate-400"
              />
              <button
                type="button"
                onClick={handleSendTestAlert}
                disabled={isTestingAlert}
                className="px-4 py-2 text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg transition-colors cursor-pointer disabled:opacity-50 flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                <Send className={`w-3.5 h-3.5 ${isTestingAlert ? 'animate-pulse' : ''}`} />
                <span>{isTestingAlert ? 'Sending...' : 'Send test alert'}</span>
              </button>
            </div>
            <p className="text-[11px] text-slate-500 mt-1.5">
              Configured from this dashboard or via the <code className="font-mono text-slate-700">ALERT_WEBHOOK_URL</code> environment variable. Alert payloads never include secrets, query parameter values, or request bodies.
            </p>

            {testAlertResult && (
              <div
                className={`mt-3 p-3 rounded-lg border text-xs flex items-start gap-2 ${
                  testAlertResult.success
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                    : 'bg-rose-50 border-rose-200 text-rose-800'
                }`}
              >
                {testAlertResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="font-semibold">{testAlertResult.message}</div>
                  {testAlertResult.entry && (
                    <div className="text-[11px] opacity-80 font-mono mt-0.5">
                      Attempts: {testAlertResult.entry.attempts} · Status: {testAlertResult.entry.status}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2 border-t border-slate-100">
            {/* Minimum Severity */}
            <div>
              <label className="block font-bold text-slate-800 mb-1.5">
                Minimum Severity to Alert
              </label>
              <select
                value={settings.alert_min_severity || 'high'}
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    alert_min_severity: e.target.value as ThreatSeverity,
                  }))
                }
                className="w-full px-3 py-2 text-xs font-semibold bg-slate-50 border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
              >
                <option value="critical">Critical only</option>
                <option value="high">High &amp; Critical (Default)</option>
                <option value="medium">Medium, High &amp; Critical</option>
                <option value="low">All Severities (Low and above)</option>
              </select>
              <p className="text-[11px] text-slate-500 mt-1.5">
                Only newly detected threats meeting or exceeding this severity trigger a webhook alert.
              </p>
            </div>

            {/* Deduplication Window */}
            <div>
              <label className="block font-bold text-slate-800 mb-1.5">
                Alert De-duplication Window (Minutes)
              </label>
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-slate-400 shrink-0" />
                <input
                  type="number"
                  min={0}
                  max={1440}
                  value={settings.alert_dedup_minutes ?? 30}
                  onChange={(e) =>
                    setSettings((prev) => ({
                      ...prev,
                      alert_dedup_minutes: Math.max(0, parseInt(e.target.value || '0', 10)),
                    }))
                  }
                  className="w-28 px-3 py-2 text-xs font-mono font-bold bg-slate-50 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-slate-900"
                />
                <span className="text-xs text-slate-500">minutes per attacker + rule</span>
              </div>
              <p className="text-[11px] text-slate-500 mt-1.5">
                Default: 30 minutes. Later hits only increment the hit count, with 1 extra alert sent at 100 hits.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* SECTION 2: DETECTION MODE & TOASTS */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/70 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 tracking-tight">Detection Operating Mode</h3>
            <p className="text-[11px] text-slate-500">Shadow Mode never blocks live traffic</p>
          </div>
        </div>

        <div className="p-5 flex flex-col gap-4 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label
              onClick={() => setSettings((prev) => ({ ...prev, mode: 'shadow' }))}
              className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-all ${
                settings.mode === 'shadow'
                  ? 'border-blue-500 bg-blue-50/50 ring-1 ring-blue-500'
                  : 'border-slate-200 hover:bg-slate-50'
              }`}
            >
              <input
                type="radio"
                name="operating_mode_view"
                checked={settings.mode === 'shadow'}
                onChange={() => setSettings((prev) => ({ ...prev, mode: 'shadow' }))}
                className="mt-0.5 text-blue-600"
              />
              <div>
                <div className="font-bold text-slate-900 flex items-center gap-1.5">
                  <span>Shadow Mode</span>
                  <span className="text-[10px] font-mono font-medium text-emerald-700 bg-emerald-50 px-1.5 py-0.2 rounded border border-emerald-200">
                    RECOMMENDED
                  </span>
                </div>
                <p className="text-slate-500 text-[11px] mt-1 leading-relaxed">
                  Evaluates requests in background. Records threat telemetry without ever blocking or delaying user requests.
                </p>
              </div>
            </label>

            <label
              onClick={() => setSettings((prev) => ({ ...prev, mode: 'alert_only' }))}
              className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-all ${
                settings.mode === 'alert_only'
                  ? 'border-amber-500 bg-amber-50/50 ring-1 ring-amber-500'
                  : 'border-slate-200 hover:bg-slate-50'
              }`}
            >
              <input
                type="radio"
                name="operating_mode_view"
                checked={settings.mode === 'alert_only'}
                onChange={() => setSettings((prev) => ({ ...prev, mode: 'alert_only' }))}
                className="mt-0.5 text-amber-600"
              />
              <div>
                <div className="font-bold text-slate-900">Alert-Only Mode</div>
                <p className="text-slate-500 text-[11px] mt-1 leading-relaxed">
                  Non-blocking evaluation with high-visibility alert dispatch for SOC responders.
                </p>
              </div>
            </label>
          </div>

          <div className="pt-3 border-t border-slate-100">
            <label className="flex items-center justify-between cursor-pointer">
              <div className="flex items-center gap-2.5">
                <Bell className="w-4 h-4 text-slate-500" />
                <div>
                  <span className="font-bold text-slate-800 text-xs block">Dashboard Live Toast Notifications</span>
                  <span className="text-[11px] text-slate-500">Show top-right toast alerts for High &amp; Critical threats</span>
                </div>
              </div>
              <input
                type="checkbox"
                checked={settings.notify_on_high_critical}
                onChange={(e) =>
                  setSettings((prev) => ({ ...prev, notify_on_high_critical: e.target.checked }))
                }
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500 cursor-pointer"
              />
            </label>
          </div>
        </div>
      </div>

      {/* TESTING TOOLS */}
      <details className="bg-white border border-amber-200 rounded-xl overflow-hidden shadow-xs">
        <summary className="px-5 py-4 bg-amber-50/70 flex items-center gap-2.5 cursor-pointer list-none">
          <div className="w-8 h-8 rounded-lg bg-amber-100 border border-amber-200 flex items-center justify-center text-amber-700">
            <Flame className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 tracking-tight">Testing Tools</h3>
            <p className="text-[11px] text-amber-800 font-medium">
              This sends FAKE traffic for testing. Do not use this if you only want real data.
            </p>
          </div>
        </summary>
        <div className="p-5 flex flex-wrap items-center gap-3 text-xs">
          <button
            type="button"
            onClick={() => void onSimulateAttack?.()}
            disabled={!onSimulateAttack}
            className="px-3.5 py-2 font-semibold text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200 rounded-lg transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
          >
            <Flame className="w-3.5 h-3.5 text-rose-600" />
            <span>Attack Simulator</span>
          </button>
          <button
            type="button"
            onClick={() => void handleGenerateSampleData()}
            disabled={isGeneratingSampleData || !authToken}
            className="px-3.5 py-2 font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
          >
            <Sparkles className={`w-3.5 h-3.5 text-blue-600 ${isGeneratingSampleData ? 'animate-pulse' : ''}`} />
            <span>{isGeneratingSampleData ? 'Generating Samples...' : 'Generate sample training data'}</span>
          </button>
          {testingToolsMessage && (
            <span className="text-[11px] font-medium text-slate-600">{testingToolsMessage}</span>
          )}
        </div>
      </details>

      {/* SECTION 3: DATA RETENTION & CLEANUP (STEP 5) */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/70 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Database className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 tracking-tight">Data Retention &amp; Daily Clean-up</h3>
              <p className="text-[11px] text-slate-500">
                Automatic daily background job prunes expired records from <code className="font-mono">traffic.jsonl</code> and <code className="font-mono">features.jsonl</code>
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={handleRunCleanupNow}
            disabled={isRunningCleanup || !authToken}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
          >
            <Trash2 className="w-3.5 h-3.5 text-slate-500" />
            <span>{isRunningCleanup ? 'Cleaning...' : 'Run cleanup now'}</span>
          </button>
        </div>

        <div className="p-5 flex flex-col gap-4 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div>
              <label className="block font-bold text-slate-800 mb-1.5">
                Raw Traffic Retention (Days)
              </label>
              <input
                type="number"
                min={1}
                max={3650}
                value={settings.raw_traffic_retention_days ?? 30}
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    raw_traffic_retention_days: Math.max(1, parseInt(e.target.value || '30', 10)),
                  }))
                }
                className="w-32 px-3 py-2 text-xs font-mono font-bold bg-slate-50 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-slate-900"
              />
              <p className="text-[11px] text-slate-500 mt-1.5">
                Days to keep raw request metadata in <code className="font-mono">traffic.jsonl</code> (default: 30 days).
              </p>
            </div>

            <div>
              <label className="block font-bold text-slate-800 mb-1.5">
                ML Feature Rows Retention (Days)
              </label>
              <input
                type="number"
                min={1}
                max={3650}
                value={settings.feature_retention_days ?? 90}
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    feature_retention_days: Math.max(1, parseInt(e.target.value || '90', 10)),
                  }))
                }
                className="w-32 px-3 py-2 text-xs font-mono font-bold bg-slate-50 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-slate-900"
              />
              <p className="text-[11px] text-slate-500 mt-1.5">
                Days to keep 1m/5m/1h aggregated ML feature rows in <code className="font-mono">features.jsonl</code> (default: 90 days).
              </p>
            </div>
          </div>

          {cleanupMessage && (
            <div className="p-3 rounded-lg bg-blue-50 border border-blue-200 text-blue-900 text-xs font-medium">
              {cleanupMessage}
            </div>
          )}
        </div>
      </div>
    </form>
  );
}
