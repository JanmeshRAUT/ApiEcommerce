import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  Layers,
  ExternalLink,
  X,
  Copy,
  Check,
  RefreshCw,
  Eye,
  ShieldCheck,
  XCircle,
  Bell,
  Webhook,
} from 'lucide-react';
import { ThreatRecord, ThreatSeverity, ThreatStatus, ThreatRule, AlertHistoryEntry } from '../types/threats';
import { getThreatReasoning } from '../data/threatReasoning';

interface ThreatsViewProps {
  apps: Array<{ id: string; name: string }>;
  selectedAppId: string;
  onSelectApp: (id: string) => void;
  onThreatsUpdated?: () => void;
  initialThreatId?: string | null;
}

export function ThreatsView({ apps, selectedAppId, onThreatsUpdated, initialThreatId }: ThreatsViewProps) {
  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [alertHistory, setAlertHistory] = useState<AlertHistoryEntry[]>([]);
  const [rules, setRules] = useState<ThreatRule[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [ruleFilter, setRuleFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Selected Threat for Inspection / Status update
  const [inspectThreat, setInspectThreat] = useState<ThreatRecord | null>(null);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [statusToast, setStatusToast] = useState<{ threatId: string; message: string; previousStatus: ThreatStatus } | null>(null);
  const inspectDialogRef = useRef<HTMLDivElement>(null);
  const inspectTriggerRef = useRef<HTMLTableRowElement | null>(null);

  // Fetch Threats
  const fetchThreats = useCallback(async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      if (selectedAppId && selectedAppId !== 'ALL') params.append('app_id', selectedAppId);
      if (severityFilter !== 'ALL') params.append('severity', severityFilter);
      if (statusFilter !== 'ALL') params.append('status', statusFilter);
      if (ruleFilter !== 'ALL') params.append('rule_id', ruleFilter);

      const [threatsRes, historyRes] = await Promise.all([
        fetch(`/api/threats?${params.toString()}`),
        fetch('/api/threats/alerts/history?limit=100'),
      ]);

      if (threatsRes.ok) {
        const data = await threatsRes.json();
        const loadedThreats: ThreatRecord[] = data.threats || [];
        setThreats(loadedThreats);
        if (initialThreatId) {
          const match = loadedThreats.find((t) => t.id === initialThreatId);
          if (match) setInspectThreat(match);
        }
      }
      if (historyRes.ok) {
        const hData = await historyRes.json();
        setAlertHistory(hData.history || []);
      }
    } catch (err) {
      console.error('Failed to fetch threats:', err);
    } finally {
      setIsLoading(false);
    }
  }, [selectedAppId, severityFilter, statusFilter, ruleFilter, initialThreatId]);

  // Fetch Rules for filter dropdown
  useEffect(() => {
    async function loadRules() {
      try {
        const res = await fetch('/api/threats/rules');
        if (res.ok) {
          const data = await res.json();
          setRules(data.rules || []);
        }
      } catch (err) {
        console.error('Failed to load rules for filter:', err);
      }
    }
    loadRules();
  }, []);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  // Handle status update
  const handleUpdateStatus = async (threatId: string, newStatus: ThreatStatus) => {
    setIsUpdatingStatus(true);
    try {
      const previousThreat = threats.find((threat) => threat.id === threatId);
      const res = await fetch(`/api/threats/${threatId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        const data = await res.json();
        setThreats((prev) =>
          prev.map((t) => (t.id === threatId ? data.threat : t))
        );
        if (inspectThreat && inspectThreat.id === threatId) {
          setInspectThreat(data.threat);
        }
        if (onThreatsUpdated) onThreatsUpdated();
        if (previousThreat && previousThreat.status !== newStatus) {
          setStatusToast({
            threatId,
            previousStatus: previousThreat.status,
            message: `Threat marked ${newStatus.replace('_', ' ')}`,
          });
          window.setTimeout(() => setStatusToast(null), 5000);
        }
      }
    } catch (err) {
      console.error('Failed to update threat status:', err);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIp(text);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // Filtered threats including search query
  const filteredThreats = useMemo(() => {
    if (!searchQuery.trim()) return threats;
    const q = searchQuery.toLowerCase();
    return threats.filter(
      (t) =>
        t.client_ip.toLowerCase().includes(q) ||
        t.rule_name.toLowerCase().includes(q) ||
        t.evidence.toLowerCase().includes(q) ||
        t.id.toLowerCase().includes(q) ||
        t.app_name.toLowerCase().includes(q)
    );
  }, [threats, searchQuery]);

  // Summary counts
  const counts = useMemo(() => {
    const res = { critical: 0, high: 0, medium: 0, low: 0, open: 0, total: threats.length };
    threats.forEach((t) => {
      if (t.status === 'open') res.open++;
      if (t.severity === 'critical') res.critical++;
      if (t.severity === 'high') res.high++;
      if (t.severity === 'medium') res.medium++;
      if (t.severity === 'low') res.low++;
    });
    return res;
  }, [threats]);
  const newestThreat = threats[0];
  const openHighCritical = threats.filter((threat) => threat.status === 'open' && (threat.severity === 'critical' || threat.severity === 'high')).length;
  const hasActiveFilters = Boolean(searchQuery.trim()) || severityFilter !== 'ALL' || statusFilter !== 'ALL' || ruleFilter !== 'ALL';
  const clearFilters = () => {
    setSearchQuery('');
    setSeverityFilter('ALL');
    setStatusFilter('ALL');
    setRuleFilter('ALL');
  };
  const formatRelativeTime = (timestamp: string) => {
    const elapsedMinutes = Math.max(0, Math.floor((Date.now() - new Date(timestamp).getTime()) / 60000));
    if (elapsedMinutes < 1) return 'just now';
    if (elapsedMinutes < 60) return `${elapsedMinutes} min ago`;
    const elapsedHours = Math.floor(elapsedMinutes / 60);
    if (elapsedHours < 24) return `${elapsedHours} hr ago`;
    return `${Math.floor(elapsedHours / 24)} days ago`;
  };

  useEffect(() => {
    if (!inspectThreat) return;
    const dialog = inspectDialogRef.current;
    dialog?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setInspectThreat(null);
        inspectTriggerRef.current?.focus();
      }
      if (event.key === 'Tab' && dialog) {
        const focusable = dialog.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [inspectThreat]);

  const getSeverityBadge = (sev: ThreatSeverity) => {
    switch (sev) {
      case 'critical':
        return 'bg-rose-100 text-rose-800 border-rose-300 font-bold';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-300 font-bold';
      case 'medium':
        return 'bg-amber-100 text-amber-800 border-amber-300 font-semibold';
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-300 font-medium';
    }
  };

  const getStatusBadge = (st: ThreatStatus) => {
    switch (st) {
      case 'open':
        return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'acknowledged':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'resolved':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'false_positive':
        return 'bg-slate-100 text-slate-600 border-slate-300';
    }
  };
  const inspectReasoning = inspectThreat ? getThreatReasoning(inspectThreat) : null;

  return (
    <div className="flex flex-col gap-6">
      {statusToast && (
        <div className="fixed bottom-5 right-5 z-40 flex items-center gap-3 rounded-lg bg-slate-900 px-4 py-3 text-xs text-white shadow-xl" role="status">
          <span>{statusToast.message}</span>
          <button
            onClick={() => {
              void handleUpdateStatus(statusToast.threatId, statusToast.previousStatus);
              setStatusToast(null);
            }}
            className="font-semibold text-blue-200 hover:text-white underline cursor-pointer"
          >
            Undo
          </button>
          <button onClick={() => setStatusToast(null)} aria-label="Dismiss notification" className="text-slate-300 hover:text-white cursor-pointer">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
      {/* Top Banner / Stats Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-white border border-slate-200 rounded-lg p-5">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-slate-900 tracking-tight">Security Threat Registry</h2>
            <span className="text-xs font-mono font-medium text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
              MONITORING ONLY
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Rules evaluate incoming telemetry in memory. Detections are logged and deduplicated per attacker without blocking real user traffic.
          </p>
        </div>

        {/* Severity Metrics Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={() => setSeverityFilter('critical')} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-50 border border-rose-200 text-xs hover:bg-rose-100 cursor-pointer">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-700" aria-hidden="true" />
            <span className="font-semibold text-rose-900">{counts.critical}</span>
            <span className="text-rose-700 font-medium">Critical</span>
          </button>
          <button onClick={() => setSeverityFilter('high')} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-50 border border-orange-200 text-xs hover:bg-orange-100 cursor-pointer">
            <ShieldAlert className="w-3.5 h-3.5 text-orange-700" aria-hidden="true" />
            <span className="font-semibold text-orange-900">{counts.high}</span>
            <span className="text-orange-700 font-medium">High</span>
          </button>
          <button onClick={() => setSeverityFilter('medium')} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-50 border border-amber-200 text-xs hover:bg-amber-100 cursor-pointer">
            <Clock className="w-3.5 h-3.5 text-amber-700" aria-hidden="true" />
            <span className="font-semibold text-amber-900">{counts.medium}</span>
            <span className="text-amber-700 font-medium">Medium</span>
          </button>
          <button onClick={() => setSeverityFilter('low')} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-50 border border-blue-200 text-xs hover:bg-blue-100 cursor-pointer">
            <CheckCircle2 className="w-3.5 h-3.5 text-blue-700" aria-hidden="true" />
            <span className="font-semibold text-blue-900">{counts.low}</span>
            <span className="text-blue-700 font-medium">Low</span>
          </button>
          <button
            onClick={fetchThreats}
            className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-slate-100 border border-slate-200 transition-colors cursor-pointer"
            title="Refresh threats"
            aria-label="Refresh threats"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      <div className="bg-slate-900 text-white rounded-lg p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-300">Needs attention</div>
          <div className="mt-1 text-sm font-semibold">
            {openHighCritical} open critical/high threats
            {newestThreat && <span className="text-slate-300 font-normal"> · Newest: {newestThreat.rule_name}</span>}
          </div>
        </div>
        <button
          onClick={() => {
            setStatusFilter('open');
            setSeverityFilter('ALL');
          }}
          className="inline-flex items-center justify-center gap-2 px-3 py-2 text-xs font-semibold bg-white text-slate-900 hover:bg-slate-100 rounded-md cursor-pointer"
        >
          <Eye className="w-3.5 h-3.5" aria-hidden="true" />
          Review open threats
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-white border border-slate-200 rounded-lg p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          {/* Search */}
          <div className="relative min-w-[200px] flex-1 md:flex-initial">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search IP, rule, ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white text-slate-800 placeholder-slate-400"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer font-medium"
          >
            <option value="ALL">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer font-medium"
          >
            <option value="ALL">All Statuses</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>

          {/* Rule Filter */}
          <select
            value={ruleFilter}
            onChange={(e) => setRuleFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer font-medium max-w-[180px] truncate"
          >
            <option value="ALL">All {rules.length || 'available'} Rules</option>
            {rules.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
        </div>

        <div className="text-xs text-slate-500 whitespace-nowrap self-end md:self-center">
          Showing <span className="font-semibold text-slate-900">{filteredThreats.length}</span> threat records
        </div>
      </div>

      {/* Threats Table */}
      <div className="bg-white border border-slate-200 rounded-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 border-b border-slate-200 font-sans uppercase text-xs tracking-wider">
              <tr>
                <th className="py-3 px-3.5">Severity</th>
                <th className="py-3 px-3.5">Threat</th>
                <th className="py-3 px-3.5">Who</th>
                <th className="py-3 px-3.5">Activity</th>
                <th className="py-3 px-3.5">Status</th>
                <th className="py-3 px-3.5 text-right"><span className="sr-only">Open details</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {isLoading ? (
                Array.from({ length: 4 }).map((_, index) => (
                  <tr key={`skeleton-${index}`} aria-hidden="true">
                    {Array.from({ length: 6 }).map((__, cellIndex) => (
                      <td key={cellIndex} className="py-4 px-3.5">
                        <div className="h-3 rounded bg-slate-200 animate-pulse" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-14 text-center text-slate-500 font-sans">
                    <div className="max-w-sm mx-auto flex flex-col items-center gap-3">
                      <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-700 flex items-center justify-center">
                        <ShieldCheck className="w-6 h-6" aria-hidden="true" />
                      </div>
                      <div className="font-semibold text-slate-800 text-sm">
                        {hasActiveFilters ? 'No results for these filters' : 'No threats yet — you’re all clear'}
                      </div>
                      <p className="text-xs text-slate-600">
                        {hasActiveFilters ? 'Try clearing a filter to see more threat records.' : 'Incoming detections will appear here when the monitor finds one.'}
                      </p>
                      {hasActiveFilters && (
                        <button onClick={clearFilters} className="px-3 py-1.5 text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-md cursor-pointer">
                          Clear filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredThreats.map((t) => (
                  <tr
                    key={t.id}
                    ref={(row) => {
                      if (inspectThreat?.id === t.id) inspectTriggerRef.current = row;
                    }}
                    onClick={() => {
                      inspectTriggerRef.current = document.activeElement as HTMLTableRowElement;
                      setInspectThreat(t);
                    }}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        inspectTriggerRef.current = event.currentTarget;
                        setInspectThreat(t);
                      }
                    }}
                    tabIndex={0}
                    className="hover:bg-blue-50/40 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-xs uppercase tracking-wider ${getSeverityBadge(t.severity)}`}>
                        {t.severity === 'critical' || t.severity === 'high' ? <AlertTriangle className="w-3 h-3" aria-hidden="true" /> : <ShieldCheck className="w-3 h-3" aria-hidden="true" />}
                        {t.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3.5 min-w-[220px] font-sans">
                      <div className="font-semibold text-slate-900 text-xs">{t.rule_name}</div>
                      <div className="text-xs text-slate-600 truncate max-w-[320px]" title={t.evidence}>{t.evidence}</div>
                    </td>
                    <td className="py-3 px-3.5 min-w-[150px] font-sans">
                      <div className="font-medium text-slate-800">{t.app_name}</div>
                      <div className="flex items-center gap-1 text-xs text-slate-600">
                        <span className="font-mono">{t.client_ip}</span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(t.client_ip);
                          }}
                          className="text-slate-600 hover:text-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 rounded p-0.5"
                          title="Copy IP"
                          aria-label={`Copy IP ${t.client_ip}`}
                        >
                          {copiedIp === t.client_ip ? <Check className="w-3 h-3 text-emerald-700" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    </td>
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <div className="font-semibold text-slate-800">×{t.hit_count} hits</div>
                      <time className="text-xs text-slate-600" dateTime={t.last_seen} title={new Date(t.last_seen).toLocaleString()}>
                        Last seen {formatRelativeTime(t.last_seen)}
                      </time>
                    </td>
                    <td className="py-3 px-3.5 whitespace-nowrap font-sans">
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-semibold capitalize ${getStatusBadge(t.status)}`}>
                        {t.status === 'resolved' ? <CheckCircle2 className="w-3 h-3" aria-hidden="true" /> : t.status === 'open' ? <AlertTriangle className="w-3 h-3" aria-hidden="true" /> : <Clock className="w-3 h-3" aria-hidden="true" />}
                        {t.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-3 px-3.5 text-right">
                      <span className="inline-flex p-1.5 text-slate-500" aria-hidden="true">›</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert History Table (Step 4) */}
      <div className="bg-white border border-slate-200 rounded-md overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/70 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Bell className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 tracking-tight">Alert History</h3>
              <p className="text-xs text-slate-500">
                Webhook alert delivery log (3s timeout, up to 2 retries, deduplicated per 30m + 100-hit milestones)
              </p>
            </div>
          </div>
          <span className="text-xs text-slate-500 font-mono">{alertHistory.length} deliveries</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-50 text-slate-500 border-b border-slate-200 font-sans uppercase text-xs tracking-wider">
              <tr>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Threat</th>
                <th className="py-3 px-4">Application &amp; IP</th>
                <th className="py-3 px-4">Trigger</th>
                <th className="py-3 px-4">Status (Sent / Failed)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {alertHistory.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-10 text-center text-slate-400 font-sans">
                    No webhook alerts dispatched yet. Configure a Webhook URL in Settings and click &quot;Send test alert&quot; or trigger a High/Critical threat.
                  </td>
                </tr>
              ) : (
                alertHistory.map((entry) => (
                  <tr key={entry.id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-2.5 px-4 whitespace-nowrap text-slate-600 tabular-nums">
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4 font-sans">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded border text-xs uppercase font-bold ${getSeverityBadge(entry.severity)}`}>
                          {entry.severity}
                        </span>
                        <span className="font-semibold text-slate-900">{entry.rule_name}</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-4 text-slate-600 whitespace-nowrap">
                      <span className="font-sans font-medium text-slate-800">{entry.app_name}</span>
                      <span className="text-slate-300 mx-1.5">·</span>
                      <span>{entry.client_ip}</span>
                    </td>
                    <td className="py-2.5 px-4 font-sans whitespace-nowrap">
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                        {entry.trigger_reason === 'milestone_100_hits'
                          ? '100-Hit Milestone'
                          : entry.trigger_reason === 'test_alert'
                          ? 'Test Alert'
                          : 'New Threat'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap font-sans">
                      {entry.status === 'sent' ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>sent ({entry.attempts} {entry.attempts === 1 ? 'try' : 'tries'})</span>
                        </span>
                      ) : (
                        <div className="flex items-center gap-2">
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                            <XCircle className="w-3 h-3" />
                            <span>failed ({entry.attempts} {entry.attempts === 1 ? 'try' : 'tries'})</span>
                          </span>
                          {entry.error && (
                            <span className="text-xs text-rose-600 font-mono truncate max-w-[180px]" title={entry.error}>
                              {entry.error}
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Inspection / Status Update Modal */}
      {inspectThreat && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div ref={inspectDialogRef} role="dialog" aria-modal="true" aria-labelledby="threat-dialog-title" tabIndex={-1} className="bg-white rounded-md max-w-xl w-full border border-slate-200 shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-slate-200 bg-slate-50">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg border ${getSeverityBadge(inspectThreat.severity)}`}>
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <h3 id="threat-dialog-title" className="font-bold text-slate-900 text-sm tracking-tight">{inspectThreat.rule_name}</h3>
                  <div className="flex items-center gap-2 text-xs text-slate-500 mt-0.5">
                    <span className="font-mono text-slate-600">{inspectThreat.id}</span>
                    <span>·</span>
                    <span>App: <strong className="text-slate-700">{inspectThreat.app_name}</strong></span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setInspectThreat(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition-colors"
                aria-label="Close threat details"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 flex flex-col gap-4 text-xs font-sans">
              {inspectReasoning && (
                <section className="space-y-3" aria-labelledby="threat-reasoning-title">
                  <h4 id="threat-reasoning-title" className="text-sm font-bold text-slate-900">{inspectReasoning.headline}</h4>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div><div className="font-bold text-slate-700">What happened</div><p className="mt-1 text-slate-600">{inspectReasoning.whatHappened}</p></div>
                    <div><div className="font-bold text-slate-700">Why flagged</div><p className="mt-1 text-slate-600">{inspectReasoning.whyFlagged}</p></div>
                    <div><div className="font-bold text-slate-700">Risk</div><p className="mt-1 text-slate-600">{inspectReasoning.risk}</p></div>
                    <div><div className="font-bold text-slate-700">Could be a false alarm</div><p className="mt-1 text-slate-600">{inspectReasoning.falseAlarm}</p></div>
                  </div>
                  <div>
                    <div className="font-bold text-slate-700">Recommended actions <span className="font-normal text-slate-500">({inspectReasoning.confidence} confidence)</span></div>
                    <ul className="mt-1 list-disc pl-5 text-slate-600 space-y-0.5">
                      {inspectReasoning.actions.map((action) => <li key={action}>{action}</li>)}
                    </ul>
                  </div>
                </section>
              )}
              {/* Evidence Box */}
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-1">
                  What we saw (No credentials or secret values)
                </div>
                <div className="font-mono text-slate-800 bg-white p-2.5 rounded border border-slate-200 text-xs break-all">
                  {inspectThreat.evidence}
                </div>
              </div>

              {/* Threat Details Grid */}
              <div className="grid grid-cols-2 gap-3 font-mono">
                <div className="bg-slate-50 p-2.5 rounded border border-slate-100">
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-sans block">Client IP</span>
                  <span className="text-slate-900 font-bold text-xs">{inspectThreat.client_ip}</span>
                </div>
                <div className="bg-slate-50 p-2.5 rounded border border-slate-100">
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-sans block">Hit Count (De-duplicated)</span>
                  <span className="text-blue-700 font-bold text-xs">×{inspectThreat.hit_count} occurrences</span>
                </div>
                <div className="bg-slate-50 p-2.5 rounded border border-slate-100">
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-sans block">First Seen</span>
                  <span className="text-slate-700 text-xs">{new Date(inspectThreat.first_seen).toLocaleString()}</span>
                </div>
                <div className="bg-slate-50 p-2.5 rounded border border-slate-100">
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-sans block">Last Seen</span>
                  <span className="text-slate-700 text-xs">{new Date(inspectThreat.last_seen).toLocaleString()}</span>
                </div>
              </div>

              {/* Status Management Actions */}
              <div className="pt-2 border-t border-slate-200">
                <label className="block text-xs font-bold text-slate-700 mb-2">
                  Update Status:
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <button
                    disabled={isUpdatingStatus || inspectThreat.status === 'open'}
                    onClick={() => handleUpdateStatus(inspectThreat.id, 'open')}
                    className={`px-3 py-2 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
                      inspectThreat.status === 'open'
                        ? 'bg-rose-600 text-white border-rose-600'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-rose-50 hover:text-rose-700'
                    }`}
                  >
                    Open
                  </button>

                  <button
                    disabled={isUpdatingStatus || inspectThreat.status === 'acknowledged'}
                    onClick={() => handleUpdateStatus(inspectThreat.id, 'acknowledged')}
                    className={`px-3 py-2 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
                      inspectThreat.status === 'acknowledged'
                        ? 'bg-amber-600 text-white border-amber-600'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-amber-50 hover:text-amber-700'
                    }`}
                  >
                    Acknowledged
                  </button>

                  <button
                    disabled={isUpdatingStatus || inspectThreat.status === 'resolved'}
                    onClick={() => handleUpdateStatus(inspectThreat.id, 'resolved')}
                    className={`px-3 py-2 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
                      inspectThreat.status === 'resolved'
                        ? 'bg-emerald-600 text-white border-emerald-600'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-emerald-50 hover:text-emerald-700'
                    }`}
                  >
                    Resolved
                  </button>

                  <button
                    disabled={isUpdatingStatus || inspectThreat.status === 'false_positive'}
                    onClick={() => handleUpdateStatus(inspectThreat.id, 'false_positive')}
                    className={`px-3 py-2 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
                      inspectThreat.status === 'false_positive'
                        ? 'bg-slate-700 text-white border-slate-700'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-100 hover:text-slate-900'
                    }`}
                  >
                    False Positive
                  </button>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 bg-slate-50 border-t border-slate-200 flex justify-end">
              <button
                onClick={() => setInspectThreat(null)}
                className="px-4 py-2 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
