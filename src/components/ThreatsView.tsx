import React, { useState, useEffect, useCallback, useMemo } from 'react';
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

  return (
    <div className="flex flex-col gap-6">
      {/* Top Banner / Stats Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-slate-900 tracking-tight">Security Threat Registry</h2>
            <span className="text-[11px] font-mono font-medium text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
              SHADOW MODE ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Rules evaluate incoming telemetry in memory. Detections are logged and deduplicated per attacker without blocking real user traffic.
          </p>
        </div>

        {/* Severity Metrics Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-50 border border-rose-200 text-xs">
            <span className="w-2 h-2 rounded-full bg-rose-600"></span>
            <span className="font-semibold text-rose-900">{counts.critical}</span>
            <span className="text-rose-700 font-medium">Critical</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-50 border border-orange-200 text-xs">
            <span className="w-2 h-2 rounded-full bg-orange-500"></span>
            <span className="font-semibold text-orange-900">{counts.high}</span>
            <span className="text-orange-700 font-medium">High</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-50 border border-amber-200 text-xs">
            <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            <span className="font-semibold text-amber-900">{counts.medium}</span>
            <span className="text-amber-700 font-medium">Medium</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-50 border border-blue-200 text-xs">
            <span className="w-2 h-2 rounded-full bg-blue-500"></span>
            <span className="font-semibold text-blue-900">{counts.low}</span>
            <span className="text-blue-700 font-medium">Low</span>
          </div>
          <button
            onClick={fetchThreats}
            className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-slate-100 border border-slate-200 transition-colors cursor-pointer"
            title="Refresh threats"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs flex flex-col md:flex-row gap-3 items-center justify-between">
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
            <option value="ALL">All 13 Rules</option>
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
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-50 text-slate-500 border-b border-slate-200 font-sans uppercase text-[11px] tracking-wider">
              <tr>
                <th className="py-3 px-3.5">Severity</th>
                <th className="py-3 px-3.5">Threat / Rule</th>
                <th className="py-3 px-3.5">Application</th>
                <th className="py-3 px-3.5">Attacker IP</th>
                <th className="py-3 px-3.5 text-center">Hit Count</th>
                <th className="py-3 px-3.5">Safe Evidence</th>
                <th className="py-3 px-3.5">First / Last Seen</th>
                <th className="py-3 px-3.5">Status</th>
                <th className="py-3 px-3.5 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-14 text-center text-slate-400 font-sans">
                    <div className="max-w-sm mx-auto flex flex-col items-center gap-3">
                      <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center">
                        <ShieldCheck className="w-6 h-6" />
                      </div>
                      <div className="font-semibold text-slate-800 text-sm">No Security Threats Recorded</div>
                      <p className="text-xs text-slate-500">
                        {searchQuery || severityFilter !== 'ALL' || statusFilter !== 'ALL'
                          ? 'No threats match your active filter criteria.'
                          : 'No traffic received yet'}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredThreats.map((t) => (
                  <tr
                    key={t.id}
                    onClick={() => setInspectThreat(t)}
                    className="hover:bg-blue-50/40 cursor-pointer transition-colors"
                  >
                    {/* Severity */}
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded border text-[10px] uppercase tracking-wider ${getSeverityBadge(t.severity)}`}>
                        {t.severity}
                      </span>
                    </td>

                    {/* Threat / Rule Name */}
                    <td className="py-3 px-3.5 whitespace-nowrap font-sans">
                      <div className="font-semibold text-slate-900 text-xs">{t.rule_name}</div>
                      <div className="text-[10px] text-slate-400 font-mono">{t.rule_id}</div>
                    </td>

                    {/* Application */}
                    <td className="py-3 px-3.5 whitespace-nowrap font-sans">
                      <span className="bg-slate-100 text-slate-800 px-2 py-0.5 rounded text-[11px] font-medium">
                        {t.app_name}
                      </span>
                    </td>

                    {/* Attacker IP */}
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 text-slate-800">
                        <span className="font-semibold">{t.client_ip}</span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(t.client_ip);
                          }}
                          className="text-slate-400 hover:text-blue-600 transition-colors p-0.5"
                          title="Copy IP"
                        >
                          {copiedIp === t.client_ip ? (
                            <Check className="w-3 h-3 text-emerald-600" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                      {t.hashed_user_id && (
                        <div className="text-[10px] text-slate-400 font-mono truncate max-w-[120px]" title={t.hashed_user_id}>
                          user: {t.hashed_user_id.slice(0, 10)}...
                        </div>
                      )}
                    </td>

                    {/* Hit Count (Deduplication evidence) */}
                    <td className="py-3 px-3.5 whitespace-nowrap text-center">
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-slate-100 text-slate-700 border border-slate-200">
                        ×{t.hit_count} hits
                      </span>
                    </td>

                    {/* Safe Evidence */}
                    <td className="py-3 px-3.5 font-sans text-xs text-slate-600 max-w-[240px] truncate" title={t.evidence}>
                      {t.evidence}
                    </td>

                    {/* Timestamps */}
                    <td className="py-3 px-3.5 whitespace-nowrap text-[11px] text-slate-500">
                      <div>
                        Last: <span className="text-slate-800 font-medium">{t.last_seen.split('T')[1]?.slice(0, 8)}</span>
                      </div>
                      <div className="text-[10px] text-slate-400">
                        First: {t.first_seen.split('T')[1]?.slice(0, 8)}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-3.5 whitespace-nowrap font-sans">
                      <span className={`px-2 py-0.5 rounded-full border text-[11px] font-semibold capitalize ${getStatusBadge(t.status)}`}>
                        {t.status.replace('_', ' ')}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3 px-3.5 whitespace-nowrap text-center font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setInspectThreat(t);
                        }}
                        className="px-2.5 py-1 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-md transition-colors cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert History Table (Step 4) */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/70 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Bell className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 tracking-tight">Alert History</h3>
              <p className="text-[11px] text-slate-500">
                Webhook alert delivery log (3s timeout, up to 2 retries, deduplicated per 30m + 100-hit milestones)
              </p>
            </div>
          </div>
          <span className="text-xs text-slate-500 font-mono">{alertHistory.length} deliveries</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-50 text-slate-500 border-b border-slate-200 font-sans uppercase text-[11px] tracking-wider">
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
                        <span className={`px-1.5 py-0.5 rounded border text-[10px] uppercase font-bold ${getSeverityBadge(entry.severity)}`}>
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
                      <span className="text-[11px] px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                        {entry.trigger_reason === 'milestone_100_hits'
                          ? '100-Hit Milestone'
                          : entry.trigger_reason === 'test_alert'
                          ? 'Test Alert'
                          : 'New Threat'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap font-sans">
                      {entry.status === 'sent' ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>sent ({entry.attempts} {entry.attempts === 1 ? 'try' : 'tries'})</span>
                        </span>
                      ) : (
                        <div className="flex items-center gap-2">
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                            <XCircle className="w-3 h-3" />
                            <span>failed ({entry.attempts} {entry.attempts === 1 ? 'try' : 'tries'})</span>
                          </span>
                          {entry.error && (
                            <span className="text-[11px] text-rose-600 font-mono truncate max-w-[180px]" title={entry.error}>
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
          <div className="bg-white rounded-xl max-w-xl w-full border border-slate-200 shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-slate-200 bg-slate-50">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg border ${getSeverityBadge(inspectThreat.severity)}`}>
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 text-sm tracking-tight">{inspectThreat.rule_name}</h3>
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
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 flex flex-col gap-4 text-xs font-sans">
              {/* Evidence Box */}
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
                <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                  Safe Evidence Summary (No credentials or secret values)
                </div>
                <div className="font-mono text-slate-800 bg-white p-2.5 rounded border border-slate-200 text-xs break-all">
                  {inspectThreat.evidence}
                </div>
              </div>

              {/* Threat Details Grid */}
              <div className="grid grid-cols-2 gap-3 font-mono">
                <div className="bg-slate-50 p-2.5 rounded border border-slate-100">
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider font-sans block">Client IP</span>
                  <span className="text-slate-900 font-bold text-xs">{inspectThreat.client_ip}</span>
                </div>
                <div className="bg-slate-50 p-2.5 rounded border border-slate-100">
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider font-sans block">Hit Count (De-duplicated)</span>
                  <span className="text-blue-700 font-bold text-xs">×{inspectThreat.hit_count} occurrences</span>
                </div>
                <div className="bg-slate-50 p-2.5 rounded border border-slate-100">
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider font-sans block">First Seen</span>
                  <span className="text-slate-700 text-xs">{new Date(inspectThreat.first_seen).toLocaleString()}</span>
                </div>
                <div className="bg-slate-50 p-2.5 rounded border border-slate-100">
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider font-sans block">Last Seen</span>
                  <span className="text-slate-700 text-xs">{new Date(inspectThreat.last_seen).toLocaleString()}</span>
                </div>
              </div>

              {/* Status Management Actions */}
              <div className="pt-2 border-t border-slate-200">
                <label className="block text-xs font-bold text-slate-700 mb-2">
                  Update Threat Lifecycle Status:
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <button
                    disabled={isUpdatingStatus || inspectThreat.status === 'open'}
                    onClick={() => handleUpdateStatus(inspectThreat.id, 'open')}
                    className={`px-3 py-2 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
                      inspectThreat.status === 'open'
                        ? 'bg-rose-600 text-white border-rose-600 shadow-xs'
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
                        ? 'bg-amber-600 text-white border-amber-600 shadow-xs'
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
                        ? 'bg-emerald-600 text-white border-emerald-600 shadow-xs'
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
                        ? 'bg-slate-700 text-white border-slate-700 shadow-xs'
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
