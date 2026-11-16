import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  CheckCircle2,
  AlertCircle,
  Sliders,
  Save,
  RotateCcw,
  Zap,
  Info,
  Clock,
  Tag,
  ToggleLeft,
  ToggleRight,
} from 'lucide-react';
import { ThreatRule, ThreatSeverity } from '../types/threats';

export function RulesView() {
  const [rules, setRules] = useState<ThreatRule[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [editingThreshold, setEditingThreshold] = useState<{ [ruleId: string]: number }>({});
  const [savedFeedback, setSavedFeedback] = useState<{ [ruleId: string]: string }>({});
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Fetch Rules from GET /api/threats/rules
  const fetchRules = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/threats/rules');
      if (res.ok) {
        const data = await res.json();
        setRules(data.rules || []);
        const initialThresholds: { [key: string]: number } = {};
        (data.rules || []).forEach((r: ThreatRule) => {
          initialThresholds[r.id] = r.threshold;
        });
        setEditingThreshold(initialThresholds);
      }
    } catch (err) {
      setErrorMsg('Failed to load rules.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  // Toggle Rule Enabled / Disabled
  const handleToggleRule = async (rule: ThreatRule) => {
    try {
      const newEnabled = !rule.enabled;
      const res = await fetch(`/api/threats/rules/${rule.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newEnabled }),
      });
      if (res.ok) {
        const data = await res.json();
        setRules((prev) => prev.map((r) => (r.id === rule.id ? data.rule : r)));
        showFeedback(rule.id, newEnabled ? 'Rule enabled' : 'Rule disabled');
      }
    } catch {
      setErrorMsg('Failed to toggle rule.');
    }
  };

  // Update Rule Threshold
  const handleSaveThreshold = async (ruleId: string) => {
    const thresholdVal = editingThreshold[ruleId];
    if (thresholdVal === undefined || thresholdVal < 1) return;

    try {
      const res = await fetch(`/api/threats/rules/${ruleId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threshold: thresholdVal }),
      });
      if (res.ok) {
        const data = await res.json();
        setRules((prev) => prev.map((r) => (r.id === ruleId ? data.rule : r)));
        showFeedback(ruleId, `Threshold updated to ${thresholdVal}`);
      }
    } catch {
      setErrorMsg('Failed to update threshold.');
    }
  };

  const showFeedback = (ruleId: string, msg: string) => {
    setSavedFeedback((prev) => ({ ...prev, [ruleId]: msg }));
    setTimeout(() => {
      setSavedFeedback((prev) => {
        const copy = { ...prev };
        delete copy[ruleId];
        return copy;
      });
    }, 2500);
  };

  const getSeverityBadge = (sev: ThreatSeverity) => {
    switch (sev) {
      case 'critical':
        return 'bg-rose-100 text-rose-800 border-rose-300';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'medium':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-300';
    }
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-slate-900 tracking-tight">Threat Detection Rules (13 Rules)</h2>
            <span className="text-[11px] font-mono font-medium text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
              rules.json
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Rules are stored in <code className="font-mono text-slate-700 font-semibold">rules.json</code> and editable at runtime without code deployment. All rules run in shadow mode.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="font-semibold text-slate-700">
            {rules.filter((r) => r.enabled).length} of {rules.length} Active
          </span>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-700 flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-rose-500 hover:text-rose-800">×</button>
        </div>
      )}

      {/* Rules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map((rule) => {
          const isEnabled = rule.enabled;
          const currentVal = editingThreshold[rule.id] ?? rule.threshold;
          const hasChanged = currentVal !== rule.threshold;

          return (
            <div
              key={rule.id}
              className={`bg-white border rounded-xl p-5 shadow-xs transition-all flex flex-col justify-between ${
                isEnabled ? 'border-slate-200' : 'border-slate-200 bg-slate-50/60 opacity-75'
              }`}
            >
              <div>
                {/* Header: Name, Severity, and Toggle */}
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-900 text-sm">{rule.name}</span>
                      <span className={`px-2 py-0.5 rounded border text-[10px] uppercase font-bold tracking-wider ${getSeverityBadge(rule.severity)}`}>
                        {rule.severity}
                      </span>
                    </div>
                    <div className="text-[10px] font-mono text-slate-400 mt-0.5">{rule.id}</div>
                  </div>

                  {/* Toggle Switch */}
                  <button
                    onClick={() => handleToggleRule(rule)}
                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold transition-all cursor-pointer border ${
                      isEnabled
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-slate-200 text-slate-600 border-slate-300'
                    }`}
                  >
                    <span>{isEnabled ? 'ENABLED' : 'DISABLED'}</span>
                  </button>
                </div>

                {/* OWASP Tag */}
                <div className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-50 border border-blue-200 text-[11px] font-medium text-blue-700 mb-3">
                  <Tag className="w-3 h-3" />
                  <span>{rule.owasp_tag}</span>
                </div>

                {/* Description */}
                <p className="text-xs text-slate-600 mb-4 leading-relaxed">
                  {rule.description}
                </p>
              </div>

              {/* Bottom Config: Window & Editable Threshold */}
              <div className="pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-1.5 text-xs text-slate-500">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  <span>Window:</span>
                  <span className="font-mono font-semibold text-slate-700">
                    {rule.window_seconds >= 60 ? `${rule.window_seconds / 60}m` : `${rule.window_seconds}s`}
                  </span>
                </div>

                {/* Threshold input */}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-500">Threshold:</span>
                  <div className="flex items-center gap-1">
                    <input
                      type="number"
                      min={1}
                      max={1000}
                      value={currentVal}
                      onChange={(e) =>
                        setEditingThreshold((prev) => ({
                          ...prev,
                          [rule.id]: Math.max(1, parseInt(e.target.value) || 1),
                        }))
                      }
                      className="w-16 px-2 py-1 text-xs font-mono font-bold text-center bg-slate-50 border border-slate-200 rounded focus:outline-none focus:ring-1 focus:ring-blue-500 text-slate-800"
                    />
                    {hasChanged && (
                      <button
                        onClick={() => handleSaveThreshold(rule.id)}
                        className="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-semibold cursor-pointer shadow-xs"
                        title="Save threshold"
                      >
                        <Save className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                {savedFeedback[rule.id] && (
                  <div className="w-full text-right text-[11px] font-medium text-emerald-600 animate-in fade-in">
                    ✓ {savedFeedback[rule.id]}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
