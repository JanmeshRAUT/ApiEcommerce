import React, { useState, useEffect, useCallback } from 'react';
import {
  Database,
  Download,
  Sparkles,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  Filter,
  Tag,
  UserCheck,
  Bot,
} from 'lucide-react';
import { FeatureRow, FeatureWindowSize } from '../types/threats';

interface MlDataViewProps {
  apps: Array<{ id: string; name: string; environment: string }>;
  selectedAppId: string;
  authToken: string | null;
  onDataGenerated?: () => void;
}

interface PreviewResponse {
  total_rows: number;
  preview_rows: FeatureRow[];
  label_counts: Record<string, number>;
  source_counts: { rule: number; human: number };
  imbalance_warning: string | null;
}

export function MlDataView({ apps, selectedAppId, authToken, onDataGenerated }: MlDataViewProps) {
  const [filterAppId, setFilterAppId] = useState<string>(selectedAppId || 'ALL');
  const [windowSize, setWindowSize] = useState<'ALL' | FeatureWindowSize>('ALL');
  const [startDate, setStartDate] = useState<string>('');
  const [endDate, setEndDate] = useState<string>('');
  const [exportFormat] = useState<'csv'>('csv');

  const [preview, setPreview] = useState<PreviewResponse>({
    total_rows: 0,
    preview_rows: [],
    label_counts: {},
    source_counts: { rule: 0, human: 0 },
    imbalance_warning: null,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    setFilterAppId(selectedAppId || 'ALL');
  }, [selectedAppId]);

  const buildQueryParams = useCallback(() => {
    const params = new URLSearchParams();
    if (filterAppId && filterAppId !== 'ALL') params.append('app_id', filterAppId);
    if (windowSize && windowSize !== 'ALL') params.append('window_size', windowSize);
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    return params.toString();
  }, [filterAppId, windowSize, startDate, endDate]);

  const fetchPreview = useCallback(async () => {
    if (!authToken) return;
    setIsLoading(true);
    try {
      const qs = buildQueryParams();
      const res = await fetch(`/api/v1/export/features/preview${qs ? `?${qs}` : ''}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data: PreviewResponse = await res.json();
        setPreview(data);
      }
    } catch (err) {
      console.error('Failed to load ML feature preview:', err);
    } finally {
      setIsLoading(false);
    }
  }, [authToken, buildQueryParams]);

  useEffect(() => {
    fetchPreview();
  }, [fetchPreview]);

  const handleGenerateSampleData = async () => {
    if (!authToken) return;
    setIsGenerating(true);
    setStatusMessage(null);
    try {
      const res = await fetch('/api/v1/export/simulate-training-data', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({ app_id: filterAppId }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setStatusMessage({
          type: 'success',
          text: data.message || 'Generated mixed normal + attack training data.',
        });
        await fetchPreview();
        if (onDataGenerated) onDataGenerated();
      } else {
        setStatusMessage({
          type: 'error',
          text: data.error || 'Failed to generate sample training data.',
        });
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err?.message || 'Unable to generate training data.',
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExtractNow = async () => {
    if (!authToken) return;
    setIsLoading(true);
    setStatusMessage(null);
    try {
      const res = await fetch('/api/v1/export/extract-now', {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` },
      });
      const data = await res.json();
      if (res.ok) {
        setStatusMessage({
          type: 'success',
          text: data.message || 'Extracted latest features.',
        });
        await fetchPreview();
      }
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: err?.message || 'Extraction failed.' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportCsv = async () => {
    if (!authToken) return;
    setIsExporting(true);
    setStatusMessage(null);
    try {
      const qs = buildQueryParams();
      const res = await fetch(`/api/v1/export/features.csv${qs ? `?${qs}` : ''}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        setStatusMessage({
          type: 'error',
          text: errData.error || `Export failed (HTTP ${res.status}).`,
        });
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const suffix = windowSize !== 'ALL' ? `_${windowSize}` : '';
      a.download = `api_security_features${suffix}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      setStatusMessage({
        type: 'success',
        text: `Exported ${preview.total_rows} feature rows as CSV.`,
      });
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err?.message || 'CSV export failed.',
      });
    } finally {
      setIsExporting(false);
    }
  };

  const labelEntries = Object.entries(preview.label_counts).sort((a, b) => b[1] - a[1]);

  return (
    <div className="flex flex-col gap-6">
      {/* HEADER BAR */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900 tracking-tight">ML Training Data &amp; Feature Export</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Metadata-only aggregated window features (<code className="font-mono text-slate-700">features.jsonl</code>) with rule &amp; human labels.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={handleExtractNow}
            disabled={isLoading}
            className="px-3 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 border border-slate-200 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5"
            title="Extract feature rows right now from recent in-memory requests"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-slate-600 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh / Extract Now</span>
          </button>

          <button
            type="button"
            onClick={handleGenerateSampleData}
            disabled={isGenerating}
            className="px-3.5 py-2 text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
          >
            <Sparkles className={`w-3.5 h-3.5 text-blue-600 ${isGenerating ? 'animate-pulse' : ''}`} />
            <span>{isGenerating ? 'Generating Samples...' : 'Generate sample training data'}</span>
          </button>

          <button
            type="button"
            onClick={handleExportCsv}
            disabled={isExporting || preview.total_rows === 0}
            className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg shadow-xs transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{isExporting ? 'Exporting...' : 'Export training data'}</span>
          </button>
        </div>
      </div>

      {/* ACTION FEEDBACK MESSAGE */}
      {statusMessage && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center gap-2.5 ${
            statusMessage.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
              : 'bg-rose-50 border-rose-200 text-rose-800'
          }`}
        >
          {statusMessage.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
          )}
          <span className="font-medium">{statusMessage.text}</span>
        </div>
      )}

      {/* FILTER OPTIONS */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
        <div className="flex items-center gap-2 mb-3 text-xs font-bold text-slate-800">
          <Filter className="w-3.5 h-3.5 text-blue-600" />
          <span>Dataset Selection &amp; Export Options</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 text-xs">
          <div>
            <label className="block font-semibold text-slate-600 mb-1">Application</label>
            <select
              value={filterAppId}
              onChange={(e) => setFilterAppId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-800 font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
            >
              <option value="ALL">All Applications</option>
              {apps.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.name} ({app.environment})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block font-semibold text-slate-600 mb-1">Window Size</label>
            <select
              value={windowSize}
              onChange={(e) => setWindowSize(e.target.value as 'ALL' | FeatureWindowSize)}
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-800 font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
            >
              <option value="ALL">All Windows (1m, 5m, 1h)</option>
              <option value="1m">1 Minute (1m)</option>
              <option value="5m">5 Minutes (5m)</option>
              <option value="1h">1 Hour (1h)</option>
            </select>
          </div>

          <div>
            <label className="block font-semibold text-slate-600 mb-1">Start Date</label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-800 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block font-semibold text-slate-600 mb-1">End Date</label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-800 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block font-semibold text-slate-600 mb-1">Export Format</label>
            <select
              value={exportFormat}
              disabled
              className="w-full px-3 py-2 bg-slate-100 border border-slate-300 rounded-lg text-slate-700 font-semibold cursor-not-allowed"
            >
              <option value="csv">CSV (features.csv)</option>
            </select>
          </div>
        </div>
      </div>

      {/* IMBALANCE WARNING */}
      {preview.imbalance_warning && (
        <div className="bg-amber-50 border border-amber-300 text-amber-900 rounded-xl p-4 flex items-start gap-3 text-xs shadow-xs">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold text-amber-950">Unbalanced Training Dataset Warning</div>
            <p className="mt-0.5 text-amber-800 leading-relaxed">{preview.imbalance_warning}</p>
          </div>
        </div>
      )}

      {/* LABEL COUNTS & SUMMARY CARDS */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-2">
            <Tag className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-bold text-slate-900">Row Counts per Label</h3>
            <span className="text-xs font-mono font-semibold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded">
              {preview.total_rows} total rows
            </span>
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-600">
            <span className="inline-flex items-center gap-1 bg-slate-100 px-2.5 py-1 rounded-md font-medium">
              <Bot className="w-3.5 h-3.5 text-blue-600" />
              Rule-labeled: <strong className="font-mono text-slate-900">{preview.source_counts.rule}</strong>
            </span>
            <span className="inline-flex items-center gap-1 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-md font-medium text-emerald-800">
              <UserCheck className="w-3.5 h-3.5 text-emerald-600" />
              Human-corrected: <strong className="font-mono">{preview.source_counts.human}</strong>
            </span>
          </div>
        </div>

        {labelEntries.length === 0 ? (
          <div className="text-xs text-slate-500 py-4 text-center bg-slate-50 rounded-lg border border-dashed border-slate-200">
            No feature rows stored yet. Click <strong>&quot;Generate sample training data&quot;</strong> above or wait for the 1-minute background extraction job.
          </div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {labelEntries.map(([lbl, count]) => {
              const pct = preview.total_rows > 0 ? ((count / preview.total_rows) * 100).toFixed(1) : '0.0';
              const isNormal = lbl === 'normal';
              return (
                <div
                  key={lbl}
                  className={`p-3 rounded-lg border ${
                    isNormal
                      ? 'bg-emerald-50/50 border-emerald-200'
                      : 'bg-rose-50/50 border-rose-200'
                  }`}
                >
                  <div
                    className={`text-[11px] font-mono font-bold truncate ${
                      isNormal ? 'text-emerald-800' : 'text-rose-800'
                    }`}
                    title={lbl}
                  >
                    {lbl}
                  </div>
                  <div className="flex items-baseline justify-between mt-1">
                    <span className="text-xl font-bold font-mono text-slate-900 tabular-nums">{count}</span>
                    <span className="text-[11px] font-mono text-slate-500">{pct}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* PREVIEW TABLE: FIRST 20 ROWS */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/70 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-slate-900">Dataset Preview (First 20 Rows)</h3>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Endpoint: <code className="font-mono text-blue-700">GET /api/v1/export/features.csv</code> (Admin auth required)
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            Showing {preview.preview_rows.length} of {preview.total_rows} rows
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[11px]">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-semibold">
                <th className="py-2.5 px-3 whitespace-nowrap">Win</th>
                <th className="py-2.5 px-3 whitespace-nowrap">App</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Client IP</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Req Count</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">4xx Rate</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">5xx Rate</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Uniq EP</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Uniq UID</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Fail Login</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Avg Gap (ms)</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Avg RT (ms)</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Avg/Max Req Sz</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">POST Ratio</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Night Ratio</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Uniq UA</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Label</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono">
              {preview.preview_rows.length === 0 ? (
                <tr>
                  <td colSpan={17} className="py-10 text-center text-slate-400 font-sans text-xs">
                    No matching ML feature rows found for the selected filters.
                  </td>
                </tr>
              ) : (
                preview.preview_rows.map((row) => {
                  const isNormal = row.label === 'normal';
                  return (
                    <tr key={row.feature_id} className="hover:bg-blue-50/40 transition-colors">
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-bold">
                          {row.window_size}
                        </span>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap font-sans font-medium text-slate-800">
                        {row.app_name}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap text-slate-600">{row.client_ip}</td>
                      <td className="py-2 px-3 text-right tabular-nums font-bold text-slate-900">
                        {row.request_count}
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">
                        {row.error_rate_4xx.toFixed(2)}
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">
                        {row.error_rate_5xx.toFixed(2)}
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">{row.unique_endpoints}</td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">{row.unique_user_ids}</td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">{row.failed_logins}</td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">
                        {row.avg_gap_between_requests_ms}
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">
                        {row.avg_response_time_ms}
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-600 whitespace-nowrap">
                        {row.avg_request_size} / {row.max_request_size}
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">
                        {row.post_ratio.toFixed(2)}
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">
                        {row.night_time_ratio.toFixed(2)}
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums text-slate-700">{row.unique_user_agents}</td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded font-bold border ${
                            isNormal
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                              : 'bg-rose-50 text-rose-700 border-rose-200'
                          }`}
                        >
                          {row.label}
                        </span>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`px-1.5 py-0.5 rounded font-semibold ${
                            row.label_source === 'human'
                              ? 'bg-indigo-50 text-indigo-700 border border-indigo-200'
                              : 'bg-slate-100 text-slate-600'
                          }`}
                        >
                          {row.label_source}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
