import React from 'react';
import { Activity, AlertTriangle, Check, CheckCircle2, ChevronDown, Clock, Copy, Download, ExternalLink, Globe, Layers, Lock, Search, ShieldAlert, X } from 'lucide-react';
import { ResponsiveContainer, LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';

export interface TrafficRecord {
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

export interface DashboardStats {
  total_requests: number;
  error_rate: number;
  failed_logins: number;
  avg_response_time_ms: number;
  status_code_breakdown: { '2xx': number; '3xx': number; '4xx': number; '5xx': number };
  requests_per_minute: Array<{ time: string; timestamp: number; requests: number; errors: number }>;
  top_endpoints: Array<{ endpoint: string; count: number; percentage: number }>;
  top_client_ips: Array<{ ip: string; count: number; percentage: number }>;
  slowest_endpoints: Array<{ endpoint: string; avg_response_time_ms: number; count: number }>;
  generated_at: string;
  selected_app_id: string | null;
  open_threats_by_severity?: { critical: number; high: number; medium: number; low: number; total: number };
}

interface DashboardViewProps {
  apps: Array<{ id: string; name: string; environment: 'dev' | 'prod'; status: 'active' | 'disabled' }>;
  selectedAppId: string;
  setSelectedAppId: (value: string) => void;
  setActiveTab: (value: 'threats') => void;
  stats: DashboardStats | null;
  topEndpointsChartData: Array<{ name: string; fullName: string; requests: number; percentage: number }>;
  requestsPerMinuteChartData: Array<{ time: string; requests: number; errors: number }>;
  statusBreakdownData: Array<{ name: string; count: number; fill: string }>;
  records: TrafficRecord[];
  methodFilter: string;
  setMethodFilter: (value: string) => void;
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  searchQuery: string;
  setSearchQuery: (value: string) => void;
  setSelectedRecord: (record: TrafficRecord | null) => void;
  selectedRecord: TrafficRecord | null;
  copiedId: boolean;
  handleCopyJson: (record: TrafficRecord) => void;
}

export function DashboardView({ apps, selectedAppId, setSelectedAppId, setActiveTab, stats, topEndpointsChartData, requestsPerMinuteChartData, statusBreakdownData, records, methodFilter, setMethodFilter, statusFilter, setStatusFilter, searchQuery, setSearchQuery, setSelectedRecord, selectedRecord, copiedId, handleCopyJson }: DashboardViewProps) {
  return (
    <>

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

            {(stats?.total_requests ?? 0) === 0 ? (
              <div className="bg-white border border-slate-200 rounded-xl p-12 text-center shadow-xs">
                <Activity className="w-10 h-10 mx-auto text-blue-600 mb-3" />
                <p className="text-sm font-semibold text-slate-800">No traffic received yet</p>
              </div>
            ) : (
            <>
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
                            <div className="font-semibold text-slate-800">No traffic received yet</div>
                            <p className="text-xs text-slate-500">
                              Register an app and send real traffic to see requests here.
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
                                {r.app_name || 'Unknown application'}
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
          </>

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
                  <span className="text-slate-900 font-bold">{selectedRecord.app_name || 'Unknown application'}</span>
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


    </>
  );
}
