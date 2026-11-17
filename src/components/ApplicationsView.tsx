import React from 'react';
import { AlertTriangle, Check, Copy, Eye, EyeOff, Key, Layers, Plus, Power, RotateCw, Trash2, X } from 'lucide-react';

export interface RegisteredApp {
  id: string;
  name: string;
  environment: 'dev' | 'prod';
  key_prefix: string;
  status: 'active' | 'disabled';
  created_at: string;
  last_seen_at: string | null;
  total_requests: number;
  key_history: Array<{ old_key_prefix: string | null; new_key_prefix: string; rotated_at: string }>;
}

interface NewKeyModal { appId: string; appName: string; plainKey: string }
interface ApplicationsViewProps {
  apps: RegisteredApp[];
  setIsRegisteringApp: (value: boolean) => void;
  handleRegisterApp: (event: React.FormEvent) => void;
  handleRegenerateKey: (app: RegisteredApp) => void;
  handleToggleStatus: (app: RegisteredApp) => void;
  handleDeleteApp: (app: RegisteredApp) => void;
  isRegisteringApp: boolean;
  newAppName: string;
  setNewAppName: (value: string) => void;
  newAppEnv: 'dev' | 'prod';
  setNewAppEnv: (value: 'dev' | 'prod') => void;
  newKeyModal: NewKeyModal | null;
  isKeyVisible: boolean;
  setIsKeyVisible: React.Dispatch<React.SetStateAction<boolean>>;
  copiedKey: boolean;
  setCopiedKey: (value: boolean) => void;
  closeKeyDialog: () => void;
}

export function ApplicationsView({ apps, setIsRegisteringApp, handleRegisterApp, handleRegenerateKey, handleToggleStatus, handleDeleteApp, isRegisteringApp, newAppName, setNewAppName, newAppEnv, setNewAppEnv, newKeyModal, isKeyVisible, setIsKeyVisible, copiedKey, setCopiedKey, closeKeyDialog }: ApplicationsViewProps) {
  return (
    <>

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
            <div className="bg-white border border-slate-200 rounded-md overflow-hidden">
              <div className="px-4 py-3 bg-blue-50 border-b border-blue-100 text-xs text-blue-900">
                For your safety, we only store a scrambled version of your key. We can never show it to you again after you close this box — if you lose it, regenerate instead.
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-semibold text-xs">
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
                          No apps registered yet. Click &quot;Register app&quot; to connect your first real app.
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
                              className={`px-2 py-0.5 rounded text-xs font-semibold uppercase font-mono ${
                                app.environment === 'prod'
                                  ? 'bg-purple-50 text-purple-700 border border-purple-200'
                                  : 'bg-blue-50 text-blue-700 border border-blue-200'
                              }`}
                            >
                              {app.environment}
                            </span>
                          </td>

                          <td className="py-3 px-4 font-mono text-slate-600 text-xs">
                            <div>{app.key_prefix}</div>
                            {app.key_history.length > 0 && (
                              <details className="mt-1 font-sans">
                                <summary className="text-xs text-blue-600 cursor-pointer">Key history ({app.key_history.length})</summary>
                                <div className="mt-1 space-y-1 text-xs text-slate-500">
                                  {app.key_history.map((rotation) => (
                                    <div key={`${rotation.rotated_at}-${rotation.new_key_prefix}`}>
                                      {rotation.old_key_prefix} → {rotation.new_key_prefix} · {new Date(rotation.rotated_at).toLocaleString()}
                                    </div>
                                  ))}
                                </div>
                              </details>
                            )}
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${
                                app.status === 'active'
                                  ? 'bg-emerald-50 text-emerald-700'
                                  : 'bg-slate-100 text-slate-500'
                              }`}
                            >
                              <span className={`w-1.5 h-1.5 rounded-full ${app.status === 'active' ? 'bg-emerald-500' : 'bg-slate-400'}`}></span>
                              <span>{app.status === 'active' ? 'Active' : 'Disabled'}</span>
                            </span>
                          </td>

                          <td className="py-3 px-4 text-slate-500 text-xs">
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
      {/* MODAL: REGISTER APP FORM */}
      {isRegisteringApp && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-lg max-w-md w-full p-6 shadow-xl">
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
                      <div className="text-xs text-slate-500">Local or staging backends</div>
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
                      <div className="text-xs text-slate-500">Live production cluster</div>
                    </div>
                  </label>
                </div>
              </div>

              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-slate-500 text-xs leading-relaxed">
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
                  className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold"
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
          <div className="bg-white border border-slate-200 rounded-lg max-w-lg w-full p-6 shadow-2xl">
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
                <strong>Copy this now — you won't be able to see it again. The old key stops working immediately.</strong>
              </span>
            </div>

            <div className="mb-4">
              <label className="block text-xs font-semibold text-slate-700 mb-1">API Key</label>
              <div className="flex items-center gap-2">
                <input
                  type={isKeyVisible ? 'text' : 'password'}
                  readOnly
                  value={newKeyModal.plainKey}
                  className="w-full font-mono text-xs px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg select-all text-slate-900 font-semibold"
                />
                <button
                  type="button"
                  onClick={() => setIsKeyVisible((visible) => !visible)}
                  className="p-2 text-slate-500 hover:text-blue-600 border border-slate-300 rounded-lg cursor-pointer"
                  title={isKeyVisible ? 'Hide API key' : 'Show API key'}
                >
                  {isKeyVisible ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
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
                onClick={closeKeyDialog}
                className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
              >
                Close — I have safely stored this key
              </button>
            </div>
          </div>
        </div>
      )}


    </>
  );
}
