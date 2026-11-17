import React from 'react';
import { AlertTriangle, ShieldAlert, X, ArrowRight } from 'lucide-react';
import { ThreatRecord } from '../types/threats';

interface ToastNotificationsProps {
  toasts: ThreatRecord[];
  onDismiss: (id: string) => void;
  onViewThreat: (threat: ThreatRecord) => void;
}

export function ToastNotifications({ toasts, onDismiss, onViewThreat }: ToastNotificationsProps) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2.5 max-w-sm w-full pointer-events-none">
      {toasts.map((threat) => {
        const isCritical = threat.severity === 'critical';

        return (
          <div
            key={threat.id}
            className={`pointer-events-auto rounded-lg p-4 shadow-xl border backdrop-blur-xs transition-all animate-in slide-in-from-top-2 duration-200 ${
              isCritical
                ? 'bg-rose-900/95 text-white border-rose-700 shadow-rose-900/20'
                : 'bg-slate-900/95 text-white border-amber-600/80 shadow-slate-900/30'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-2.5">
                <div
                  className={`p-1.5 rounded-lg shrink-0 ${
                    isCritical ? 'bg-rose-800 text-rose-200' : 'bg-amber-500/20 text-amber-400'
                  }`}
                >
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${
                        isCritical ? 'bg-rose-800 text-rose-200' : 'bg-amber-400/20 text-amber-300'
                      }`}
                    >
                      {threat.severity}
                    </span>
                    <span className="text-xs font-bold leading-tight">{threat.rule_name}</span>
                  </div>
                  <div className="text-xs text-slate-300 mt-1 font-mono">
                    IP: <span className="text-white font-semibold">{threat.client_ip}</span> · App:{' '}
                    <span className="text-white">{threat.app_name}</span>
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5 line-clamp-1">{threat.evidence}</div>
                </div>
              </div>

              <button
                onClick={() => onDismiss(threat.id)}
                className="text-slate-400 hover:text-white p-1 rounded transition-colors"
                title="Dismiss"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="mt-3 pt-2.5 border-t border-white/10 flex items-center justify-between text-xs">
              <span className="text-slate-400 font-mono text-xs">
                {threat.hit_count > 1 ? `×${threat.hit_count} hits` : 'Just detected'}
              </span>
              <button
                onClick={() => {
                  onViewThreat(threat);
                  onDismiss(threat.id);
                }}
                className="font-semibold text-blue-300 hover:text-white flex items-center gap-1 transition-colors cursor-pointer"
              >
                <span>Investigate in Threats</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
