import React from 'react';
import { Lock, ShieldCheck, ShieldAlert, Calendar, CheckCircle2, AlertTriangle, Key } from 'lucide-react';
import { TlsResultRecord } from '../db/database.ts';

interface TlsViewProps {
  tlsResults: TlsResultRecord[];
}

export const TlsView: React.FC<TlsViewProps> = ({ tlsResults }) => {
  if (tlsResults.length === 0) {
    return (
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl p-12 text-center text-slate-500">
        <Lock className="w-10 h-10 mx-auto mb-3 opacity-50 text-slate-600" />
        <h4 className="text-sm font-bold text-slate-300">No TLS Endpoints Inspected</h4>
        <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
          TLS certificates and cipher suites are analyzed on active HTTPS, FTPS, SMTPS, and secure web sockets.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="text-xs text-slate-400">
        Extracted cryptographic profiles for <strong className="text-white font-mono">{tlsResults.length}</strong> active TLS endpoints.
      </div>

      <div className="grid grid-cols-1 gap-5">
        {tlsResults.map((t) => {
          let sans: string[] = [];
          try {
            sans = JSON.parse(t.sans_json || '[]');
          } catch {}

          const isExpired = t.days_remaining < 0;
          const isExpiringSoon = t.days_remaining <= 30 && !isExpired;

          return (
            <div
              key={`${t.port}-${t.subject_cn}`}
              className="bg-[#0b0e17] border border-[#1e2333] rounded-xl p-5 space-y-4 shadow-sm"
            >
              {/* Header */}
              <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#1b2030]">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-red-950/40 border border-red-900/50 flex items-center justify-center font-mono text-sm font-bold text-red-400">
                    {t.port}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white font-mono">{t.subject_cn}</h3>
                    <div className="text-xs text-slate-400 flex items-center gap-1.5 mt-0.5">
                      <span>Issuer:</span>
                      <strong className="text-slate-300">{t.issuer_cn}</strong>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {t.is_valid ? (
                    <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 bg-emerald-950/40 border border-emerald-900/60 px-3 py-1 rounded-md">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Valid Certificate</span>
                    </span>
                  ) : (
                    <span className="flex items-center gap-1.5 text-xs font-semibold text-red-400 bg-red-950/50 border border-red-900/80 px-3 py-1 rounded-md">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>Validation Warning</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Validation Warning Alert if applicable */}
              {t.validation_error && (
                <div className="p-3 bg-red-950/40 border border-red-900/60 rounded-lg text-xs text-red-300 flex items-start gap-2.5">
                  <ShieldAlert className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
                  <div>
                    <strong className="font-semibold">Security Alert: </strong>
                    {t.validation_error}
                  </div>
                </div>
              )}

              {/* Metadata Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
                <div className="bg-[#10131e] p-3 rounded-lg border border-[#1e2333]">
                  <div className="text-[11px] text-slate-500 uppercase font-semibold mb-1">Expiration Status</div>
                  <div className={`font-mono font-bold text-sm ${isExpired ? 'text-red-400' : isExpiringSoon ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {isExpired ? 'Expired' : `${t.days_remaining} Days Left`}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5 font-mono">Until {t.valid_to}</div>
                </div>

                <div className="bg-[#10131e] p-3 rounded-lg border border-[#1e2333]">
                  <div className="text-[11px] text-slate-500 uppercase font-semibold mb-1">Validity Window</div>
                  <div className="font-mono text-slate-200 text-xs">
                    {t.valid_from}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Activated timestamp</div>
                </div>

                <div className="bg-[#10131e] p-3 rounded-lg border border-[#1e2333]">
                  <div className="text-[11px] text-slate-500 uppercase font-semibold mb-1">Cipher Suite</div>
                  <div className="font-mono text-slate-200 text-xs truncate" title={t.cipher}>
                    {t.cipher}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Negotiated session cipher</div>
                </div>

                <div className="bg-[#10131e] p-3 rounded-lg border border-[#1e2333]">
                  <div className="text-[11px] text-slate-500 uppercase font-semibold mb-1">Protocol Version</div>
                  <div className="font-mono text-slate-200 font-bold text-sm">
                    {t.protocol_version}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Cryptographic protocol</div>
                </div>
              </div>

              {/* Subject Alternative Names (SANs) */}
              {sans.length > 0 && (
                <div>
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Subject Alternative Names (SANs) — {sans.length} domains
                  </div>
                  <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-2 bg-[#090b12] rounded-lg border border-[#1b2030]">
                    {sans.map((s, idx) => (
                      <span
                        key={idx}
                        className="font-mono text-[11px] text-slate-300 bg-[#141824] px-2 py-0.5 rounded border border-[#22283a]"
                      >
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
