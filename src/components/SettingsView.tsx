import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Lock, Terminal, History, CheckCircle2, AlertOctagon, ExternalLink } from 'lucide-react';
import { AuditEventRecord } from '../db/database.ts';

interface SettingsViewProps {
  hasGeminiKey: boolean;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ hasGeminiKey }) => {
  const [auditLogs, setAuditLogs] = useState<AuditEventRecord[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/audit-logs?limit=50');
      const data = await res.json();
      setAuditLogs(data.logs || []);
    } catch {
      // Ignore
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Security Architecture Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Default-Deny Policy */}
        <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl space-y-3">
          <div className="flex items-center gap-2.5">
            <Shield className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Target Validation & Default-Deny Policy</h3>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            All reconnaissance requests are strictly filtered before any network socket is opened. The following address spaces are blocked by default:
          </p>
          <ul className="text-xs space-y-1.5 font-mono text-slate-300">
            <li className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>127.0.0.0/8 & ::1 (Loopback)</span>
            </li>
            <li className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Private RFC1918)</span>
            </li>
            <li className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>169.254.0.0/16 (Link-Local & Cloud Metadata 169.254.169.254)</span>
            </li>
            <li className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>100.64.0.0/10 (Carrier-Grade NAT RFC6598)</span>
            </li>
          </ul>
          <div className="pt-2 border-t border-[#1a1f2e] text-[11px] text-amber-300/90">
            * Authorized penetration testing against private lab infrastructure requires the explicit <code className="bg-black/50 px-1 py-0.5 rounded font-mono text-white">--allow-private</code> CLI flag or Lab Mode switch in the UI.
          </div>
        </div>

        {/* Defense Mechanisms */}
        <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl space-y-3">
          <div className="flex items-center gap-2.5">
            <Lock className="w-4 h-4 text-red-500" />
            <h3 className="text-sm font-bold text-white">DNS Rebinding & Rate Limiting</h3>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            AUGUR RECON enforces pre-flight resolution and active connection locking to eliminate attack vectors:
          </p>
          <div className="space-y-2 text-xs">
            <div className="p-2.5 bg-[#121522] rounded-lg border border-[#1e2333]">
              <div className="font-semibold text-white mb-0.5">DNS Rebinding Immunity</div>
              <div className="text-[11px] text-slate-400">
                Target hostnames are resolved upfront and validated against policy; sockets pin directly to the validated IP, bypassing subsequent spoofed DNS queries.
              </div>
            </div>
            <div className="p-2.5 bg-[#121522] rounded-lg border border-[#1e2333]">
              <div className="font-semibold text-white mb-0.5">Sliding-Window Token Bucket Limiter</div>
              <div className="text-[11px] text-slate-400">
                Scan job submissions and REST API endpoints are metered to prevent socket starvation and flooding.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
        <div className="p-4 border-b border-[#1e2333] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white">Security & Audit Event Trail</h3>
            <p className="text-xs text-slate-500">Immutable chronological record of scans, authorizations, and policy enforcement decisions</p>
          </div>
          <button
            onClick={fetchAuditLogs}
            className="text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            Refresh Log
          </button>
        </div>

        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#080a10] border-b border-[#1e2333] text-slate-400 uppercase font-semibold text-[11px] tracking-wider sticky top-0">
              <tr>
                <th className="px-5 py-3">Timestamp</th>
                <th className="px-5 py-3">Action</th>
                <th className="px-5 py-3">Target</th>
                <th className="px-5 py-3">Actor</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#151928]">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500">
                    No security audit events recorded yet.
                  </td>
                </tr>
              ) : (
                auditLogs.map((log) => {
                  const isBlocked = log.status === 'blocked';
                  const isSuccess = log.status === 'success';

                  return (
                    <tr key={log.id} className="hover:bg-[#121624] transition-colors">
                      <td className="px-5 py-2.5 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                        {log.timestamp.replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="px-5 py-2.5 font-mono font-semibold text-white">
                        {log.action}
                      </td>
                      <td className="px-5 py-2.5 font-mono text-slate-300">
                        {log.target}
                      </td>
                      <td className="px-5 py-2.5 font-mono text-slate-400">
                        {log.actor}
                      </td>
                      <td className="px-5 py-2.5 font-mono">
                        <span
                          className={`font-semibold text-[11px] ${
                            isBlocked ? 'text-red-400' : isSuccess ? 'text-emerald-400' : 'text-amber-400'
                          }`}
                        >
                          {log.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-5 py-2.5 font-mono text-[11px] text-slate-400 max-w-xs truncate" title={log.details_json}>
                        {log.details_json}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Project & Packaging Metadata */}
      <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl flex flex-wrap items-center justify-between gap-4 text-xs">
        <div>
          <div className="font-bold text-white">AUGUR RECON 2.0 &bull; Architecture & Kali Linux Packaging</div>
          <div className="text-slate-400 mt-0.5">
            Engineered by <strong className="text-slate-200">Isha Sonaria</strong> &bull; Debian Package: <code className="font-mono text-red-400 bg-red-950/40 px-1.5 py-0.5 rounded">dist/augur-recon_2.0.0_all.deb</code>
          </div>
        </div>

        <a
          href="https://github.com/ishasonaria568-prog"
          target="_blank"
          rel="noopener noreferrer"
          className="px-3.5 py-1.5 bg-[#121522] hover:bg-[#1a1f30] border border-[#23293d] rounded-lg text-slate-300 hover:text-white transition-colors flex items-center gap-1.5"
        >
          <span>GitHub Repository</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </div>
    </div>
  );
};
