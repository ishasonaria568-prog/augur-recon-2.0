import React, { useState, useEffect } from 'react';
import { GitCompare, ShieldAlert, ArrowRight, AlertTriangle, CheckCircle2, Shield } from 'lucide-react';
import { ScanJobRecord } from '../db/database.ts';
import { ScanDiffResult } from '../scanner/scan-diff.ts';

interface DiffViewProps {
  scans: ScanJobRecord[];
  initialOldId?: string;
  initialNewId?: string;
}

export const DiffView: React.FC<DiffViewProps> = ({
  scans,
  initialOldId,
  initialNewId,
}) => {
  const [oldId, setOldId] = useState<string>(initialOldId || (scans.length > 1 ? scans[1].id : ''));
  const [newId, setNewId] = useState<string>(initialNewId || (scans.length > 0 ? scans[0].id : ''));
  const [diff, setDiff] = useState<ScanDiffResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialOldId) setOldId(initialOldId);
    if (initialNewId) setNewId(initialNewId);
  }, [initialOldId, initialNewId]);

  const runDiff = async () => {
    if (!oldId || !newId) {
      setError('Please select both a baseline scan and a target scan to compare.');
      return;
    }
    if (oldId === newId) {
      setError('Please select two distinct scan jobs for comparison.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/scans/diff/${oldId}/${newId}`);
      if (!res.ok) {
        const body = await res.json();
        throw new Error(body.error || 'Failed to calculate diff');
      }
      const data = await res.json();
      setDiff(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (oldId && newId && oldId !== newId) {
      runDiff();
    }
  }, [oldId, newId]);

  return (
    <div className="space-y-6">
      {/* Selector Card */}
      <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <GitCompare className="w-4 h-4 text-red-500" />
            <h3 className="text-sm font-bold text-white">Attack Surface Drift & Diff Analyzer</h3>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Temporal Comparison</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase">
              Baseline Scan (Older / Previous State)
            </label>
            <select
              value={oldId}
              onChange={(e) => setOldId(e.target.value)}
              className="w-full bg-[#121522] border border-[#242a3d] focus:border-red-500 rounded-lg px-3 py-2 text-xs text-white font-mono"
            >
              <option value="">Select baseline scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.normalized_host} ({s.resolved_ip}) — {s.created_at?.slice(0, 16)} [{s.open_ports_count} open]
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase">
              Comparison Scan (Newer / Current State)
            </label>
            <select
              value={newId}
              onChange={(e) => setNewId(e.target.value)}
              className="w-full bg-[#121522] border border-[#242a3d] focus:border-red-500 rounded-lg px-3 py-2 text-xs text-white font-mono"
            >
              <option value="">Select current scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.normalized_host} ({s.resolved_ip}) — {s.created_at?.slice(0, 16)} [{s.open_ports_count} open]
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-red-950/40 border border-red-900/60 rounded-lg text-xs text-red-300">
            {error}
          </div>
        )}
      </div>

      {/* Diff Results Output */}
      {diff && (
        <div className="space-y-6">
          {/* IP Drift Notice */}
          {diff.ipChanged && (
            <div className="p-4 bg-amber-950/30 border border-amber-900/50 rounded-xl flex items-center justify-between text-xs text-amber-200">
              <div className="flex items-center gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>
                  <strong>Target IP Drift:</strong> Target resolution migrated from <code className="font-mono bg-black/40 px-1 py-0.5 rounded">{diff.oldIp}</code> to <code className="font-mono bg-black/40 px-1 py-0.5 rounded">{diff.newIp}</code>.
                </span>
              </div>
            </div>
          )}

          {/* Delta KPI Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-[#0b0e17] border border-[#1e2333] p-4 rounded-xl">
              <div className="text-[11px] uppercase font-semibold text-slate-400 mb-1">Newly Exposed Ports</div>
              <div className="text-2xl font-bold font-mono text-red-500 tabular-nums">
                +{diff.portsDiff.newlyOpened.length}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Potential new attack vectors</div>
            </div>

            <div className="bg-[#0b0e17] border border-[#1e2333] p-4 rounded-xl">
              <div className="text-[11px] uppercase font-semibold text-slate-400 mb-1">Closed / Guarded Ports</div>
              <div className="text-2xl font-bold font-mono text-emerald-400 tabular-nums">
                -{diff.portsDiff.newlyClosed.length}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Remediated or filtered endpoints</div>
            </div>

            <div className="bg-[#0b0e17] border border-[#1e2333] p-4 rounded-xl">
              <div className="text-[11px] uppercase font-semibold text-slate-400 mb-1">Service & DNS Updates</div>
              <div className="text-2xl font-bold font-mono text-white tabular-nums">
                {diff.servicesDiff.modified.length + diff.dnsDiff.added.length + diff.dnsDiff.removed.length}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Configuration modifications</div>
            </div>
          </div>

          {/* Newly Opened Ports */}
          <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[#1e2333] flex items-center justify-between">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                Newly Exposed Ports ({diff.portsDiff.newlyOpened.length})
              </h4>
            </div>
            {diff.portsDiff.newlyOpened.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No new ports were opened between baseline and comparison scan.
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="bg-[#080a10] border-b border-[#1e2333] text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="px-5 py-2.5">Port</th>
                    <th className="px-5 py-2.5">Protocol</th>
                    <th className="px-5 py-2.5">State</th>
                    <th className="px-5 py-2.5">Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#151928]">
                  {diff.portsDiff.newlyOpened.map((p) => (
                    <tr key={p.port} className="bg-red-950/20">
                      <td className="px-5 py-2.5 font-mono font-bold text-red-400">+{p.port}</td>
                      <td className="px-5 py-2.5 font-mono text-slate-300 uppercase">{p.protocol}</td>
                      <td className="px-5 py-2.5 font-mono text-emerald-400 font-semibold">OPEN</td>
                      <td className="px-5 py-2.5 font-mono text-slate-400">{p.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Newly Closed Ports */}
          <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[#1e2333] flex items-center justify-between">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                Closed or Filtered Ports ({diff.portsDiff.newlyClosed.length})
              </h4>
            </div>
            {diff.portsDiff.newlyClosed.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No ports were closed between these scan points.
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="bg-[#080a10] border-b border-[#1e2333] text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="px-5 py-2.5">Port</th>
                    <th className="px-5 py-2.5">Protocol</th>
                    <th className="px-5 py-2.5">Previous State</th>
                    <th className="px-5 py-2.5">Current Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#151928]">
                  {diff.portsDiff.newlyClosed.map((p) => (
                    <tr key={p.port} className="bg-emerald-950/10">
                      <td className="px-5 py-2.5 font-mono font-bold text-emerald-400">-{p.port}</td>
                      <td className="px-5 py-2.5 font-mono text-slate-300 uppercase">{p.protocol}</td>
                      <td className="px-5 py-2.5 font-mono text-slate-400">OPEN in Baseline</td>
                      <td className="px-5 py-2.5 font-mono text-slate-500 font-semibold">CLOSED / GUARDED</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Service & Banner Updates */}
          {diff.servicesDiff.modified.length > 0 && (
            <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
              <div className="p-4 border-b border-[#1e2333]">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Modified Service Banners ({diff.servicesDiff.modified.length})
                </h4>
              </div>
              <div className="divide-y divide-[#151928]">
                {diff.servicesDiff.modified.map((m) => (
                  <div key={m.port} className="p-4 space-y-2 text-xs">
                    <div className="flex items-center gap-2 font-mono">
                      <strong className="text-white">Port {m.port}:</strong>
                      <span className="text-slate-400">{m.oldService}</span>
                      <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                      <span className="text-red-400 font-bold">{m.newService}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-[11px] font-mono">
                      <div className="p-2 bg-[#080a10] rounded border border-[#1e2333] text-slate-400 truncate">
                        Baseline: {m.oldBanner}
                      </div>
                      <div className="p-2 bg-[#080a10] rounded border border-red-950 text-slate-200 truncate">
                        Current: {m.newBanner}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
