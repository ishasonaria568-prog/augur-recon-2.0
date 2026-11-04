import React, { useState } from 'react';
import { History, Search, Trash2, ArrowRight, GitCompare, Download, FileText } from 'lucide-react';
import { ScanJobRecord } from '../db/database.ts';

interface HistoryViewProps {
  scans: ScanJobRecord[];
  onSelectScan: (jobId: string) => void;
  onCompareScans: (oldId: string, newId: string) => void;
  onDeleteScan: (jobId: string) => Promise<void>;
  onExportReport: (jobId: string, format: 'json' | 'html' | 'markdown' | 'csv') => void;
  onOpenNewScan: () => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({
  scans,
  onSelectScan,
  onCompareScans,
  onDeleteScan,
  onExportReport,
  onOpenNewScan,
}) => {
  const [search, setSearch] = useState('');
  const [selectedForDiff, setSelectedForDiff] = useState<string[]>([]);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const filtered = scans.filter((s) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      s.normalized_host.toLowerCase().includes(q) ||
      s.resolved_ip.includes(q) ||
      s.id.toLowerCase().includes(q)
    );
  });

  const toggleSelectDiff = (id: string) => {
    if (selectedForDiff.includes(id)) {
      setSelectedForDiff(selectedForDiff.filter((x) => x !== id));
    } else {
      if (selectedForDiff.length >= 2) {
        setSelectedForDiff([selectedForDiff[1], id]);
      } else {
        setSelectedForDiff([...selectedForDiff, id]);
      }
    }
  };

  const handleTriggerDiff = () => {
    if (selectedForDiff.length === 2) {
      onCompareScans(selectedForDiff[0], selectedForDiff[1]);
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm(`Are you sure you want to delete scan record ${id.slice(0, 8)}?`)) {
      setDeletingId(id);
      try {
        await onDeleteScan(id);
      } finally {
        setDeletingId(null);
      }
    }
  };

  return (
    <div className="space-y-5">
      {/* Search and Diff Header Bar */}
      <div className="bg-[#0b0e17] border border-[#1e2333] p-4 rounded-xl flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search scans by target, IP, or scan ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#121522] border border-[#242a3d] focus:border-red-500 focus:outline-none rounded-lg pl-9 pr-3.5 py-2 text-xs text-white placeholder:text-slate-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-3">
          {selectedForDiff.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">
                Selected for Diff: <strong className="text-white font-mono">{selectedForDiff.length}/2</strong>
              </span>
              <button
                disabled={selectedForDiff.length !== 2}
                onClick={handleTriggerDiff}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 disabled:opacity-40 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <GitCompare className="w-3.5 h-3.5" />
                <span>Compare Selected Scans</span>
              </button>
            </div>
          )}

          <button
            onClick={onOpenNewScan}
            className="px-3.5 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors cursor-pointer"
          >
            New Scan
          </button>
        </div>
      </div>

      {/* History Table */}
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <History className="w-10 h-10 mx-auto mb-3 opacity-50 text-slate-600" />
            <h4 className="text-sm font-bold text-slate-300">No Reconnaissance Scans Match Query</h4>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              Scan records are permanently stored in SQLite and indexed by host and timestamp.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#080a10] border-b border-[#1e2333] text-slate-400 uppercase font-semibold text-[11px] tracking-wider">
                <tr>
                  <th className="px-4 py-3 w-10 text-center">Diff</th>
                  <th className="px-4 py-3">Target Host</th>
                  <th className="px-4 py-3">Resolved IP</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Open / Total</th>
                  <th className="px-4 py-3">Duration</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#151928]">
                {filtered.map((scan) => {
                  const isSelected = selectedForDiff.includes(scan.id);
                  const isCompleted = scan.status === 'completed';

                  return (
                    <tr key={scan.id} className="hover:bg-[#121624] transition-colors">
                      <td className="px-4 py-3 text-center">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => toggleSelectDiff(scan.id)}
                          className="accent-red-600 rounded cursor-pointer"
                        />
                      </td>
                      <td className="px-4 py-3 font-mono font-bold text-white">
                        <button
                          onClick={() => onSelectScan(scan.id)}
                          className="hover:text-red-400 transition-colors text-left cursor-pointer"
                        >
                          {scan.normalized_host}
                        </button>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">{scan.resolved_ip}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`font-mono text-[11px] font-semibold ${
                            isCompleted ? 'text-emerald-400' : 'text-red-400'
                          }`}
                        >
                          {scan.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono">
                        <strong className={scan.open_ports_count > 0 ? 'text-red-400' : 'text-slate-400'}>
                          {scan.open_ports_count}
                        </strong>
                        <span className="text-slate-600"> / {scan.total_ports_probed}</span>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">
                        {scan.duration_ms ? `${scan.duration_ms}ms` : '—'}
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-500 text-[11px]">
                        {scan.created_at ? scan.created_at.replace('T', ' ').slice(0, 19) : '—'}
                      </td>
                      <td className="px-4 py-3 text-right space-x-2">
                        <button
                          onClick={() => onSelectScan(scan.id)}
                          className="text-slate-300 hover:text-white font-medium cursor-pointer"
                          title="View findings"
                        >
                          View
                        </button>
                        <button
                          onClick={() => onExportReport(scan.id, 'html')}
                          className="text-slate-400 hover:text-red-400 cursor-pointer"
                          title="Download HTML Report"
                        >
                          <Download className="w-3.5 h-3.5 inline" />
                        </button>
                        <button
                          onClick={() => handleDelete(scan.id)}
                          disabled={deletingId === scan.id}
                          className="text-slate-500 hover:text-red-500 cursor-pointer"
                          title="Delete scan record"
                        >
                          <Trash2 className="w-3.5 h-3.5 inline" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
