import React, { useState } from 'react';
import { Globe, Copy, Check, Search } from 'lucide-react';
import { DnsResultRecord } from '../db/database.ts';

interface DnsViewProps {
  dnsRecords: DnsResultRecord[];
  targetHost?: string;
}

export const DnsView: React.FC<DnsViewProps> = ({ dnsRecords, targetHost }) => {
  const [filterType, setFilterType] = useState<string>('all');
  const [copiedId, setCopiedId] = useState<number | null>(null);

  const recordTypes = Array.from(new Set(dnsRecords.map((d) => d.record_type))).sort();

  const filtered = dnsRecords.filter((d) => {
    if (filterType !== 'all' && d.record_type !== filterType) return false;
    return true;
  });

  const handleCopy = (id: number, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (dnsRecords.length === 0) {
    return (
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl p-12 text-center text-slate-500">
        <Globe className="w-10 h-10 mx-auto mb-3 opacity-50 text-slate-600" />
        <h4 className="text-sm font-bold text-slate-300">No DNS Records Enumerated</h4>
        <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
          DNS intelligence is queried during reconnaissance for domain targets (A, AAAA, MX, NS, TXT, CNAME, SOA, and PTR).
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Type Filter Tabs */}
      <div className="flex items-center gap-1.5 p-1 bg-[#121522] rounded-lg border border-[#1e2333] overflow-x-auto">
        <button
          onClick={() => setFilterType('all')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap ${
            filterType === 'all' ? 'bg-red-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
          }`}
        >
          All Records ({dnsRecords.length})
        </button>
        {recordTypes.map((type) => {
          const count = dnsRecords.filter((d) => d.record_type === type).length;
          return (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                filterType === type ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
              }`}
            >
              {type} ({count})
            </button>
          );
        })}
      </div>

      {/* DNS Records Table */}
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#080a10] border-b border-[#1e2333] text-slate-400 uppercase font-semibold text-[11px] tracking-wider">
            <tr>
              <th className="px-5 py-3 w-28">Record Type</th>
              <th className="px-5 py-3">Resolved Value / Record Data</th>
              <th className="px-5 py-3 w-24">Priority</th>
              <th className="px-5 py-3 w-24">TTL</th>
              <th className="px-5 py-3 w-20 text-right">Copy</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#151928]">
            {filtered.map((d, idx) => {
              const recordId = d.id || idx;
              return (
                <tr key={`${d.record_type}-${idx}`} className="hover:bg-[#121624] transition-colors">
                  <td className="px-5 py-3">
                    <span className="font-mono font-bold text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-900/50">
                      {d.record_type}
                    </span>
                  </td>
                  <td className="px-5 py-3 font-mono text-slate-200 break-all">
                    {d.value}
                  </td>
                  <td className="px-5 py-3 font-mono text-slate-400">
                    {d.priority ?? '—'}
                  </td>
                  <td className="px-5 py-3 font-mono text-slate-400">
                    {d.ttl ? `${d.ttl}s` : '—'}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <button
                      onClick={() => handleCopy(recordId, d.value)}
                      className="text-slate-400 hover:text-white p-1 rounded transition-colors cursor-pointer"
                      title="Copy value"
                    >
                      {copiedId === recordId ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
