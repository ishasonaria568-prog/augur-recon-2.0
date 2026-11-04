import React, { useState } from 'react';
import { ShieldAlert, Search, Filter, Copy, Check, Download } from 'lucide-react';
import { PortResultRecord, ServiceResultRecord } from '../db/database.ts';

interface OpenPortsViewProps {
  ports: PortResultRecord[];
  services: ServiceResultRecord[];
  targetHost?: string;
}

export const OpenPortsView: React.FC<OpenPortsViewProps> = ({
  ports,
  services,
  targetHost,
}) => {
  const [filterState, setFilterState] = useState<'all' | 'open' | 'closed' | 'filtered'>('open');
  const [protocolFilter, setProtocolFilter] = useState<'all' | 'tcp' | 'udp'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  const filteredPorts = ports.filter((p) => {
    if (filterState === 'open' && p.state !== 'open') return false;
    if (filterState === 'closed' && p.state !== 'closed') return false;
    if (filterState === 'filtered' && !p.state.includes('filtered')) return false;

    if (protocolFilter !== 'all' && p.protocol !== protocolFilter) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchPort = p.port.toString().includes(q);
      const matchReason = p.reason.toLowerCase().includes(q);
      const svc = services.find((s) => s.port === p.port);
      const matchSvc = svc?.service_name.toLowerCase().includes(q) || svc?.product?.toLowerCase().includes(q);
      if (!matchPort && !matchReason && !matchSvc) return false;
    }

    return true;
  });

  const copyPortsList = () => {
    const openOnly = ports.filter((p) => p.state === 'open').map((p) => p.port).join(',');
    navigator.clipboard.writeText(openOnly);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const openCount = ports.filter((p) => p.state === 'open').length;

  return (
    <div className="space-y-5">
      {/* Filter and Action Bar */}
      <div className="bg-[#0b0e17] border border-[#1e2333] p-4 rounded-xl flex flex-wrap items-center justify-between gap-4">
        {/* State Filter Tabs */}
        <div className="flex items-center gap-1 p-1 bg-[#121522] rounded-lg border border-[#1e2333]">
          <button
            onClick={() => setFilterState('open')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
              filterState === 'open' ? 'bg-red-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Open Ports ({openCount})
          </button>
          <button
            onClick={() => setFilterState('all')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
              filterState === 'all' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            All Probed ({ports.length})
          </button>
          <button
            onClick={() => setFilterState('closed')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
              filterState === 'closed' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Closed
          </button>
          <button
            onClick={() => setFilterState('filtered')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
              filterState === 'filtered' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Filtered
          </button>
        </div>

        {/* Search & Copy */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search port or service..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#121522] border border-[#242a3d] focus:border-red-500 focus:outline-none rounded-lg pl-9 pr-3.5 py-1.5 text-xs text-white placeholder:text-slate-500 w-48 sm:w-64 font-mono"
            />
          </div>

          <button
            onClick={copyPortsList}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-[#141824] hover:bg-[#1c2233] border border-[#23293d] rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
            title="Copy comma-separated list of open ports"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
            <span>{copied ? 'Copied' : 'Copy Open Ports'}</span>
          </button>
        </div>
      </div>

      {/* Ports Table */}
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
        {filteredPorts.length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <ShieldAlert className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-xs">No ports match the selected filter criteria.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#080a10] border-b border-[#1e2333] text-slate-400 uppercase font-semibold text-[11px] tracking-wider">
                <tr>
                  <th className="px-5 py-3">Port</th>
                  <th className="px-5 py-3">Protocol</th>
                  <th className="px-5 py-3">State</th>
                  <th className="px-5 py-3">Service Fingerprint</th>
                  <th className="px-5 py-3">Probe Reason / Handshake</th>
                  <th className="px-5 py-3 text-right">Round-Trip Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#151928]">
                {filteredPorts.map((p) => {
                  const svc = services.find((s) => s.port === p.port);
                  const isOpen = p.state === 'open';

                  return (
                    <tr key={`${p.protocol}-${p.port}`} className="hover:bg-[#121624] transition-colors">
                      <td className="px-5 py-3 font-mono font-bold text-white text-sm">
                        {p.port}
                      </td>
                      <td className="px-5 py-3 font-mono text-slate-400 uppercase text-[11px]">
                        {p.protocol}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs">
                        <span
                          className={`font-semibold ${
                            isOpen
                              ? 'text-emerald-400'
                              : p.state === 'closed'
                              ? 'text-slate-500'
                              : 'text-amber-400'
                          }`}
                        >
                          {p.state.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        {svc ? (
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-red-400 font-semibold">{svc.service_name}</span>
                            {(svc.product || svc.version) && (
                              <span className="text-slate-400 text-[11px]">
                                {svc.product} {svc.version}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-600 font-mono text-[11px]">Not identified</span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-slate-400 font-mono text-[11px] max-w-md truncate" title={p.reason}>
                        {p.reason}
                      </td>
                      <td className="px-5 py-3 font-mono text-slate-400 text-right tabular-nums">
                        {p.latency_ms}ms
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
