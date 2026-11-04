import React, { useState } from 'react';
import { Server, Terminal, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react';
import { ServiceResultRecord } from '../db/database.ts';

interface ServicesViewProps {
  services: ServiceResultRecord[];
}

export const ServicesView: React.FC<ServicesViewProps> = ({ services }) => {
  const [expandedPort, setExpandedPort] = useState<number | null>(null);
  const [copiedPort, setCopiedPort] = useState<number | null>(null);

  const toggleExpand = (port: number) => {
    setExpandedPort(expandedPort === port ? null : port);
  };

  const copyBanner = (port: number, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPort(port);
    setTimeout(() => setCopiedPort(null), 2000);
  };

  if (services.length === 0) {
    return (
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl p-12 text-center text-slate-500">
        <Server className="w-10 h-10 mx-auto mb-3 opacity-50 text-slate-600" />
        <h4 className="text-sm font-bold text-slate-300">No Services Fingerprinted</h4>
        <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
          Services are identified on open listening ports via protocol-aware banners and HTTP probes.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="text-xs text-slate-400">
        Showing <strong className="text-white font-mono">{services.length}</strong> application services fingerprinted via active TCP probes.
      </div>

      <div className="space-y-3">
        {services.map((svc) => {
          const isExpanded = expandedPort === svc.port;

          return (
            <div
              key={`${svc.protocol}-${svc.port}`}
              className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden transition-colors"
            >
              {/* Service Summary Header */}
              <div
                onClick={() => toggleExpand(svc.port)}
                className="p-4 flex items-center justify-between cursor-pointer hover:bg-[#121524] transition-colors"
              >
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-lg bg-red-950/40 border border-red-900/50 flex flex-col items-center justify-center font-mono">
                    <span className="text-xs font-bold text-red-400">{svc.port}</span>
                    <span className="text-[9px] text-slate-500 uppercase">{svc.protocol}</span>
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white font-mono">{svc.service_name}</span>
                      {(svc.product || svc.version) && (
                        <span className="text-xs text-slate-300 font-medium">
                          — {svc.product} {svc.version}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-500 font-mono mt-0.5 truncate max-w-xl">
                      {svc.banner || 'TCP handshake established (no text banner returned)'}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-slate-400">
                  <span className="text-[11px] font-mono">{isExpanded ? 'Hide Raw Probe' : 'Inspect Raw'}</span>
                  {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                </div>
              </div>

              {/* Raw Probe Expansion */}
              {isExpanded && (
                <div className="p-4 border-t border-[#1e2333] bg-[#07080d]">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-mono text-slate-400 uppercase flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-red-400" />
                      Raw Daemon Response / Probe Payload
                    </span>
                    <button
                      onClick={() => copyBanner(svc.port, svc.raw_probe_response || svc.banner)}
                      className="text-[11px] text-slate-400 hover:text-white flex items-center gap-1 cursor-pointer font-mono"
                    >
                      {copiedPort === svc.port ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedPort === svc.port ? 'Copied' : 'Copy Payload'}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-[#030407] border border-[#1b2030] rounded-lg text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-64 leading-relaxed">
                    {svc.raw_probe_response || svc.banner || 'No payload recorded.'}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
