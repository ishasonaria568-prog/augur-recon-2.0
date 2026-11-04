import React from 'react';
import { Radar, ShieldCheck, Terminal } from 'lucide-react';
import { NavSection } from './Sidebar.tsx';

interface TopBarProps {
  currentSection: NavSection;
  activeTarget?: string;
  onOpenNewScan: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  currentSection,
  activeTarget,
  onOpenNewScan,
}) => {
  const sectionTitles: Record<NavSection, string> = {
    overview: 'Attack Surface Overview',
    new_scan: 'Scan Management & Target Authorization',
    live_scan: 'Live Reconnaissance Monitor',
    ports: 'Discovered Ports & Network Exposure',
    services: 'Protocol & Banner Fingerprinting',
    dns: 'DNS Intelligence & Zone Mapping',
    tls: 'TLS & Cryptographic Posture',
    history: 'Historical Reconnaissance Archive',
    diff: 'Attack Surface Drift & Diff Engine',
    reports: 'Multi-Format Security Reports',
    ai: 'AI Security Posture Advisor (Gemini)',
    settings: 'Security Policies & Audit Trail',
  };

  return (
    <header className="h-14 border-b border-[#1e2230] bg-[#090b12] px-6 flex items-center justify-between gap-6 select-none">
      {/* Breadcrumb Trail */}
      <div className="flex items-center gap-2 text-xs">
        <span className="font-semibold text-slate-400">AUGUR RECON</span>
        <span className="text-slate-600">/</span>
        <span className="text-slate-200 font-medium">{sectionTitles[currentSection]}</span>
        {activeTarget && (
          <>
            <span className="text-slate-600">/</span>
            <span className="font-mono text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-900/40">
              {activeTarget}
            </span>
          </>
        )}
      </div>

      {/* Action Zone */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#121520] border border-[#222738] text-[11px] text-slate-400">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>Default-Deny Policy Active</span>
        </div>

        <button
          onClick={onOpenNewScan}
          className="px-3.5 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-md transition-colors flex items-center gap-2 shadow-sm whitespace-nowrap cursor-pointer"
        >
          <Radar className="w-3.5 h-3.5" />
          <span>Launch Scan</span>
        </button>
      </div>
    </header>
  );
};
