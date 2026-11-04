import React from 'react';
import {
  ShieldAlert,
  LayoutDashboard,
  Radar,
  Radio,
  Server,
  Globe,
  Lock,
  History,
  GitCompare,
  FileText,
  Sparkles,
  Settings,
  Terminal,
  ExternalLink,
} from 'lucide-react';

export type NavSection =
  | 'overview'
  | 'new_scan'
  | 'live_scan'
  | 'ports'
  | 'services'
  | 'dns'
  | 'tls'
  | 'history'
  | 'diff'
  | 'reports'
  | 'ai'
  | 'settings';

interface SidebarProps {
  currentSection: NavSection;
  onSelectSection: (section: NavSection) => void;
  openPortsCount: number;
  totalScansCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentSection,
  onSelectSection,
  openPortsCount,
  totalScansCount,
}) => {
  const navItems = [
    { id: 'overview' as NavSection, label: 'Overview', icon: LayoutDashboard },
    { id: 'new_scan' as NavSection, label: 'New Scan', icon: Radar },
    { id: 'live_scan' as NavSection, label: 'Live Recon', icon: Radio },
    { id: 'ports' as NavSection, label: 'Open Ports', icon: ShieldAlert, badge: openPortsCount > 0 ? openPortsCount : undefined },
    { id: 'services' as NavSection, label: 'Services & Banners', icon: Server },
    { id: 'dns' as NavSection, label: 'DNS Intelligence', icon: Globe },
    { id: 'tls' as NavSection, label: 'TLS Inspection', icon: Lock },
    { id: 'history' as NavSection, label: 'Scan History', icon: History, badge: totalScansCount > 0 ? totalScansCount : undefined },
    { id: 'diff' as NavSection, label: 'Scan Comparison', icon: GitCompare },
    { id: 'reports' as NavSection, label: 'Reports', icon: FileText },
    { id: 'ai' as NavSection, label: 'AI Posture Advisor', icon: Sparkles },
    { id: 'settings' as NavSection, label: 'Security & Audit', icon: Settings },
  ];

  return (
    <aside className="w-64 shrink-0 bg-[#07090e] border-r border-[#1e2230] flex flex-col h-screen select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-[#1e2230] flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-red-950/80 border border-red-800/60 flex items-center justify-center text-red-500 shadow-sm">
            <Radar className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="text-base font-extrabold tracking-tight text-white flex items-center gap-1.5">
              <span>AUGUR</span>
              <span className="text-red-500">2.0</span>
            </div>
            <div className="text-[11px] text-slate-500 font-mono tracking-wider uppercase">Recon Intelligence</div>
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentSection === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectSection(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                isActive
                  ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#121520]'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-red-400' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span className={`px-1.5 py-0.2 font-mono text-[10px] rounded ${isActive ? 'bg-red-500/20 text-red-300' : 'bg-[#1a1e2b] text-slate-400'}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Developer & CLI Attribution Footer */}
      <div className="p-4 border-t border-[#1e2230] bg-[#05060a]">
        <div className="flex items-center justify-between text-[11px] text-slate-400 mb-2">
          <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
            <Terminal className="w-3.5 h-3.5 text-red-400" />
            CLI: augur scan
          </span>
          <span className="font-mono text-slate-500">v2.0.0</span>
        </div>
        <div className="text-[10px] text-slate-500 flex items-center justify-between">
          <span>By Isha Sonaria</span>
          <a
            href="https://github.com/ishasonaria568-prog"
            target="_blank"
            rel="noopener noreferrer"
            className="text-red-400 hover:text-red-300 transition-colors flex items-center gap-0.5"
          >
            GitHub <ExternalLink className="w-2.5 h-2.5" />
          </a>
        </div>
      </div>
    </aside>
  );
};
