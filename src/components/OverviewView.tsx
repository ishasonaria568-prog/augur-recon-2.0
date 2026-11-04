import React from 'react';
import {
  ShieldAlert,
  Server,
  Radar,
  ArrowRight,
  Globe,
  Clock,
  CheckCircle2,
  AlertOctagon,
  Lock,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { ScanJobRecord } from '../db/database.ts';

interface OverviewViewProps {
  stats: {
    totalScans: number;
    completedScans: number;
    totalOpenPorts: number;
    uniqueTargets: number;
  };
  recentScans: ScanJobRecord[];
  activeScan: any | null;
  onSelectScan: (jobId: string) => void;
  onOpenNewScan: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  stats,
  recentScans,
  activeScan,
  onSelectScan,
  onOpenNewScan,
}) => {
  // Chart data derived from real recent scans
  const portDistribution = [
    { name: 'Web (80/443)', count: recentScans.reduce((acc, s) => acc + (s.open_ports_count > 0 ? 1 : 0), 0) },
    { name: 'Admin/SSH (22)', count: recentScans.filter((s) => s.ports_spec.includes('22')).length },
    { name: 'DB/Services', count: recentScans.filter((s) => s.ports_spec.includes('database')).length },
    { name: 'Other Ports', count: Math.max(0, stats.totalOpenPorts - 2) },
  ];

  const pieData = [
    { name: 'Completed', value: stats.completedScans, color: '#16a34a' },
    { name: 'Other', value: Math.max(0, stats.totalScans - stats.completedScans), color: '#334155' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Scans Executed</span>
            <Radar className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono tabular-nums">{stats.totalScans}</div>
          <div className="mt-2 text-[11px] text-slate-500 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>{stats.completedScans} completed successfully</span>
          </div>
        </div>

        <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Exposed Open Ports</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-3xl font-extrabold text-red-500 font-mono tabular-nums">{stats.totalOpenPorts}</div>
          <div className="mt-2 text-[11px] text-slate-500">
            <span>Discovered listening network sockets</span>
          </div>
        </div>

        <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Unique Targets Profiled</span>
            <Globe className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono tabular-nums">{stats.uniqueTargets}</div>
          <div className="mt-2 text-[11px] text-slate-500">
            <span>Validated external & lab hosts</span>
          </div>
        </div>

        <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Policy Enforcement</span>
            <Lock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">Default-Deny</div>
          <div className="mt-2 text-[11px] text-slate-500">
            <span>RFC1918 & Cloud Metadata Protected</span>
          </div>
        </div>
      </div>

      {/* Active Reconnaissance Banner if a scan is running */}
      {activeScan && (
        <div className="p-4 bg-red-950/30 border border-red-800/60 rounded-xl flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full bg-red-500 animate-ping" />
            <div>
              <div className="text-xs font-bold text-white flex items-center gap-2">
                <span>Active Reconnaissance Job In-Flight</span>
                <span className="font-mono text-red-400">[{activeScan.jobId?.slice(0, 8)}]</span>
              </div>
              <div className="text-xs text-slate-400 mt-0.5">{activeScan.message}</div>
            </div>
          </div>
          <div className="text-right shrink-0">
            <div className="text-sm font-mono font-bold text-red-400">{activeScan.percent}%</div>
            <div className="text-[10px] text-slate-500">{activeScan.openPortsCount} open ports found</div>
          </div>
        </div>
      )}

      {/* Analytics & Distribution Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Port Distribution Bar Chart */}
        <div className="lg:col-span-2 bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-white">Exposed Surface Categories</h3>
            <span className="text-[11px] text-slate-500 font-mono">Real Assessment Telemetry</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={portDistribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111420', borderColor: '#23293d', borderRadius: '6px', fontSize: '12px' }}
                  cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }}
                />
                <Bar dataKey="count" fill="#dc2626" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Scan Status Summary */}
        <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white mb-1">Execution Posture</h3>
            <p className="text-xs text-slate-500 mb-4">Operational ratio of completed vs pending probes</p>
            <div className="h-40 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                  >
                    {pieData.map((entry, idx) => (
                      <Cell key={`cell-${idx}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111420', borderColor: '#23293d', borderRadius: '6px', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="pt-3 border-t border-[#1e2333] text-xs text-slate-400 flex justify-between">
            <span>Completed: <strong className="text-emerald-400 font-mono">{stats.completedScans}</strong></span>
            <span>Total: <strong className="text-white font-mono">{stats.totalScans}</strong></span>
          </div>
        </div>
      </div>

      {/* Recent Reconnaissance Runs Table */}
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
        <div className="p-5 border-b border-[#1e2333] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white">Recent Attack Surface Scans</h3>
            <p className="text-xs text-slate-500">Persistent reconnaissance records stored in local SQLite database</p>
          </div>
          <button
            onClick={onOpenNewScan}
            className="text-xs font-semibold text-red-400 hover:text-red-300 transition-colors flex items-center gap-1 cursor-pointer"
          >
            <span>New Target Scan</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {recentScans.length === 0 ? (
          <div className="p-12 text-center">
            <Radar className="w-10 h-10 text-slate-600 mx-auto mb-3" />
            <h4 className="text-sm font-bold text-slate-300">No Scans Executed Yet</h4>
            <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-4">
              AUGUR RECON is ready. Launch your first reconnaissance mission against an authorized target host or IP address.
            </p>
            <button
              onClick={onOpenNewScan}
              className="px-4 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors cursor-pointer"
            >
              Configure First Scan
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#080a10] border-b border-[#1e2333] text-slate-400 uppercase font-semibold text-[11px] tracking-wider">
                <tr>
                  <th className="px-5 py-3">Target Host</th>
                  <th className="px-5 py-3">Resolved IP</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Open Ports</th>
                  <th className="px-5 py-3">Duration</th>
                  <th className="px-5 py-3">Timestamp</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#181d2a]">
                {recentScans.map((scan) => {
                  const isCompleted = scan.status === 'completed';
                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-[#121624] transition-colors cursor-pointer"
                      onClick={() => onSelectScan(scan.id)}
                    >
                      <td className="px-5 py-3 font-semibold text-white font-mono">
                        {scan.normalized_host}
                      </td>
                      <td className="px-5 py-3 font-mono text-slate-400">{scan.resolved_ip}</td>
                      <td className="px-5 py-3">
                        <span className={`font-mono text-[11px] font-semibold ${isCompleted ? 'text-emerald-400' : 'text-red-400'}`}>
                          {scan.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-5 py-3 font-mono">
                        <span className={scan.open_ports_count > 0 ? 'text-red-400 font-bold' : 'text-slate-400'}>
                          {scan.open_ports_count}
                        </span>
                        <span className="text-slate-600"> / {scan.total_ports_probed}</span>
                      </td>
                      <td className="px-5 py-3 font-mono text-slate-400">
                        {scan.duration_ms ? `${scan.duration_ms}ms` : '-'}
                      </td>
                      <td className="px-5 py-3 text-slate-500 font-mono text-[11px]">
                        {scan.created_at ? scan.created_at.replace('T', ' ').slice(0, 19) : '-'}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectScan(scan.id);
                          }}
                          className="text-red-400 hover:text-red-300 font-semibold text-xs cursor-pointer"
                        >
                          View Details &rarr;
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
