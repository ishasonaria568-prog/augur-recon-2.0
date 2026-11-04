import React from 'react';
import { Radio, ShieldAlert, CheckCircle2, Clock, Terminal } from 'lucide-react';
import { ReconProgressEvent } from '../scanner/recon-orchestrator.ts';
import { ScanJobRecord } from '../db/database.ts';

interface LiveScanViewProps {
  activeScan: ReconProgressEvent | null;
  latestJob: ScanJobRecord | null;
  onSelectScan: (jobId: string) => void;
  onOpenNewScan: () => void;
}

export const LiveScanView: React.FC<LiveScanViewProps> = ({
  activeScan,
  latestJob,
  onSelectScan,
  onOpenNewScan,
}) => {
  if (!activeScan) {
    return (
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl p-12 text-center max-w-xl mx-auto my-8">
        <Radio className="w-12 h-12 text-slate-600 mx-auto mb-4" />
        <h3 className="text-base font-bold text-white">No Reconnaissance Job Currently Active</h3>
        <p className="text-xs text-slate-400 mt-2 mb-6">
          Live Recon monitor streams probe milestones, phase transitions, and real-time socket detections during an active scan.
        </p>
        <div className="flex items-center justify-center gap-3">
          {latestJob && (
            <button
              onClick={() => onSelectScan(latestJob.id)}
              className="px-4 py-2 text-xs font-semibold text-slate-300 bg-[#161a26] hover:bg-[#1e2336] border border-[#2a3148] rounded-lg transition-colors cursor-pointer"
            >
              View Most Recent Scan ({latestJob.normalized_host})
            </button>
          )}
          <button
            onClick={onOpenNewScan}
            className="px-4 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors cursor-pointer"
          >
            Launch New Scan
          </button>
        </div>
      </div>
    );
  }

  const phases = [
    { id: 'validating', label: 'Target Validation & Pre-flight' },
    { id: 'dns', label: 'DNS Zone Mapping' },
    { id: 'ports', label: 'Port Probing (TCP/UDP)' },
    { id: 'services', label: 'Service Banner Grabbing' },
    { id: 'tls', label: 'TLS Inspection' },
    { id: 'finalizing', label: 'Finalizing Report' },
  ];

  const currentPhaseIndex = phases.findIndex((p) => p.id === activeScan.phase);

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Live Active Header */}
      <div className="bg-[#0b0e17] border border-red-900/60 p-6 rounded-xl relative overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-3.5 h-3.5 rounded-full bg-red-500 animate-ping" />
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <span>Live Reconnaissance Stream</span>
              <span className="font-mono text-xs text-red-400 bg-red-950/60 px-2 py-0.5 rounded border border-red-900/40">
                JOB: {activeScan.jobId.slice(0, 12)}
              </span>
            </h2>
          </div>
          <div className="font-mono text-xl font-bold text-red-400 tabular-nums">
            {activeScan.percent}%
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-[#141826] h-2.5 rounded-full overflow-hidden mb-3">
          <div
            className="bg-red-600 h-full transition-all duration-300 rounded-full"
            style={{ width: `${activeScan.percent}%` }}
          />
        </div>

        <div className="flex items-center justify-between text-xs text-slate-400">
          <div className="font-mono text-slate-300">{activeScan.message}</div>
          <div className="font-mono text-red-400 font-semibold">{activeScan.openPortsCount} open ports discovered</div>
        </div>
      </div>

      {/* Phase Progression Stepper */}
      <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Pipeline Milestones</h3>
        <div className="space-y-3">
          {phases.map((phase, idx) => {
            const isDone = currentPhaseIndex > idx;
            const isCurrent = currentPhaseIndex === idx;

            return (
              <div
                key={phase.id}
                className={`flex items-center justify-between p-3 rounded-lg border text-xs transition-colors ${
                  isCurrent
                    ? 'bg-red-950/30 border-red-800/80 text-white'
                    : isDone
                    ? 'bg-[#0f121d] border-[#1e2436] text-slate-300'
                    : 'bg-[#080a10] border-[#141824] text-slate-600'
                }`}
              >
                <div className="flex items-center gap-3">
                  {isDone ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : isCurrent ? (
                    <div className="w-4 h-4 rounded-full border-2 border-red-500 border-t-transparent animate-spin" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-700 flex items-center justify-center text-[10px] text-slate-600">
                      {idx + 1}
                    </div>
                  )}
                  <span className="font-semibold">{phase.label}</span>
                </div>
                <span className="font-mono text-[11px]">
                  {isDone ? 'COMPLETED' : isCurrent ? 'RUNNING' : 'QUEUED'}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
