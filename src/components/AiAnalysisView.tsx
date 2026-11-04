import React, { useState } from 'react';
import { Sparkles, Zap, ShieldAlert, CheckCircle2, AlertTriangle, ArrowRight, Info } from 'lucide-react';
import { ScanJobRecord } from '../db/database.ts';

interface AiAnalysisViewProps {
  scans: ScanJobRecord[];
  activeJobId?: string;
  aiAnalysis?: any;
  hasGeminiKey: boolean;
  onRunAnalysis: (jobId: string) => Promise<void>;
}

export const AiAnalysisView: React.FC<AiAnalysisViewProps> = ({
  scans,
  activeJobId,
  aiAnalysis,
  hasGeminiKey,
  onRunAnalysis,
}) => {
  const [selectedJobId, setSelectedJobId] = useState<string>(activeJobId || (scans.length > 0 ? scans[0].id : ''));
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const selectedScan = scans.find((s) => s.id === selectedJobId);

  const handleRun = async () => {
    if (!selectedJobId) return;
    setIsAnalyzing(true);
    setErrorMsg(null);
    try {
      await onRunAnalysis(selectedJobId);
    } catch (err: any) {
      setErrorMsg(err.message || 'AI Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const keyFindings = aiAnalysis ? JSON.parse(aiAnalysis.key_findings_json || '[]') : [];
  const recommendations = aiAnalysis ? JSON.parse(aiAnalysis.recommendations_json || '[]') : [];

  return (
    <div className="space-y-6">
      {/* Top Banner & Control */}
      <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-red-500" />
            <h3 className="text-sm font-bold text-white">Gemini AI Attack Surface Advisor</h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Empirical synthesis of open services, TLS cipher hygiene, and perimeter exposure.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedJobId}
            onChange={(e) => setSelectedJobId(e.target.value)}
            className="bg-[#121522] border border-[#242a3d] focus:border-red-500 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.normalized_host} ({s.resolved_ip}) — [{s.open_ports_count} open]
              </option>
            ))}
          </select>

          <button
            onClick={handleRun}
            disabled={isAnalyzing || !selectedJobId || !hasGeminiKey}
            className="px-4 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 disabled:opacity-40 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer shadow-sm"
          >
            <Zap className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
            <span>{isAnalyzing ? 'Synthesizing...' : aiAnalysis ? 'Re-Run AI Analysis' : 'Run AI Analysis'}</span>
          </button>
        </div>
      </div>

      {/* API Key Status Notice if missing */}
      {!hasGeminiKey && (
        <div className="p-4 bg-amber-950/30 border border-amber-900/60 rounded-xl flex items-start gap-3 text-xs text-amber-200">
          <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <strong>AI Analysis Optional Module: </strong>
            Gemini API key is not configured in environment variables (<code className="font-mono bg-black/40 px-1 py-0.5 rounded">GEMINI_API_KEY</code>). All core network reconnaissance, DNS enumeration, TLS analysis, and reporting operate with zero external AI dependencies.
          </div>
        </div>
      )}

      {errorMsg && (
        <div className="p-3.5 bg-red-950/60 border border-red-800 rounded-lg text-xs text-red-300">
          {errorMsg}
        </div>
      )}

      {/* Analysis Presentation */}
      {aiAnalysis ? (
        <div className="space-y-6">
          {/* Executive Summary Card */}
          <div className="bg-[#0b0e17] border border-[#1e2333] p-5 rounded-xl space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#1b2030]">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Executive Attack Surface Summary
              </span>
              <span className="font-mono text-[11px] text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-900/40">
                Model: {aiAnalysis.model}
              </span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed font-sans">
              {aiAnalysis.summary}
            </p>
            <div className="text-[10px] text-slate-500 italic pt-1">
              * Note: Findings reflect observed empirical evidence only. Recommendations provide defensive hardening guidance.
            </div>
          </div>

          {/* Key Findings List */}
          {keyFindings.length > 0 && (
            <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
              <div className="p-4 border-b border-[#1e2333]">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Observed Attack Surface Findings ({keyFindings.length})
                </h4>
              </div>
              <div className="divide-y divide-[#151928]">
                {keyFindings.map((f: any, idx: number) => (
                  <div key={idx} className="p-4 space-y-1.5 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] font-bold text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-900/50">
                        {f.category}
                      </span>
                      <strong className="text-white">{f.observation}</strong>
                    </div>
                    <p className="text-slate-400 text-xs pl-2 border-l border-slate-700">
                      {f.riskContext}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Hardening Recommendations */}
          {recommendations.length > 0 && (
            <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden">
              <div className="p-4 border-b border-[#1e2333]">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Prioritized Hardening Recommendations ({recommendations.length})
                </h4>
              </div>
              <div className="divide-y divide-[#151928]">
                {recommendations.map((r: any, idx: number) => {
                  const isHigh = r.priority === 'HIGH';
                  const isMedium = r.priority === 'MEDIUM';

                  return (
                    <div key={idx} className="p-4 space-y-1 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white text-xs flex items-center gap-2">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          <span>{r.title}</span>
                        </span>
                        <span
                          className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded ${
                            isHigh
                              ? 'bg-red-950/60 text-red-400 border border-red-900'
                              : isMedium
                              ? 'bg-amber-950/60 text-amber-400 border border-amber-900'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {r.priority} PRIORITY
                        </span>
                      </div>
                      <p className="text-slate-300 text-xs mt-1 pl-5">
                        {r.action}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl p-12 text-center text-slate-500">
          <Sparkles className="w-10 h-10 mx-auto mb-3 opacity-50 text-slate-600" />
          <h4 className="text-sm font-bold text-slate-300">No AI Posture Analysis Generated Yet</h4>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto mb-4">
            Click "Run AI Analysis" to synthesize the empirical scan observations for the selected target.
          </p>
          {hasGeminiKey && selectedJobId && (
            <button
              onClick={handleRun}
              disabled={isAnalyzing}
              className="px-4 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors cursor-pointer"
            >
              Run AI Security Analysis
            </button>
          )}
        </div>
      )}
    </div>
  );
};
