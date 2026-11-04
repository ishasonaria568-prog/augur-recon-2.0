import React, { useState } from 'react';
import { X, Radar, AlertTriangle, ShieldCheck, Cpu, Zap, Info } from 'lucide-react';
import { PORT_PRESETS } from '../scanner/port-parser.ts';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onStartScan: (params: {
    target: string;
    ports: string;
    concurrency: number;
    timeoutMs: number;
    enableUdp: boolean;
    allowPrivate: boolean;
    runAiAnalysis: boolean;
  }) => Promise<void>;
  hasGeminiKey: boolean;
}

export const NewScanModal: React.FC<NewScanModalProps> = ({
  isOpen,
  onClose,
  onStartScan,
  hasGeminiKey,
}) => {
  const [target, setTarget] = useState('');
  const [selectedPreset, setSelectedPreset] = useState<string>('top20');
  const [customPorts, setCustomPorts] = useState('');
  const [concurrency, setConcurrency] = useState(35);
  const [timeoutMs, setTimeoutMs] = useState(1500);
  const [enableUdp, setEnableUdp] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [runAiAnalysis, setRunAiAnalysis] = useState(hasGeminiKey);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      setErrorMsg('Target hostname or IP address is required.');
      return;
    }

    const portsSpec = selectedPreset === 'custom' ? customPorts : selectedPreset;
    if (selectedPreset === 'custom' && !customPorts.trim()) {
      setErrorMsg('Please specify port numbers or ranges (e.g. 80,443,8080).');
      return;
    }

    setErrorMsg(null);
    setIsSubmitting(true);
    try {
      await onStartScan({
        target: target.trim(),
        ports: portsSpec,
        concurrency,
        timeoutMs,
        enableUdp,
        allowPrivate,
        runAiAnalysis,
      });
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Scan initiation failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0b0d14] border border-[#222738] rounded-xl w-full max-w-2xl max-h-[92vh] overflow-y-auto shadow-2xl">
        {/* Modal Header */}
        <div className="p-5 border-b border-[#1e2230] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-red-950/80 border border-red-800/60 flex items-center justify-center text-red-500">
              <Radar className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Configure Reconnaissance Mission</h2>
              <p className="text-xs text-slate-400">Target specification, port profiling, and security boundary validation</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-md transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {errorMsg && (
            <div className="p-3.5 bg-red-950/60 border border-red-800/80 rounded-lg text-xs text-red-300 flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
              <div className="leading-relaxed">{errorMsg}</div>
            </div>
          )}

          {/* Target Host */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Target Hostname or IP Address *
            </label>
            <div className="relative">
              <input
                type="text"
                placeholder="e.g. scanme.nmap.org, example.com, 104.26.10.228"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="w-full bg-[#121520] border border-[#242a3d] focus:border-red-500 focus:outline-none rounded-lg px-4 py-2.5 text-sm text-white font-mono placeholder:text-slate-600 transition-colors"
                autoFocus
                required
              />
            </div>
            <p className="mt-1.5 text-[11px] text-slate-500">
              DNS resolution and destination validation occur immediately prior to connection establishment.
            </p>
          </div>

          {/* Port Presets */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Port Scope & Presets
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {Object.entries(PORT_PRESETS).map(([key, val]) => (
                <button
                  type="button"
                  key={key}
                  onClick={() => setSelectedPreset(key)}
                  className={`p-3 text-left rounded-lg border text-xs transition-colors ${
                    selectedPreset === key
                      ? 'bg-red-950/40 border-red-600/80 text-white shadow-sm'
                      : 'bg-[#121520] border-[#222738] text-slate-400 hover:text-slate-200 hover:border-slate-700'
                  }`}
                >
                  <div className="font-semibold text-slate-200">{val.name}</div>
                  <div className="text-[10px] text-slate-500 mt-1 font-mono">{val.ports.length} ports</div>
                </button>
              ))}

              <button
                type="button"
                onClick={() => setSelectedPreset('custom')}
                className={`p-3 text-left rounded-lg border text-xs transition-colors ${
                  selectedPreset === 'custom'
                    ? 'bg-red-950/40 border-red-600/80 text-white shadow-sm'
                    : 'bg-[#121520] border-[#222738] text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <div className="font-semibold text-slate-200">Custom Ports</div>
                <div className="text-[10px] text-slate-500 mt-1">Manual range / list</div>
              </button>
            </div>

            {selectedPreset === 'custom' && (
              <div className="mt-3">
                <input
                  type="text"
                  placeholder="e.g. 22,80,443,8000-8080"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  className="w-full bg-[#121520] border border-[#242a3d] focus:border-red-500 focus:outline-none rounded-lg px-3.5 py-2 text-xs text-white font-mono placeholder:text-slate-600"
                />
              </div>
            )}
          </div>

          {/* Performance & Probing Controls */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="bg-[#121520] p-4 rounded-lg border border-[#222738]">
              <div className="flex justify-between text-xs text-slate-300 font-medium mb-1.5">
                <span>Concurrency Pool</span>
                <span className="font-mono text-red-400">{concurrency} workers</span>
              </div>
              <input
                type="range"
                min="5"
                max="100"
                step="5"
                value={concurrency}
                onChange={(e) => setConcurrency(Number.parseInt(e.target.value, 10))}
                className="w-full accent-red-600 cursor-pointer"
              />
              <p className="text-[10px] text-slate-500 mt-1">Controlled connection queue prevents socket starvation.</p>
            </div>

            <div className="bg-[#121520] p-4 rounded-lg border border-[#222738]">
              <label className="block text-xs text-slate-300 font-medium mb-1.5">
                Probe Timeout (ms)
              </label>
              <input
                type="number"
                min="300"
                max="5000"
                step="100"
                value={timeoutMs}
                onChange={(e) => setTimeoutMs(Number.parseInt(e.target.value, 10))}
                className="w-full bg-[#0a0c12] border border-[#242a3d] rounded px-3 py-1.5 text-xs text-white font-mono"
              />
              <p className="text-[10px] text-slate-500 mt-1">Timeout for SYN-ACK or application banner reply.</p>
            </div>
          </div>

          {/* Scan Options Toggles */}
          <div className="space-y-3 pt-2">
            <label className="flex items-start gap-3 cursor-pointer p-3 rounded-lg bg-[#121520] border border-[#222738] hover:border-slate-700 transition-colors">
              <input
                type="checkbox"
                checked={enableUdp}
                onChange={(e) => setEnableUdp(e.target.checked)}
                className="mt-0.5 accent-red-600 rounded"
              />
              <div>
                <div className="text-xs font-semibold text-slate-200">Enable Best-Effort UDP Service Probing</div>
                <div className="text-[11px] text-slate-500">
                  Sends protocol probes (DNS, NTP, SNMP, SSDP) to common UDP ports. Discloses stateless timeout characteristics.
                </div>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer p-3 rounded-lg bg-[#121520] border border-[#222738] hover:border-slate-700 transition-colors">
              <input
                type="checkbox"
                checked={allowPrivate}
                onChange={(e) => setAllowPrivate(e.target.checked)}
                className="mt-0.5 accent-red-600 rounded"
              />
              <div>
                <div className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Authorized Private Lab Mode (--allow-private)</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Explicitly authorizes scanning of RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and local subnets for authorized penetration testing labs.
                </div>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer p-3 rounded-lg bg-[#121520] border border-[#222738] hover:border-slate-700 transition-colors">
              <input
                type="checkbox"
                checked={runAiAnalysis}
                onChange={(e) => setRunAiAnalysis(e.target.checked)}
                disabled={!hasGeminiKey}
                className="mt-0.5 accent-red-600 rounded"
              />
              <div>
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-red-400" />
                  <span>Auto-Synthesize Security Posture via Gemini AI</span>
                </div>
                <div className="text-[11px] text-slate-500">
                  {hasGeminiKey
                    ? 'Evaluates real empirical findings (banners, open ports, TLS validity) to deliver hardening guidance.'
                    : 'Gemini API Key is not configured in environment variables (scanning remains fully operational).'}
                </div>
              </div>
            </label>
          </div>

          {/* Modal Footer */}
          <div className="pt-4 border-t border-[#1e2230] flex items-center justify-between">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-5 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors flex items-center gap-2 shadow-sm disabled:opacity-50 cursor-pointer"
            >
              <Radar className={`w-4 h-4 ${isSubmitting ? 'animate-spin' : ''}`} />
              <span>{isSubmitting ? 'Validating & Launching...' : 'Start Reconnaissance'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
