import React, { useState, useEffect } from 'react';
import { FileText, Download, Copy, Check, ExternalLink } from 'lucide-react';
import { ScanJobRecord } from '../db/database.ts';

interface ReportsViewProps {
  scans: ScanJobRecord[];
  activeJobId?: string;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ scans, activeJobId }) => {
  const [selectedJobId, setSelectedJobId] = useState<string>(activeJobId || (scans.length > 0 ? scans[0].id : ''));
  const [format, setFormat] = useState<'html' | 'markdown' | 'json' | 'csv'>('html');
  const [reportContent, setReportContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (activeJobId) {
      setSelectedJobId(activeJobId);
    }
  }, [activeJobId]);

  const fetchReport = async () => {
    if (!selectedJobId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/scans/${selectedJobId}/report?format=${format}`);
      const text = await res.text();
      setReportContent(text);
    } catch {
      setReportContent('Failed to load report.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedJobId) {
      fetchReport();
    }
  }, [selectedJobId, format]);

  const handleDownload = () => {
    if (!selectedJobId) return;
    window.location.href = `/api/scans/${selectedJobId}/report?format=${format}&download=true`;
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(reportContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (scans.length === 0) {
    return (
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl p-12 text-center text-slate-500">
        <FileText className="w-10 h-10 mx-auto mb-3 opacity-50 text-slate-600" />
        <h4 className="text-sm font-bold text-slate-300">No Reconnaissance Reports Available</h4>
        <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
          Execute a scan to generate structured JSON, CSV, Markdown, and standalone HTML reports.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Configuration & Format Toolbar */}
      <div className="bg-[#0b0e17] border border-[#1e2333] p-4 rounded-xl flex flex-wrap items-center justify-between gap-4">
        {/* Job Selector */}
        <div className="flex items-center gap-3">
          <label className="text-xs text-slate-400 font-semibold uppercase">Scan Job:</label>
          <select
            value={selectedJobId}
            onChange={(e) => setSelectedJobId(e.target.value)}
            className="bg-[#121522] border border-[#242a3d] focus:border-red-500 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.normalized_host} ({s.resolved_ip}) — {s.created_at?.slice(0, 16)}
              </option>
            ))}
          </select>
        </div>

        {/* Format Selector Tabs */}
        <div className="flex items-center gap-1 p-1 bg-[#121522] rounded-lg border border-[#1e2333]">
          {(['html', 'markdown', 'json', 'csv'] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => setFormat(fmt)}
              className={`px-3 py-1 text-xs font-semibold rounded-md uppercase transition-colors cursor-pointer ${
                format === fmt ? 'bg-red-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
              }`}
            >
              {fmt}
            </button>
          ))}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-[#141824] hover:bg-[#1c2233] border border-[#23293d] rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Content'}</span>
          </button>

          <button
            onClick={handleDownload}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download {format.toUpperCase()}</span>
          </button>
        </div>
      </div>

      {/* Preview Area */}
      <div className="bg-[#0b0e17] border border-[#1e2333] rounded-xl overflow-hidden min-h-[500px]">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400 font-mono">
            Compiling and rendering report...
          </div>
        ) : format === 'html' ? (
          <iframe
            srcDoc={reportContent}
            className="w-full h-[650px] border-none bg-[#090a0f]"
            title="Augur Recon Security Report"
          />
        ) : (
          <pre className="p-5 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-[650px]">
            {reportContent}
          </pre>
        )}
      </div>
    </div>
  );
};
