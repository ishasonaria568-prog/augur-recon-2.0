/**
 * AUGUR RECON 2.0 - Central Web Application Shell
 * Developer: Isha Sonaria (https://github.com/ishasonaria568-prog)
 * AI-Augmented Attack Surface Intelligence
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, NavSection } from './components/Sidebar.tsx';
import { TopBar } from './components/TopBar.tsx';
import { OverviewView } from './components/OverviewView.tsx';
import { LiveScanView } from './components/LiveScanView.tsx';
import { OpenPortsView } from './components/OpenPortsView.tsx';
import { ServicesView } from './components/ServicesView.tsx';
import { DnsView } from './components/DnsView.tsx';
import { TlsView } from './components/TlsView.tsx';
import { HistoryView } from './components/HistoryView.tsx';
import { DiffView } from './components/DiffView.tsx';
import { ReportsView } from './components/ReportsView.tsx';
import { AiAnalysisView } from './components/AiAnalysisView.tsx';
import { SettingsView } from './components/SettingsView.tsx';
import { NewScanModal } from './components/NewScanModal.tsx';
import { ScanJobRecord } from './db/database.ts';
import { ReconProgressEvent } from './scanner/recon-orchestrator.ts';

export default function App() {
  const [currentSection, setCurrentSection] = useState<NavSection>('overview');
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Application Data States
  const [stats, setStats] = useState({
    totalScans: 0,
    completedScans: 0,
    totalOpenPorts: 0,
    uniqueTargets: 0,
  });
  const [recentScans, setRecentScans] = useState<ScanJobRecord[]>([]);
  const [allScans, setAllScans] = useState<ScanJobRecord[]>([]);
  const [activeScanEvent, setActiveScanEvent] = useState<ReconProgressEvent | null>(null);
  const [hasGeminiKey, setHasGeminiKey] = useState(false);

  // Detailed view of currently inspected scan
  const [currentScanDetails, setCurrentScanDetails] = useState<{
    job: ScanJobRecord;
    ports: any[];
    services: any[];
    tls: any[];
    dns: any[];
    aiAnalysis?: any;
  } | null>(null);

  // Diff target selections
  const [diffOldId, setDiffOldId] = useState<string | undefined>();
  const [diffNewId, setDiffNewId] = useState<string | undefined>();

  // Fetch application overview stats & recent jobs
  const fetchOverviewData = useCallback(async () => {
    try {
      const res = await fetch('/api/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data.stats || { totalScans: 0, completedScans: 0, totalOpenPorts: 0, uniqueTargets: 0 });
        setRecentScans(data.recentScans || []);
      }
    } catch {
      // Offline fallback
    }
  }, []);

  // Fetch full scan history list
  const fetchAllScans = useCallback(async () => {
    try {
      const res = await fetch('/api/scans?limit=100');
      if (res.ok) {
        const data = await res.json();
        setAllScans(data.scans || []);
        // If no scan is currently selected, pick the latest
        if (!currentScanDetails && data.scans?.length > 0) {
          fetchScanDetails(data.scans[0].id);
        }
      }
    } catch {
      // Offline fallback
    }
  }, [currentScanDetails]);

  // Fetch config and security policy
  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch('/api/config');
      if (res.ok) {
        const data = await res.json();
        setHasGeminiKey(data.hasGeminiApiKey);
      }
    } catch {
      // Offline fallback
    }
  }, []);

  // Fetch details for a specific scan job
  const fetchScanDetails = async (jobId: string) => {
    try {
      const res = await fetch(`/api/scans/${jobId}`);
      if (res.ok) {
        const data = await res.json();
        setCurrentScanDetails(data);
      }
    } catch (err) {
      console.error('Failed to load scan details', err);
    }
  };

  useEffect(() => {
    fetchOverviewData();
    fetchAllScans();
    fetchConfig();
  }, [fetchOverviewData, fetchAllScans, fetchConfig]);

  // Handle starting a new scan
  const handleStartScan = async (params: {
    target: string;
    ports: string;
    concurrency: number;
    timeoutMs: number;
    enableUdp: boolean;
    allowPrivate: boolean;
    runAiAnalysis: boolean;
  }) => {
    setCurrentSection('live_scan');
    setActiveScanEvent({
      jobId: 'init',
      phase: 'validating',
      message: `Enforcing security policy for ${params.target}...`,
      percent: 5,
      openPortsCount: 0,
    });

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Scan initiation failed');
      }

      // Scan completed
      setActiveScanEvent(null);
      await fetchOverviewData();
      await fetchAllScans();

      if (data.data) {
        setCurrentScanDetails(data.data);
      }
    } catch (err: any) {
      setActiveScanEvent(null);
      throw err;
    }
  };

  // Handle running Gemini AI analysis on a job
  const handleRunAiAnalysis = async (jobId: string) => {
    const res = await fetch(`/api/scans/${jobId}/analyze`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'AI analysis request failed');
    }
    await fetchScanDetails(jobId);
  };

  // Handle deleting a scan job
  const handleDeleteScan = async (jobId: string) => {
    const res = await fetch(`/api/scans/${jobId}`, { method: 'DELETE' });
    if (res.ok) {
      await fetchOverviewData();
      await fetchAllScans();
      if (currentScanDetails?.job.id === jobId) {
        setCurrentScanDetails(null);
      }
    }
  };

  // Handle selecting a scan from anywhere in the UI
  const handleSelectScan = async (jobId: string) => {
    await fetchScanDetails(jobId);
    setCurrentSection('ports');
  };

  // Handle initiating comparison between two scans
  const handleCompareScans = (oldId: string, newId: string) => {
    setDiffOldId(oldId);
    setDiffNewId(newId);
    setCurrentSection('diff');
  };

  // Export report download trigger
  const handleExportReport = (jobId: string, format: string) => {
    window.location.href = `/api/scans/${jobId}/report?format=${format}&download=true`;
  };

  return (
    <div className="flex h-screen bg-[#050608] text-slate-100 overflow-hidden font-sans">
      {/* Sidebar Navigation */}
      <Sidebar
        currentSection={currentSection}
        onSelectSection={(sec) => {
          if (sec === 'new_scan') {
            setIsModalOpen(true);
          } else {
            setCurrentSection(sec);
          }
        }}
        openPortsCount={currentScanDetails?.ports.filter((p: any) => p.state === 'open').length || 0}
        totalScansCount={stats.totalScans}
      />

      {/* Main Workspace Frame */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <TopBar
          currentSection={currentSection}
          activeTarget={currentScanDetails?.job.normalized_host}
          onOpenNewScan={() => setIsModalOpen(true)}
        />

        <main className="flex-1 overflow-y-auto p-6 bg-[#06080d]">
          <div className="max-w-[1440px] mx-auto">
            {currentSection === 'overview' && (
              <OverviewView
                stats={stats}
                recentScans={recentScans}
                activeScan={activeScanEvent}
                onSelectScan={handleSelectScan}
                onOpenNewScan={() => setIsModalOpen(true)}
              />
            )}

            {currentSection === 'live_scan' && (
              <LiveScanView
                activeScan={activeScanEvent}
                latestJob={currentScanDetails?.job || recentScans[0] || null}
                onSelectScan={handleSelectScan}
                onOpenNewScan={() => setIsModalOpen(true)}
              />
            )}

            {currentSection === 'ports' && (
              <OpenPortsView
                ports={currentScanDetails?.ports || []}
                services={currentScanDetails?.services || []}
                targetHost={currentScanDetails?.job.normalized_host}
              />
            )}

            {currentSection === 'services' && (
              <ServicesView services={currentScanDetails?.services || []} />
            )}

            {currentSection === 'dns' && (
              <DnsView
                dnsRecords={currentScanDetails?.dns || []}
                targetHost={currentScanDetails?.job.normalized_host}
              />
            )}

            {currentSection === 'tls' && (
              <TlsView tlsResults={currentScanDetails?.tls || []} />
            )}

            {currentSection === 'history' && (
              <HistoryView
                scans={allScans}
                onSelectScan={handleSelectScan}
                onCompareScans={handleCompareScans}
                onDeleteScan={handleDeleteScan}
                onExportReport={handleExportReport}
                onOpenNewScan={() => setIsModalOpen(true)}
              />
            )}

            {currentSection === 'diff' && (
              <DiffView
                scans={allScans}
                initialOldId={diffOldId}
                initialNewId={diffNewId}
              />
            )}

            {currentSection === 'reports' && (
              <ReportsView
                scans={allScans}
                activeJobId={currentScanDetails?.job.id}
              />
            )}

            {currentSection === 'ai' && (
              <AiAnalysisView
                scans={allScans}
                activeJobId={currentScanDetails?.job.id}
                aiAnalysis={currentScanDetails?.aiAnalysis}
                hasGeminiKey={hasGeminiKey}
                onRunAnalysis={handleRunAiAnalysis}
              />
            )}

            {currentSection === 'settings' && (
              <SettingsView hasGeminiKey={hasGeminiKey} />
            )}
          </div>
        </main>
      </div>

      {/* New Reconnaissance Mission Modal */}
      <NewScanModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onStartScan={handleStartScan}
        hasGeminiKey={hasGeminiKey}
      />
    </div>
  );
}
