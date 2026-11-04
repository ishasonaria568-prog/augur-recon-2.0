/**
 * AUGUR RECON 2.0 - Multi-Format Report Generation Engine
 * Produces structured JSON, CSV, Markdown, and Standalone Self-Contained HTML security reports.
 */

import { getDatabase, ScanJobRecord } from '../db/database.ts';

export type ReportFormat = 'json' | 'csv' | 'markdown' | 'html';

export interface ScanReportData {
  job: ScanJobRecord;
  ports: any[];
  services: any[];
  tls: any[];
  dns: any[];
  aiAnalysis?: any;
}

export function getScanReportData(jobId: string): ScanReportData {
  const db = getDatabase();
  const job = db.getScanJob(jobId);
  if (!job) throw new Error(`Scan job ${jobId} not found.`);

  const ports = db.getPortResults(jobId);
  const services = db.getServiceResults(jobId);
  const tls = db.getTlsResults(jobId);
  const dns = db.getDnsResults(jobId);
  const aiAnalysis = db.getAiAnalysis(jobId);

  return {
    job,
    ports,
    services,
    tls,
    dns,
    aiAnalysis,
  };
}

export function generateJsonReport(data: ScanReportData): string {
  return JSON.stringify(
    {
      reportTitle: 'AUGUR RECON 2.0 - Attack Surface Reconnaissance Report',
      generatedAt: new Date().toISOString(),
      developer: 'Isha Sonaria',
      metadata: {
        jobId: data.job.id,
        target: data.job.target_input,
        normalizedHost: data.job.normalized_host,
        resolvedIp: data.job.resolved_ip,
        scanType: data.job.scan_type,
        status: data.job.status,
        durationMs: data.job.duration_ms,
        startedAt: data.job.started_at,
        completedAt: data.job.completed_at,
      },
      summary: {
        totalPortsProbed: data.job.total_ports_probed,
        openPortsCount: data.job.open_ports_count,
        servicesIdentified: data.services.length,
        tlsCertificatesFound: data.tls.length,
        dnsRecordsEnumerated: data.dns.length,
      },
      findings: {
        openPorts: data.ports.filter((p) => p.state === 'open'),
        allPortResults: data.ports,
        discoveredServices: data.services,
        tlsCertificates: data.tls,
        dnsRecords: data.dns,
      },
      aiAnalysis: data.aiAnalysis
        ? {
            model: data.aiAnalysis.model,
            summary: data.aiAnalysis.summary,
            keyFindings: JSON.parse(data.aiAnalysis.key_findings_json || '[]'),
            recommendations: JSON.parse(data.aiAnalysis.recommendations_json || '[]'),
          }
        : null,
      disclaimer:
        'This assessment report was produced by AUGUR RECON 2.0 strictly for authorized security assessments. All data represents observed empirical facts at the time of scan.',
    },
    null,
    2
  );
}

export function generateCsvReport(data: ScanReportData): string {
  const lines: string[] = [];
  lines.push('Category,Port,Protocol,State,Service/Type,Product/Version,Details/Value,LatencyMs/TTL');

  // Ports
  for (const p of data.ports) {
    const svc = data.services.find((s) => s.port === p.port && s.protocol === p.protocol);
    const serviceName = svc ? svc.service_name : 'unidentified';
    const prodVer = svc ? `${svc.product || ''} ${svc.version || ''}`.trim() : '';
    const details = (p.reason || '').replace(/"/g, '""');
    lines.push(`Port,${p.port},${p.protocol},${p.state},"${serviceName}","${prodVer}","${details}",${p.latency_ms}`);
  }

  // DNS
  for (const d of data.dns) {
    const val = (d.value || '').replace(/"/g, '""');
    lines.push(`DNS,-,-,-,${d.record_type},-,"${val}",${d.ttl ?? ''}`);
  }

  // TLS
  for (const t of data.tls) {
    const subj = (t.subject_cn || '').replace(/"/g, '""');
    const issuer = (t.issuer_cn || '').replace(/"/g, '""');
    lines.push(`TLS,${t.port},tcp,${t.is_valid ? 'valid' : 'invalid'},X.509,"${issuer}","Subject: ${subj} | Expires: ${t.valid_to} (${t.days_remaining}d)",-`);
  }

  return lines.join('\n');
}

export function generateMarkdownReport(data: ScanReportData): string {
  const openPorts = data.ports.filter((p) => p.state === 'open');

  let md = `# AUGUR RECON 2.0 — Attack Surface Intelligence Report\n\n`;
  md += `**Target:** \`${data.job.target_input}\` (Resolved IP: \`${data.job.resolved_ip}\`)\n`;
  md += `**Scan ID:** \`${data.job.id}\`\n`;
  md += `**Started:** ${data.job.started_at} | **Completed:** ${data.job.completed_at} (${data.job.duration_ms}ms)\n`;
  md += `**Status:** ${data.job.status.toUpperCase()} | **Auditor / Tool:** Isha Sonaria / AUGUR RECON 2.0\n\n`;

  md += `## 1. Executive Summary\n\n`;
  md += `- **Total Ports Probed:** ${data.job.total_ports_probed}\n`;
  md += `- **Open Ports Detected:** ${openPorts.length}\n`;
  md += `- **Application Services Fingerprinted:** ${data.services.length}\n`;
  md += `- **TLS Certificates Inspected:** ${data.tls.length}\n`;
  md += `- **DNS Zone Records Discovered:** ${data.dns.length}\n\n`;

  md += `## 2. Discovered Open Ports & Services\n\n`;
  if (openPorts.length === 0) {
    md += `*No open ports were detected during this reconnaissance job.*\n\n`;
  } else {
    md += `| Port | Protocol | Service | Product / Version | Banner / Response Summary | Latency |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
    for (const p of openPorts) {
      const svc = data.services.find((s) => s.port === p.port);
      const svcName = svc ? svc.service_name : 'unknown';
      const prod = svc ? `${svc.product || ''} ${svc.version || ''}`.trim() || '-' : '-';
      const banner = svc ? (svc.banner || '').replace(/[\r\n]+/g, ' ').slice(0, 70) : '-';
      md += `| **${p.port}** | ${p.protocol.toUpperCase()} | \`${svcName}\` | ${prod} | ${banner} | ${p.latency_ms}ms |\n`;
    }
    md += `\n`;
  }

  md += `## 3. TLS Certificate & Cryptographic Posture\n\n`;
  if (data.tls.length === 0) {
    md += `*No TLS-enabled endpoints were observed during this assessment.*\n\n`;
  } else {
    for (const t of data.tls) {
      md += `### Port ${t.port}/TCP — Subject: ${t.subject_cn}\n\n`;
      md += `- **Issuer:** ${t.issuer_cn}\n`;
      md += `- **Validity:** Valid from ${t.valid_from} to ${t.valid_to} (${t.days_remaining} days remaining)\n`;
      md += `- **Status:** ${t.is_valid ? '✅ Valid' : `⚠️ Validation Warning: ${t.validation_error}`}\n`;
      md += `- **Cipher Suite:** \`${t.cipher}\` (${t.protocol_version})\n`;
      try {
        const sans = JSON.parse(t.sans_json || '[]');
        if (sans.length > 0) {
          md += `- **Subject Alternative Names (SANs):** ${sans.join(', ')}\n`;
        }
      } catch {}
      md += `\n`;
    }
  }

  md += `## 4. DNS Intelligence & Zone Discovery\n\n`;
  if (data.dns.length === 0) {
    md += `*No DNS records discovered for target hostname/IP.*\n\n`;
  } else {
    md += `| Type | Value | Priority | TTL |\n`;
    md += `| :--- | :--- | :--- | :--- |\n`;
    for (const d of data.dns) {
      md += `| **${d.record_type}** | \`${d.value}\` | ${d.priority ?? '-'} | ${d.ttl ? `${d.ttl}s` : '-'} |\n`;
    }
    md += `\n`;
  }

  if (data.aiAnalysis) {
    md += `## 5. AI-Assisted Security Posture Analysis (Gemini)\n\n`;
    md += `> **Model:** \`${data.aiAnalysis.model}\` | *Note: This section contains advisory synthesis based strictly on empirical evidence gathered above.*\n\n`;
    md += `${data.aiAnalysis.summary}\n\n`;

    try {
      const findings = JSON.parse(data.aiAnalysis.key_findings_json || '[]');
      if (findings.length > 0) {
        md += `### Key Observations & Attack Surface Exposure\n\n`;
        for (const f of findings) {
          md += `- **${f.title || f.category || 'Observation'}:** ${f.detail || f.description || f}\n`;
        }
        md += `\n`;
      }
      const recs = JSON.parse(data.aiAnalysis.recommendations_json || '[]');
      if (recs.length > 0) {
        md += `### Hardening & Remediation Recommendations\n\n`;
        for (const r of recs) {
          md += `- **${r.priority ? `[${r.priority}] ` : ''}${r.title || 'Guideline'}:** ${r.action || r.description || r}\n`;
        }
        md += `\n`;
      }
    } catch {}
  }

  md += `## 6. Technical Limitations & Disclaimer\n\n`;
  md += `1. TCP SYN/Connect scans identify services actively listening at scan execution time. Filtered ports may be guarded by stateful packet inspection.\n`;
  md += `2. Best-effort UDP scanning without kernel raw sockets relies on ICMP unreachable packets or direct application responses. Open/filtered states represent absence of ICMP replies.\n`;
  md += `3. Reconnaissance was executed under authorized testing guidelines. Do not conduct unauthorized testing on third-party systems.\n\n`;
  md += `---\n*Generated by AUGUR RECON 2.0 — https://github.com/ishasonaria568-prog/augur-recon*\n`;

  return md;
}

export function generateHtmlReport(data: ScanReportData): string {
  const openPorts = data.ports.filter((p) => p.state === 'open');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AUGUR RECON 2.0 Report — ${data.job.target_input}</title>
  <style>
    :root {
      --bg: #090a0f;
      --card-bg: #11131a;
      --border: #232733;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #dc2626;
      --accent-soft: rgba(220, 38, 38, 0.12);
      --success: #16a34a;
      --success-soft: rgba(22, 163, 74, 0.12);
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      line-height: 1.6;
      padding: 40px 24px;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
    }
    .header {
      border-bottom: 2px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
    }
    .brand-title {
      font-size: 26px;
      font-weight: 800;
      letter-spacing: -0.02em;
      color: #fff;
    }
    .brand-title span { color: var(--accent); }
    .tagline {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 4px;
    }
    .meta-box {
      font-size: 13px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 12px 18px;
      border-radius: 6px;
    }
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 36px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 18px 20px;
      border-radius: 8px;
    }
    .stat-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }
    .stat-value {
      font-size: 30px;
      font-weight: 700;
      color: #fff;
      font-family: var(--font-mono);
      margin-top: 6px;
    }
    .section-title {
      font-size: 18px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-title span.count {
      background: var(--accent-soft);
      color: var(--accent);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-family: var(--font-mono);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 36px;
      font-size: 13px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    th, td {
      padding: 12px 16px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    th {
      background: #0d0e14;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.05em;
    }
    tr:last-child td { border-bottom: none; }
    .mono { font-family: var(--font-mono); }
    .badge-open {
      color: #4ade80;
      font-weight: 600;
    }
    .tls-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
      font-size: 13px;
    }
    .tls-header {
      font-weight: 700;
      color: #fff;
      font-size: 15px;
      margin-bottom: 12px;
      display: flex;
      justify-content: space-between;
    }
    .tls-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 12px;
    }
    .ai-box {
      background: #0d0f17;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 36px;
    }
    .ai-badge {
      font-size: 11px;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
    }
    .footer {
      border-top: 1px solid var(--border);
      padding-top: 24px;
      margin-top: 48px;
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }
    @media print {
      body { background: #fff; color: #000; }
      .stat-card, .tls-card, .ai-box, table { border-color: #ccc; background: #fff; color: #000; }
      th { background: #eee; color: #000; }
      .brand-title { color: #000; }
      .brand-title span { color: #b91c1c; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div>
        <div class="brand-title">AUGUR <span>RECON 2.0</span></div>
        <div class="tagline">AI-Augmented Attack Surface Intelligence — Authorized Reconnaissance Report</div>
      </div>
      <div class="meta-box">
        <div><strong>TARGET:</strong> ${data.job.target_input} (${data.job.resolved_ip})</div>
        <div><strong>SCAN ID:</strong> ${data.job.id}</div>
        <div><strong>COMPLETED:</strong> ${data.job.completed_at || 'In-Progress'} (${data.job.duration_ms || 0}ms)</div>
      </div>
    </header>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-label">Total Probed</div>
        <div class="stat-value">${data.job.total_ports_probed}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Open Ports</div>
        <div class="stat-value" style="color: ${openPorts.length > 0 ? '#ef4444' : '#10b981'};">${openPorts.length}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Services Identified</div>
        <div class="stat-value">${data.services.length}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">DNS Records</div>
        <div class="stat-value">${data.dns.length}</div>
      </div>
    </div>

    <h2 class="section-title">Open Attack Surface & Listening Services <span class="count">${openPorts.length}</span></h2>
    ${
      openPorts.length === 0
        ? '<p style="color: var(--text-muted); margin-bottom: 32px;">No open ports were observed during this scan execution.</p>'
        : `<table>
        <thead>
          <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Identified Service</th>
            <th>Product / Version</th>
            <th>Banner / Probe Output</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          ${openPorts
            .map((p) => {
              const svc = data.services.find((s) => s.port === p.port);
              const svcName = svc ? svc.service_name : 'unknown';
              const prod = svc ? `${svc.product || ''} ${svc.version || ''}`.trim() || '—' : '—';
              const banner = svc ? (svc.banner || '').replace(/</g, '&lt;').replace(/>/g, '&gt;').slice(0, 80) : '—';
              return `<tr>
                <td class="mono" style="font-weight: 700; color: #fff;">${p.port}</td>
                <td class="mono">${p.protocol.toUpperCase()}</td>
                <td class="badge-open">OPEN</td>
                <td class="mono">${svcName}</td>
                <td>${prod}</td>
                <td class="mono" style="font-size: 11px; color: var(--text-muted);">${banner}</td>
                <td class="mono">${p.latency_ms}ms</td>
              </tr>`;
            })
            .join('')}
        </tbody>
      </table>`
    }

    <h2 class="section-title">TLS & Cryptographic Infrastructure <span class="count">${data.tls.length}</span></h2>
    ${
      data.tls.length === 0
        ? '<p style="color: var(--text-muted); margin-bottom: 32px;">No TLS certificates detected.</p>'
        : data.tls
            .map((t) => {
              let sans: string[] = [];
              try { sans = JSON.parse(t.sans_json || '[]'); } catch {}
              return `<div class="tls-card">
                <div class="tls-header">
                  <span>Port ${t.port}/TCP — ${t.subject_cn}</span>
                  <span style="color: ${t.is_valid ? 'var(--success)' : 'var(--accent)'}; font-size: 12px;">
                    ${t.is_valid ? 'VALID CERTIFICATE' : 'VALIDATION ALERT: ' + (t.validation_error || '')}
                  </span>
                </div>
                <div class="tls-grid">
                  <div><strong>Issuer:</strong> ${t.issuer_cn}</div>
                  <div><strong>Expires:</strong> ${t.valid_to} (${t.days_remaining} days left)</div>
                  <div><strong>Cipher:</strong> <span class="mono">${t.cipher}</span></div>
                  <div><strong>Protocol:</strong> <span class="mono">${t.protocol_version}</span></div>
                </div>
                ${sans.length > 0 ? `<div style="margin-top: 10px; color: var(--text-muted); font-size: 12px;"><strong>SANs:</strong> ${sans.join(', ')}</div>` : ''}
              </div>`;
            })
            .join('')
    }

    <h2 class="section-title">DNS Zone & Name Intelligence <span class="count">${data.dns.length}</span></h2>
    ${
      data.dns.length === 0
        ? '<p style="color: var(--text-muted); margin-bottom: 32px;">No DNS records recorded for this target.</p>'
        : `<table>
        <thead>
          <tr>
            <th>Record Type</th>
            <th>Value</th>
            <th>Priority</th>
            <th>TTL</th>
          </tr>
        </thead>
        <tbody>
          ${data.dns
            .map(
              (d) => `<tr>
                <td class="mono" style="font-weight: 700; color: #fff;">${d.record_type}</td>
                <td class="mono" style="word-break: break-all;">${d.value}</td>
                <td class="mono">${d.priority ?? '—'}</td>
                <td class="mono">${d.ttl ? d.ttl + 's' : '—'}</td>
              </tr>`
            )
            .join('')}
        </tbody>
      </table>`
    }

    ${
      data.aiAnalysis
        ? `<div class="ai-box">
          <div class="ai-badge">AI Security Posture Synthesis (${data.aiAnalysis.model})</div>
          <p style="margin-bottom: 16px; font-size: 14px;">${data.aiAnalysis.summary}</p>
        </div>`
        : ''
    }

    <footer class="footer">
      <div>AUGUR RECON 2.0 &bull; Architected by Isha Sonaria &bull; <a href="https://github.com/ishasonaria568-prog" style="color: var(--accent); text-decoration: none;">GitHub</a></div>
      <div>Strictly for authorized security assessments. Never scan systems without authorization.</div>
    </footer>
  </div>
</body>
</html>`;
}

export function generateReport(jobId: string, format: ReportFormat): { content: string; mimeType: string; filename: string } {
  const data = getScanReportData(jobId);
  const safeHost = data.job.normalized_host.replace(/[^a-z0-9_-]/gi, '_');

  switch (format) {
    case 'json':
      return {
        content: generateJsonReport(data),
        mimeType: 'application/json',
        filename: `augur-recon-${safeHost}-${jobId.slice(0, 8)}.json`,
      };
    case 'csv':
      return {
        content: generateCsvReport(data),
        mimeType: 'text/csv',
        filename: `augur-recon-${safeHost}-${jobId.slice(0, 8)}.csv`,
      };
    case 'markdown':
      return {
        content: generateMarkdownReport(data),
        mimeType: 'text/markdown',
        filename: `augur-recon-${safeHost}-${jobId.slice(0, 8)}.md`,
      };
    case 'html':
    default:
      return {
        content: generateHtmlReport(data),
        mimeType: 'text/html',
        filename: `augur-recon-${safeHost}-${jobId.slice(0, 8)}.html`,
      };
  }
}
