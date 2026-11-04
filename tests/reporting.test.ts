/**
 * AUGUR RECON 2.0 - Report Generation Tests
 */

import { describe, it, expect } from 'vitest';
import {
  generateJsonReport,
  generateCsvReport,
  generateMarkdownReport,
  generateHtmlReport,
  ScanReportData,
} from '../src/reporting/report-generator.ts';

describe('Reporting Engine - Multi-Format Output', () => {
  const mockData: ScanReportData = {
    job: {
      id: 'mock-job-12345678',
      target_input: 'example.com',
      normalized_host: 'example.com',
      resolved_ip: '93.184.216.34',
      scan_type: 'tcp',
      status: 'completed',
      ports_spec: 'top20',
      allow_private: 0,
      total_ports_probed: 20,
      open_ports_count: 2,
      started_at: '2026-11-03T23:00:00.000Z',
      completed_at: '2026-11-03T23:00:01.500Z',
      duration_ms: 1500,
      error_message: null,
      created_at: '2026-11-03T23:00:00.000Z',
    },
    ports: [
      { id: 1, job_id: 'mock-job-12345678', port: 80, protocol: 'tcp', state: 'open', reason: 'SYN-ACK', latency_ms: 12 },
      { id: 2, job_id: 'mock-job-12345678', port: 443, protocol: 'tcp', state: 'open', reason: 'SYN-ACK', latency_ms: 15 },
    ],
    services: [
      {
        id: 1,
        job_id: 'mock-job-12345678',
        port: 80,
        protocol: 'tcp',
        service_name: 'http',
        product: 'Apache',
        version: '2.4.58',
        banner: 'HTTP/1.1 200 OK',
        raw_probe_response: 'Server: Apache/2.4.58',
      },
    ],
    tls: [
      {
        id: 1,
        job_id: 'mock-job-12345678',
        port: 443,
        subject_cn: 'example.com',
        issuer_cn: 'DigiCert Global Root G2',
        valid_from: '2026-01-01',
        valid_to: '2027-01-01',
        days_remaining: 150,
        sans_json: '["example.com","www.example.com"]',
        cipher: 'TLS_AES_256_GCM_SHA384',
        protocol_version: 'TLSv1.3',
        is_valid: 1,
        validation_error: null,
      },
    ],
    dns: [
      { id: 1, job_id: 'mock-job-12345678', record_type: 'A', value: '93.184.216.34', priority: null, ttl: 300 },
    ],
  };

  it('generates valid JSON report with complete structure and metadata', () => {
    const jsonStr = generateJsonReport(mockData);
    const parsed = JSON.parse(jsonStr);

    expect(parsed.reportTitle).toContain('AUGUR RECON 2.0');
    expect(parsed.developer).toBe('Isha Sonaria');
    expect(parsed.metadata.target).toBe('example.com');
    expect(parsed.metadata.resolvedIp).toBe('93.184.216.34');
    expect(parsed.findings.openPorts.length).toBe(2);
    expect(parsed.findings.discoveredServices.length).toBe(1);
    expect(parsed.findings.tlsCertificates.length).toBe(1);
    expect(parsed.findings.dnsRecords.length).toBe(1);
  });

  it('generates structured CSV report with columns', () => {
    const csv = generateCsvReport(mockData);
    const lines = csv.split('\n');

    expect(lines[0]).toBe('Category,Port,Protocol,State,Service/Type,Product/Version,Details/Value,LatencyMs/TTL');
    expect(csv).toContain('Port,80,tcp,open');
    expect(csv).toContain('DNS,-,-,-,A');
    expect(csv).toContain('TLS,443,tcp,valid');
  });

  it('generates clean Markdown report with executive summary and tables', () => {
    const md = generateMarkdownReport(mockData);

    expect(md).toContain('# AUGUR RECON 2.0');
    expect(md).toContain('**Target:** `example.com`');
    expect(md).toContain('| **80** | TCP | `http` |');
    expect(md).toContain('DigiCert Global Root G2');
  });

  it('generates standalone HTML report with embedded responsive styles and print support', () => {
    const html = generateHtmlReport(mockData);

    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('AUGUR <span>RECON 2.0</span>');
    expect(html).toContain('example.com');
    expect(html).toContain('Apache 2.4.58');
    expect(html).toContain('@media print');
  });
});
