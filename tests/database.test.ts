/**
 * AUGUR RECON 2.0 - SQLite Database & Diff Operations Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ReconDatabase } from '../src/db/database.ts';
import fs from 'node:fs';
import path from 'node:path';

describe('Database & Scan Persistence Engine', () => {
  let db: ReconDatabase;
  const testDbPath = path.resolve(process.cwd(), '.test-augur.db');

  beforeEach(() => {
    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
    db = new ReconDatabase(testDbPath);
  });

  afterEach(() => {
    db.close();
    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
  });

  it('initializes tables and runs migrations', () => {
    const rawDb = db.getDbInstance();
    const tables = rawDb.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    const tableNames = tables.map((t: any) => t.name);

    expect(tableNames).toContain('scan_jobs');
    expect(tableNames).toContain('port_results');
    expect(tableNames).toContain('service_results');
    expect(tableNames).toContain('tls_results');
    expect(tableNames).toContain('dns_results');
    expect(tableNames).toContain('audit_events');
  });

  it('creates, retrieves, and updates scan job records', () => {
    const jobId = 'test-job-1';
    db.createScanJob({
      id: jobId,
      target_input: 'example.com',
      normalized_host: 'example.com',
      resolved_ip: '93.184.216.34',
      scan_type: 'tcp',
      status: 'running',
      ports_spec: 'top20',
      allow_private: 0,
      total_ports_probed: 20,
      open_ports_count: 0,
      started_at: new Date().toISOString(),
      completed_at: null,
      duration_ms: null,
      error_message: null,
      created_at: new Date().toISOString(),
    });

    const job = db.getScanJob(jobId);
    expect(job).toBeDefined();
    expect(job?.normalized_host).toBe('example.com');
    expect(job?.status).toBe('running');

    db.updateScanJob(jobId, { status: 'completed', open_ports_count: 2, duration_ms: 1250 });
    const updated = db.getScanJob(jobId);
    expect(updated?.status).toBe('completed');
    expect(updated?.open_ports_count).toBe(2);
    expect(updated?.duration_ms).toBe(1250);
  });

  it('persists port and service results in batch transactions', () => {
    const jobId = 'test-job-results';
    db.createScanJob({
      id: jobId,
      target_input: 'target.local',
      normalized_host: 'target.local',
      resolved_ip: '192.168.1.10',
      scan_type: 'tcp',
      status: 'completed',
      ports_spec: '80,443',
      allow_private: 1,
      total_ports_probed: 2,
      open_ports_count: 2,
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      duration_ms: 50,
      error_message: null,
      created_at: new Date().toISOString(),
    });

    db.savePortResults([
      { job_id: jobId, port: 80, protocol: 'tcp', state: 'open', reason: 'SYN-ACK', latency_ms: 5 },
      { job_id: jobId, port: 443, protocol: 'tcp', state: 'open', reason: 'SYN-ACK', latency_ms: 8 },
    ]);

    db.saveServiceResults([
      {
        job_id: jobId,
        port: 80,
        protocol: 'tcp',
        service_name: 'http',
        product: 'nginx',
        version: '1.24.0',
        banner: 'HTTP/1.1 200 OK (nginx/1.24.0)',
        raw_probe_response: 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0',
      },
    ]);

    const ports = db.getPortResults(jobId);
    expect(ports.length).toBe(2);
    expect(ports[0].port).toBe(80);
    expect(ports[1].port).toBe(443);

    const services = db.getServiceResults(jobId);
    expect(services.length).toBe(1);
    expect(services[0].product).toBe('nginx');
  });

  it('records audit log entries', () => {
    db.logAudit({
      action: 'SCAN_INITIATED',
      target: 'example.com',
      actor: 'unit-test',
      status: 'success',
      details: { test: true },
    });

    const logs = db.listAuditEvents(10);
    expect(logs.length).toBeGreaterThan(0);
    expect(logs[0].action).toBe('SCAN_INITIATED');
    expect(logs[0].actor).toBe('unit-test');
  });
});
