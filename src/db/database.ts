/**
 * AUGUR RECON 2.0 - SQLite Database & Migration Engine
 * Provides persistent local storage, transactions, migrations, and query interfaces.
 */

import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

export interface ScanJobRecord {
  id: string;
  target_input: string;
  normalized_host: string;
  resolved_ip: string;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  ports_spec: string;
  allow_private: number;
  total_ports_probed: number;
  open_ports_count: number;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  error_message: string | null;
  created_at: string;
}

export interface PortResultRecord {
  id?: number;
  job_id: string;
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered' | 'open/filtered';
  reason: string;
  latency_ms: number;
}

export interface ServiceResultRecord {
  id?: number;
  job_id: string;
  port: number;
  protocol: string;
  service_name: string;
  product: string;
  version: string;
  banner: string;
  raw_probe_response: string;
}

export interface TlsResultRecord {
  id?: number;
  job_id: string;
  port: number;
  subject_cn: string;
  issuer_cn: string;
  valid_from: string;
  valid_to: string;
  days_remaining: number;
  sans_json: string;
  cipher: string;
  protocol_version: string;
  is_valid: number;
  validation_error: string | null;
}

export interface DnsResultRecord {
  id?: number;
  job_id: string;
  record_type: string;
  value: string;
  priority: number | null;
  ttl: number | null;
}

export interface AuditEventRecord {
  id?: number;
  timestamp: string;
  action: string;
  target: string;
  actor: string;
  status: 'success' | 'failure' | 'blocked';
  details_json: string;
}

export interface AiAnalysisRecord {
  id?: number;
  job_id: string;
  model: string;
  summary: string;
  key_findings_json: string;
  recommendations_json: string;
  created_at: string;
}

export class ReconDatabase {
  private db: Database.Database;
  private dbPath: string;

  constructor(customPath?: string) {
    if (customPath) {
      this.dbPath = customPath;
    } else {
      const dataDir = process.env.AUGUR_DATA_DIR || path.resolve(process.cwd(), '.augur');
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      this.dbPath = path.join(dataDir, 'augur-recon.db');
    }

    this.db = new Database(this.dbPath);
    // Enforce WAL mode for maximum concurrency and performance
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.runMigrations();
  }

  private runMigrations() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS scan_jobs (
        id TEXT PRIMARY KEY,
        target_input TEXT NOT NULL,
        normalized_host TEXT NOT NULL,
        resolved_ip TEXT NOT NULL,
        scan_type TEXT NOT NULL DEFAULT 'standard',
        status TEXT NOT NULL DEFAULT 'pending',
        ports_spec TEXT NOT NULL,
        allow_private INTEGER NOT NULL DEFAULT 0,
        total_ports_probed INTEGER NOT NULL DEFAULT 0,
        open_ports_count INTEGER NOT NULL DEFAULT 0,
        started_at TEXT,
        completed_at TEXT,
        duration_ms INTEGER,
        error_message TEXT,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_scan_jobs_host ON scan_jobs(normalized_host);

      CREATE TABLE IF NOT EXISTS port_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        state TEXT NOT NULL,
        reason TEXT,
        latency_ms INTEGER,
        FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_port_results_job ON port_results(job_id);

      CREATE TABLE IF NOT EXISTS service_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        service_name TEXT NOT NULL,
        product TEXT,
        version TEXT,
        banner TEXT,
        raw_probe_response TEXT,
        FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_service_results_job ON service_results(job_id);

      CREATE TABLE IF NOT EXISTS tls_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        port INTEGER NOT NULL,
        subject_cn TEXT,
        issuer_cn TEXT,
        valid_from TEXT,
        valid_to TEXT,
        days_remaining INTEGER,
        sans_json TEXT,
        cipher TEXT,
        protocol_version TEXT,
        is_valid INTEGER DEFAULT 1,
        validation_error TEXT,
        FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_tls_results_job ON tls_results(job_id);

      CREATE TABLE IF NOT EXISTS dns_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        record_type TEXT NOT NULL,
        value TEXT NOT NULL,
        priority INTEGER,
        ttl INTEGER,
        FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_dns_results_job ON dns_results(job_id);

      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        actor TEXT NOT NULL,
        status TEXT NOT NULL,
        details_json TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC);

      CREATE TABLE IF NOT EXISTS config_entries (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS ai_analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL UNIQUE,
        model TEXT NOT NULL,
        summary TEXT NOT NULL,
        key_findings_json TEXT NOT NULL,
        recommendations_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
      );
    `);
  }

  public getDbInstance(): Database.Database {
    return this.db;
  }

  // --- Scan Jobs API ---

  public createScanJob(job: ScanJobRecord) {
    const stmt = this.db.prepare(`
      INSERT INTO scan_jobs (
        id, target_input, normalized_host, resolved_ip, scan_type, status,
        ports_spec, allow_private, total_ports_probed, open_ports_count,
        started_at, completed_at, duration_ms, error_message, created_at
      ) VALUES (
        @id, @target_input, @normalized_host, @resolved_ip, @scan_type, @status,
        @ports_spec, @allow_private, @total_ports_probed, @open_ports_count,
        @started_at, @completed_at, @duration_ms, @error_message, @created_at
      )
    `);
    stmt.run(job);
  }

  public updateScanJob(id: string, updates: Partial<ScanJobRecord>) {
    const keys = Object.keys(updates);
    if (keys.length === 0) return;
    const setClause = keys.map((k) => `${k} = ?`).join(', ');
    const values = keys.map((k) => (updates as any)[k]);
    values.push(id);
    const stmt = this.db.prepare(`UPDATE scan_jobs SET ${setClause} WHERE id = ?`);
    stmt.run(...values);
  }

  public getScanJob(id: string): ScanJobRecord | undefined {
    const stmt = this.db.prepare('SELECT * FROM scan_jobs WHERE id = ?');
    return stmt.get(id) as ScanJobRecord | undefined;
  }

  public listScanJobs(limit = 100, offset = 0, search?: string): ScanJobRecord[] {
    if (search && search.trim()) {
      const q = `%${search.trim()}%`;
      const stmt = this.db.prepare(
        'SELECT * FROM scan_jobs WHERE normalized_host LIKE ? OR resolved_ip LIKE ? OR id LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
      );
      return stmt.all(q, q, q, limit, offset) as ScanJobRecord[];
    }
    const stmt = this.db.prepare('SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ? OFFSET ?');
    return stmt.all(limit, offset) as ScanJobRecord[];
  }

  public deleteScanJob(id: string): boolean {
    const stmt = this.db.prepare('DELETE FROM scan_jobs WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  // --- Port Results ---

  public savePortResults(results: PortResultRecord[]) {
    if (results.length === 0) return;
    const stmt = this.db.prepare(`
      INSERT INTO port_results (job_id, port, protocol, state, reason, latency_ms)
      VALUES (@job_id, @port, @protocol, @state, @reason, @latency_ms)
    `);
    const insertMany = this.db.transaction((items: PortResultRecord[]) => {
      for (const item of items) stmt.run(item);
    });
    insertMany(results);
  }

  public getPortResults(jobId: string): PortResultRecord[] {
    const stmt = this.db.prepare('SELECT * FROM port_results WHERE job_id = ? ORDER BY port ASC');
    return stmt.all(jobId) as PortResultRecord[];
  }

  // --- Services ---

  public saveServiceResults(services: ServiceResultRecord[]) {
    if (services.length === 0) return;
    const stmt = this.db.prepare(`
      INSERT INTO service_results (job_id, port, protocol, service_name, product, version, banner, raw_probe_response)
      VALUES (@job_id, @port, @protocol, @service_name, @product, @version, @banner, @raw_probe_response)
    `);
    const insertMany = this.db.transaction((items: ServiceResultRecord[]) => {
      for (const item of items) stmt.run(item);
    });
    insertMany(services);
  }

  public getServiceResults(jobId: string): ServiceResultRecord[] {
    const stmt = this.db.prepare('SELECT * FROM service_results WHERE job_id = ? ORDER BY port ASC');
    return stmt.all(jobId) as ServiceResultRecord[];
  }

  // --- TLS Results ---

  public saveTlsResults(tls: TlsResultRecord[]) {
    if (tls.length === 0) return;
    const stmt = this.db.prepare(`
      INSERT INTO tls_results (job_id, port, subject_cn, issuer_cn, valid_from, valid_to, days_remaining, sans_json, cipher, protocol_version, is_valid, validation_error)
      VALUES (@job_id, @port, @subject_cn, @issuer_cn, @valid_from, @valid_to, @days_remaining, @sans_json, @cipher, @protocol_version, @is_valid, @validation_error)
    `);
    const insertMany = this.db.transaction((items: TlsResultRecord[]) => {
      for (const item of items) stmt.run(item);
    });
    insertMany(tls);
  }

  public getTlsResults(jobId: string): TlsResultRecord[] {
    const stmt = this.db.prepare('SELECT * FROM tls_results WHERE job_id = ? ORDER BY port ASC');
    return stmt.all(jobId) as TlsResultRecord[];
  }

  // --- DNS Results ---

  public saveDnsResults(dnsRecords: DnsResultRecord[]) {
    if (dnsRecords.length === 0) return;
    const stmt = this.db.prepare(`
      INSERT INTO dns_results (job_id, record_type, value, priority, ttl)
      VALUES (@job_id, @record_type, @value, @priority, @ttl)
    `);
    const insertMany = this.db.transaction((items: DnsResultRecord[]) => {
      for (const item of items) stmt.run(item);
    });
    insertMany(dnsRecords);
  }

  public getDnsResults(jobId: string): DnsResultRecord[] {
    const stmt = this.db.prepare('SELECT * FROM dns_results WHERE job_id = ? ORDER BY record_type ASC, priority ASC');
    return stmt.all(jobId) as DnsResultRecord[];
  }

  // --- Audit Events ---

  public logAudit(event: {
    action: string;
    target: string;
    actor: string;
    status: 'success' | 'failure' | 'blocked';
    details?: any;
  }) {
    const stmt = this.db.prepare(`
      INSERT INTO audit_events (timestamp, action, target, actor, status, details_json)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      new Date().toISOString(),
      event.action,
      event.target,
      event.actor,
      event.status,
      JSON.stringify(event.details || {})
    );
  }

  public listAuditEvents(limit = 100): AuditEventRecord[] {
    const stmt = this.db.prepare('SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?');
    return stmt.all(limit) as AuditEventRecord[];
  }

  // --- AI Analysis ---

  public saveAiAnalysis(analysis: AiAnalysisRecord) {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO ai_analyses (job_id, model, summary, key_findings_json, recommendations_json, created_at)
      VALUES (@job_id, @model, @summary, @key_findings_json, @recommendations_json, @created_at)
    `);
    stmt.run(analysis);
  }

  public getAiAnalysis(jobId: string): AiAnalysisRecord | undefined {
    const stmt = this.db.prepare('SELECT * FROM ai_analyses WHERE job_id = ?');
    return stmt.get(jobId) as AiAnalysisRecord | undefined;
  }

  // --- Config ---

  public getConfig(key: string): string | null {
    const stmt = this.db.prepare('SELECT value FROM config_entries WHERE key = ?');
    const row = stmt.get(key) as { value: string } | undefined;
    return row ? row.value : null;
  }

  public setConfig(key: string, value: string) {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO config_entries (key, value, updated_at)
      VALUES (?, ?, ?)
    `);
    stmt.run(key, value, new Date().toISOString());
  }

  public getAllConfig(): Record<string, string> {
    const stmt = this.db.prepare('SELECT key, value FROM config_entries');
    const rows = stmt.all() as { key: string; value: string }[];
    const result: Record<string, string> = {};
    for (const r of rows) result[r.key] = r.value;
    return result;
  }

  // Aggregate stats
  public getOverviewStats() {
    const totalScans = (this.db.prepare('SELECT COUNT(*) as count FROM scan_jobs').get() as any).count;
    const completedScans = (this.db.prepare("SELECT COUNT(*) as count FROM scan_jobs WHERE status = 'completed'").get() as any).count;
    const totalOpenPorts = (this.db.prepare("SELECT COUNT(*) as count FROM port_results WHERE state = 'open'").get() as any).count;
    const uniqueTargets = (this.db.prepare('SELECT COUNT(DISTINCT normalized_host) as count FROM scan_jobs').get() as any).count;

    return {
      totalScans,
      completedScans,
      totalOpenPorts,
      uniqueTargets,
    };
  }

  public close() {
    this.db.close();
  }
}

// Global singleton instance
let defaultDbInstance: ReconDatabase | null = null;

export function getDatabase(): ReconDatabase {
  if (!defaultDbInstance) {
    defaultDbInstance = new ReconDatabase();
  }
  return defaultDbInstance;
}
