/**
 * AUGUR RECON 2.0 - Structured Audit Logger
 * Logs security decisions, scan authorizations, target evaluations, and administrative changes.
 */

import { getDatabase } from '../db/database.ts';

export interface AuditLogOptions {
  action: string;
  target: string;
  actor: string;
  status: 'success' | 'failure' | 'blocked';
  details?: Record<string, any>;
}

export function logSecurityAudit(options: AuditLogOptions): void {
  const timestamp = new Date().toISOString();
  try {
    const db = getDatabase();
    db.logAudit(options);
  } catch (err) {
    // Failsafe console log if database write encounters temporary lock
    console.error(`[AUDIT_WRITE_ERROR] Failed to write audit log to database:`, err);
  }

  // Also output structured stdout for DevSecOps pipelines / systemd journal
  const logPayload = {
    app: 'augur-recon',
    level: options.status === 'blocked' ? 'WARN' : 'INFO',
    timestamp,
    ...options,
  };
  console.log(`[AUDIT] ${JSON.stringify(logPayload)}`);
}
