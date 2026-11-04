/**
 * AUGUR RECON 2.0 - Scan Comparison Engine
 * Computes deterministic diffs between two reconnaissance jobs to detect attack surface drift:
 * new ports, closed ports, service changes, certificate alterations, and DNS modifications.
 */

import { getDatabase, ScanJobRecord, PortResultRecord, ServiceResultRecord, TlsResultRecord, DnsResultRecord } from '../db/database.ts';

export interface ScanDiffResult {
  oldJob: ScanJobRecord;
  newJob: ScanJobRecord;
  timeDeltaMs: number;
  ipChanged: boolean;
  oldIp: string;
  newIp: string;
  portsDiff: {
    newlyOpened: PortResultRecord[];
    newlyClosed: PortResultRecord[];
    unchangedOpen: PortResultRecord[];
  };
  servicesDiff: {
    added: ServiceResultRecord[];
    removed: ServiceResultRecord[];
    modified: Array<{
      port: number;
      oldService: string;
      newService: string;
      oldBanner: string;
      newBanner: string;
    }>;
  };
  tlsDiff: {
    added: TlsResultRecord[];
    removed: TlsResultRecord[];
    changed: Array<{
      port: number;
      oldIssuer: string;
      newIssuer: string;
      oldExpiry: string;
      newExpiry: string;
    }>;
  };
  dnsDiff: {
    added: DnsResultRecord[];
    removed: DnsResultRecord[];
  };
}

export function compareScans(oldJobId: string, newJobId: string): ScanDiffResult {
  const db = getDatabase();
  const oldJob = db.getScanJob(oldJobId);
  const newJob = db.getScanJob(newJobId);

  if (!oldJob) throw new Error(`Historical scan job ${oldJobId} not found in database.`);
  if (!newJob) throw new Error(`Target scan job ${newJobId} not found in database.`);

  const oldTime = new Date(oldJob.created_at).getTime();
  const newTime = new Date(newJob.created_at).getTime();
  const timeDeltaMs = Math.abs(newTime - oldTime);

  const oldPorts = db.getPortResults(oldJobId);
  const newPorts = db.getPortResults(newJobId);

  const oldOpenMap = new Map<number, PortResultRecord>();
  for (const p of oldPorts) {
    if (p.state === 'open') oldOpenMap.set(p.port, p);
  }

  const newOpenMap = new Map<number, PortResultRecord>();
  for (const p of newPorts) {
    if (p.state === 'open') newOpenMap.set(p.port, p);
  }

  const newlyOpened: PortResultRecord[] = [];
  const unchangedOpen: PortResultRecord[] = [];
  const newlyClosed: PortResultRecord[] = [];

  for (const [port, pRecord] of newOpenMap.entries()) {
    if (!oldOpenMap.has(port)) {
      newlyOpened.push(pRecord);
    } else {
      unchangedOpen.push(pRecord);
    }
  }

  for (const [port, pRecord] of oldOpenMap.entries()) {
    if (!newOpenMap.has(port)) {
      newlyClosed.push(pRecord);
    }
  }

  // Services Diff
  const oldServices = db.getServiceResults(oldJobId);
  const newServices = db.getServiceResults(newJobId);

  const oldServiceMap = new Map<number, ServiceResultRecord>();
  for (const s of oldServices) oldServiceMap.set(s.port, s);

  const newServiceMap = new Map<number, ServiceResultRecord>();
  for (const s of newServices) newServiceMap.set(s.port, s);

  const addedServices: ServiceResultRecord[] = [];
  const removedServices: ServiceResultRecord[] = [];
  const modifiedServices: Array<{
    port: number;
    oldService: string;
    newService: string;
    oldBanner: string;
    newBanner: string;
  }> = [];

  for (const [port, sRecord] of newServiceMap.entries()) {
    if (!oldServiceMap.has(port)) {
      addedServices.push(sRecord);
    } else {
      const oldS = oldServiceMap.get(port)!;
      if (oldS.service_name !== sRecord.service_name || oldS.banner !== sRecord.banner) {
        modifiedServices.push({
          port,
          oldService: oldS.service_name,
          newService: sRecord.service_name,
          oldBanner: oldS.banner,
          newBanner: sRecord.banner,
        });
      }
    }
  }

  for (const [port, sRecord] of oldServiceMap.entries()) {
    if (!newServiceMap.has(port)) {
      removedServices.push(sRecord);
    }
  }

  // TLS Diff
  const oldTls = db.getTlsResults(oldJobId);
  const newTls = db.getTlsResults(newJobId);
  const oldTlsMap = new Map<number, TlsResultRecord>();
  for (const t of oldTls) oldTlsMap.set(t.port, t);
  const newTlsMap = new Map<number, TlsResultRecord>();
  for (const t of newTls) newTlsMap.set(t.port, t);

  const addedTls: TlsResultRecord[] = [];
  const removedTls: TlsResultRecord[] = [];
  const changedTls: Array<{
    port: number;
    oldIssuer: string;
    newIssuer: string;
    oldExpiry: string;
    newExpiry: string;
  }> = [];

  for (const [port, tRecord] of newTlsMap.entries()) {
    if (!oldTlsMap.has(port)) {
      addedTls.push(tRecord);
    } else {
      const oldT = oldTlsMap.get(port)!;
      if (oldT.issuer_cn !== tRecord.issuer_cn || oldT.valid_to !== tRecord.valid_to) {
        changedTls.push({
          port,
          oldIssuer: oldT.issuer_cn,
          newIssuer: tRecord.issuer_cn,
          oldExpiry: oldT.valid_to,
          newExpiry: tRecord.valid_to,
        });
      }
    }
  }

  for (const [port, tRecord] of oldTlsMap.entries()) {
    if (!newTlsMap.has(port)) removedTls.push(tRecord);
  }

  // DNS Diff
  const oldDns = db.getDnsResults(oldJobId);
  const newDns = db.getDnsResults(newJobId);

  const oldDnsSet = new Set(oldDns.map((d) => `${d.record_type}:${d.value}`));
  const newDnsSet = new Set(newDns.map((d) => `${d.record_type}:${d.value}`));

  const addedDns = newDns.filter((d) => !oldDnsSet.has(`${d.record_type}:${d.value}`));
  const removedDns = oldDns.filter((d) => !newDnsSet.has(`${d.record_type}:${d.value}`));

  return {
    oldJob,
    newJob,
    timeDeltaMs,
    ipChanged: oldJob.resolved_ip !== newJob.resolved_ip,
    oldIp: oldJob.resolved_ip,
    newIp: newJob.resolved_ip,
    portsDiff: {
      newlyOpened,
      newlyClosed,
      unchangedOpen,
    },
    servicesDiff: {
      added: addedServices,
      removed: removedServices,
      modified: modifiedServices,
    },
    tlsDiff: {
      added: addedTls,
      removed: removedTls,
      changed: changedTls,
    },
    dnsDiff: {
      added: addedDns,
      removed: removedDns,
    },
  };
}
