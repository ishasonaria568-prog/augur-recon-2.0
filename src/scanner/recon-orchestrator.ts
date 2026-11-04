/**
 * AUGUR RECON 2.0 - Network Reconnaissance Orchestrator
 * Coordinates target validation, TCP/UDP scanning, service identification,
 * TLS analysis, DNS enumeration, and database persistence.
 */

import crypto from 'node:crypto';
import { validateScanTarget, ValidatedTarget } from '../security/target-validator.ts';
import { logSecurityAudit } from '../security/audit-logger.ts';
import { parsePortSpecification } from './port-parser.ts';
import { scanTcpPorts, TcpProbeResult } from './tcp-scanner.ts';
import { scanUdpPorts, UdpProbeResult, COMMON_UDP_PORTS } from './udp-scanner.ts';
import { identifyService, DiscoveredService } from './service-detector.ts';
import { inspectTlsCertificate, TlsInspectionResult } from './tls-inspector.ts';
import { enumerateDns, DiscoveredDnsRecord } from './dns-enumerator.ts';
import {
  getDatabase,
  ScanJobRecord,
  PortResultRecord,
  ServiceResultRecord,
  TlsResultRecord,
  DnsResultRecord,
} from '../db/database.ts';

export interface ScanExecutionOptions {
  target: string;
  ports?: string;
  concurrency?: number;
  timeoutMs?: number;
  enableUdp?: boolean;
  allowPrivate?: boolean;
  actor?: string;
  onProgress?: (event: ReconProgressEvent) => void;
  signal?: AbortSignal;
}

export interface ReconProgressEvent {
  jobId: string;
  phase: 'validating' | 'dns' | 'ports' | 'services' | 'tls' | 'finalizing';
  message: string;
  percent: number;
  openPortsCount: number;
}

export interface FullScanResult {
  job: ScanJobRecord;
  targetInfo: ValidatedTarget;
  ports: PortResultRecord[];
  services: ServiceResultRecord[];
  tlsResults: TlsResultRecord[];
  dnsResults: DnsResultRecord[];
}

export async function executeReconScan(options: ScanExecutionOptions): Promise<FullScanResult> {
  const jobId = crypto.randomUUID();
  const db = getDatabase();
  const startTime = Date.now();
  const actor = options.actor || 'cli-operator';

  // 1. Target Validation & Security Policy Enforcement
  if (options.onProgress) {
    options.onProgress({
      jobId,
      phase: 'validating',
      message: `Enforcing security policies for target ${options.target}...`,
      percent: 5,
      openPortsCount: 0,
    });
  }

  let validated: ValidatedTarget;
  try {
    validated = await validateScanTarget(options.target, {
      allowPrivate: options.allowPrivate,
    });

    logSecurityAudit({
      action: 'SCAN_INITIATED',
      target: options.target,
      actor,
      status: 'success',
      details: {
        jobId,
        normalizedHost: validated.normalizedHost,
        primaryIp: validated.primaryIp,
        allowPrivate: options.allowPrivate || false,
      },
    });
  } catch (err: any) {
    logSecurityAudit({
      action: 'SCAN_REJECTED',
      target: options.target,
      actor,
      status: 'blocked',
      details: {
        reason: err.message,
        code: err.code,
      },
    });
    throw err;
  }

  const portsToScan = parsePortSpecification(options.ports);

  // Initialize DB Job Record
  const jobRecord: ScanJobRecord = {
    id: jobId,
    target_input: options.target,
    normalized_host: validated.normalizedHost,
    resolved_ip: validated.primaryIp,
    scan_type: options.enableUdp ? 'tcp+udp' : 'tcp',
    status: 'running',
    ports_spec: options.ports || 'top20',
    allow_private: options.allowPrivate ? 1 : 0,
    total_ports_probed: portsToScan.length,
    open_ports_count: 0,
    started_at: new Date(startTime).toISOString(),
    completed_at: null,
    duration_ms: null,
    error_message: null,
    created_at: new Date(startTime).toISOString(),
  };
  db.createScanJob(jobRecord);

  try {
    // 2. DNS Enumeration
    if (options.onProgress) {
      options.onProgress({
        jobId,
        phase: 'dns',
        message: 'Enumerating DNS zone records & PTR records...',
        percent: 15,
        openPortsCount: 0,
      });
    }

    const rawDns = await enumerateDns(validated.normalizedHost, validated.primaryIp);
    const dnsRecords: DnsResultRecord[] = rawDns.map((r) => ({
      job_id: jobId,
      record_type: r.recordType,
      value: r.value,
      priority: r.priority ?? null,
      ttl: r.ttl ?? null,
    }));
    db.saveDnsResults(dnsRecords);

    // 3. Port Reconnaissance (TCP + optional UDP)
    if (options.onProgress) {
      options.onProgress({
        jobId,
        phase: 'ports',
        message: `Scanning ${portsToScan.length} ports across target ${validated.primaryIp}...`,
        percent: 25,
        openPortsCount: 0,
      });
    }

    let openPortsCount = 0;
    const portResults: PortResultRecord[] = [];

    // TCP scan
    const tcpResults = await scanTcpPorts({
      host: validated.primaryIp,
      ports: portsToScan,
      timeoutMs: options.timeoutMs || 1500,
      concurrency: options.concurrency || 35,
      signal: options.signal,
      onProgress: (probed, total, latest) => {
        if (latest?.state === 'open') {
          openPortsCount++;
        }
        if (options.onProgress) {
          const progressPercent = Math.min(70, Math.round(25 + (probed / total) * 45));
          options.onProgress({
            jobId,
            phase: 'ports',
            message: `Probed ${probed}/${total} ports (${openPortsCount} open)...`,
            percent: progressPercent,
            openPortsCount,
          });
        }
      },
    });

    for (const res of tcpResults) {
      portResults.push({
        job_id: jobId,
        port: res.port,
        protocol: 'tcp',
        state: res.state,
        reason: res.reason,
        latency_ms: res.latencyMs,
      });
    }

    // UDP scan if enabled
    if (options.enableUdp) {
      const udpResults = await scanUdpPorts(validated.primaryIp, COMMON_UDP_PORTS, options.timeoutMs || 1500);
      for (const res of udpResults) {
        if (res.state === 'open') openPortsCount++;
        portResults.push({
          job_id: jobId,
          port: res.port,
          protocol: 'udp',
          state: res.state,
          reason: res.reason,
          latency_ms: res.latencyMs,
        });
      }
    }

    db.savePortResults(portResults);
    db.updateScanJob(jobId, {
      open_ports_count: openPortsCount,
    });

    // 4. Service Identification on Open Ports
    const openPorts = portResults.filter((p) => p.state === 'open');
    const serviceRecords: ServiceResultRecord[] = [];

    if (openPorts.length > 0) {
      if (options.onProgress) {
        options.onProgress({
          jobId,
          phase: 'services',
          message: `Fingerprinting application services on ${openPorts.length} open ports...`,
          percent: 75,
          openPortsCount,
        });
      }

      for (let i = 0; i < openPorts.length; i++) {
        const p = openPorts[i];
        if (options.signal?.aborted) break;
        const svc = await identifyService(
          validated.primaryIp,
          p.port,
          validated.normalizedHost,
          options.timeoutMs || 2500
        );
        serviceRecords.push({
          job_id: jobId,
          port: p.port,
          protocol: p.protocol,
          service_name: svc.serviceName,
          product: svc.product || '',
          version: svc.version || '',
          banner: svc.banner || '',
          raw_probe_response: svc.rawResponse || '',
        });
      }

      db.saveServiceResults(serviceRecords);
    }

    // 5. TLS Certificate Inspection
    const tlsRecords: TlsResultRecord[] = [];
    const tlsCandidatePorts = openPorts
      .filter((p) => [443, 8443, 9443, 2053, 2083, 2087, 2096, 465, 993, 995].includes(p.port) || p.port === 8080)
      .map((p) => p.port);

    if (tlsCandidatePorts.length > 0) {
      if (options.onProgress) {
        options.onProgress({
          jobId,
          phase: 'tls',
          message: `Extracting TLS certificates and cipher suites on ports: ${tlsCandidatePorts.join(', ')}...`,
          percent: 88,
          openPortsCount,
        });
      }

      for (const port of tlsCandidatePorts) {
        if (options.signal?.aborted) break;
        const tlsRes = await inspectTlsCertificate(
          validated.primaryIp,
          port,
          validated.normalizedHost,
          options.timeoutMs || 3000
        );
        if (tlsRes) {
          tlsRecords.push({
            job_id: jobId,
            port,
            subject_cn: tlsRes.subjectCn,
            issuer_cn: tlsRes.issuerCn,
            valid_from: tlsRes.validFrom,
            valid_to: tlsRes.validTo,
            days_remaining: tlsRes.daysRemaining,
            sans_json: JSON.stringify(tlsRes.sans),
            cipher: tlsRes.cipher,
            protocol_version: tlsRes.protocolVersion,
            is_valid: tlsRes.isValid ? 1 : 0,
            validation_error: tlsRes.validationError || null,
          });
        }
      }

      db.saveTlsResults(tlsRecords);
    }

    // 6. Complete and finalize scan job
    const endTime = Date.now();
    const durationMs = endTime - startTime;

    db.updateScanJob(jobId, {
      status: 'completed',
      completed_at: new Date(endTime).toISOString(),
      duration_ms: durationMs,
      open_ports_count: openPortsCount,
    });

    logSecurityAudit({
      action: 'SCAN_COMPLETED',
      target: options.target,
      actor,
      status: 'success',
      details: {
        jobId,
        durationMs,
        openPortsCount,
        servicesFound: serviceRecords.length,
        tlsCertsFound: tlsRecords.length,
      },
    });

    if (options.onProgress) {
      options.onProgress({
        jobId,
        phase: 'finalizing',
        message: `Scan successfully completed in ${durationMs}ms.`,
        percent: 100,
        openPortsCount,
      });
    }

    const updatedJob = db.getScanJob(jobId)!;

    return {
      job: updatedJob,
      targetInfo: validated,
      ports: portResults,
      services: serviceRecords,
      tlsResults: tlsRecords,
      dnsResults: dnsRecords,
    };
  } catch (err: any) {
    const endTime = Date.now();
    db.updateScanJob(jobId, {
      status: 'failed',
      completed_at: new Date(endTime).toISOString(),
      duration_ms: endTime - startTime,
      error_message: err.message || 'Unknown reconnaissance error',
    });

    logSecurityAudit({
      action: 'SCAN_FAILED',
      target: options.target,
      actor,
      status: 'failure',
      details: {
        jobId,
        error: err.message,
      },
    });

    throw err;
  }
}
