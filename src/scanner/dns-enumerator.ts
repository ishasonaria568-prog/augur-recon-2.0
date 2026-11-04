/**
 * AUGUR RECON 2.0 - DNS Enumeration & Intelligence Engine
 * Queries A, AAAA, MX, NS, TXT, CNAME, SOA, and PTR records with TTL and priority data.
 */

import dns from 'node:dns/promises';
import net from 'node:net';

export interface DiscoveredDnsRecord {
  recordType: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'CNAME' | 'SOA' | 'PTR';
  value: string;
  priority?: number;
  ttl?: number;
}

export async function enumerateDns(host: string, primaryIp?: string): Promise<DiscoveredDnsRecord[]> {
  const records: DiscoveredDnsRecord[] = [];
  const isIp = net.isIP(host) !== 0;

  // 1. Reverse DNS (PTR) lookup if an IP is provided or host is IP
  const targetIp = isIp ? host : primaryIp;
  if (targetIp) {
    try {
      const ptrHostnames = await dns.reverse(targetIp);
      for (const ptr of ptrHostnames) {
        records.push({
          recordType: 'PTR',
          value: ptr,
        });
      }
    } catch {
      // Normal if PTR is unassigned
    }
  }

  // If host itself is an IP, domain queries (MX, NS, SOA, etc.) are skipped
  if (isIp) {
    return records;
  }

  // Helper to safely execute a DNS query
  async function querySafe<T>(fn: () => Promise<T>, parser: (result: T) => void) {
    try {
      const res = await fn();
      parser(res);
    } catch {
      // Non-fatal if record type does not exist on zone (NODATA / ENOTFOUND)
    }
  }

  // 2. A Records (IPv4)
  await querySafe(
    () => dns.resolve4(host, { ttl: true }),
    (results) => {
      for (const r of results) {
        records.push({ recordType: 'A', value: r.address, ttl: r.ttl });
      }
    }
  );

  // 3. AAAA Records (IPv6)
  await querySafe(
    () => dns.resolve6(host, { ttl: true }),
    (results) => {
      for (const r of results) {
        records.push({ recordType: 'AAAA', value: r.address, ttl: r.ttl });
      }
    }
  );

  // 4. MX Records (Mail Exchangers)
  await querySafe(
    () => dns.resolveMx(host),
    (results) => {
      for (const r of results) {
        records.push({ recordType: 'MX', value: r.exchange, priority: r.priority });
      }
    }
  );

  // 5. NS Records (Name Servers)
  await querySafe(
    () => dns.resolveNs(host),
    (results) => {
      for (const ns of results) {
        records.push({ recordType: 'NS', value: ns });
      }
    }
  );

  // 6. TXT Records (SPF, DKIM, DMARC, Domain verification)
  await querySafe(
    () => dns.resolveTxt(host),
    (results) => {
      for (const chunk of results) {
        records.push({ recordType: 'TXT', value: chunk.join(' ') });
      }
    }
  );

  // 7. CNAME Records
  await querySafe(
    () => dns.resolveCname(host),
    (results) => {
      for (const cname of results) {
        records.push({ recordType: 'CNAME', value: cname });
      }
    }
  );

  // 8. SOA Records (Start of Authority)
  await querySafe(
    () => dns.resolveSoa(host),
    (soa) => {
      records.push({
        recordType: 'SOA',
        value: `Primary: ${soa.nsname}, Admin: ${soa.hostmaster}, Serial: ${soa.serial}, Refresh: ${soa.refresh}s, Retry: ${soa.retry}s, Expire: ${soa.expire}s, MinTTL: ${soa.minttl}s`,
      });
    }
  );

  return records;
}
