/**
 * AUGUR RECON 2.0 - Security Policy & Target Validator
 * Central Target Validation Engine with Default-Deny Architecture,
 * IPv4/IPv6 Range Verification, DNS Rebinding Protection, and Lab Mode Control.
 */

import net from 'node:net';
import dns from 'node:dns/promises';

export interface ValidationOptions {
  allowPrivate?: boolean; // Explicit lab/authorized internal penetration testing
  allowLoopback?: boolean; // Explicit local loopback testing flag
}

export interface ValidatedTarget {
  rawInput: string;
  normalizedHost: string;
  isIp: boolean;
  ipVersion: 4 | 6 | null;
  resolvedIps: string[];
  primaryIp: string;
  isPrivateOrRestricted: boolean;
  authorizationNotes: string[];
}

export class SecurityPolicyError extends Error {
  public code: string;
  constructor(message: string, code: string = 'SECURITY_RESTRICTION') {
    super(message);
    this.name = 'SecurityPolicyError';
    this.code = code;
  }
}

/**
 * Checks if an IPv4 address falls within restricted, private, or special-purpose ranges:
 * - 0.0.0.0/8 (Current network)
 * - 10.0.0.0/8 (Private RFC1918)
 * - 100.64.0.0/10 (Carrier-Grade NAT RFC6598)
 * - 127.0.0.0/8 (Loopback RFC1122)
 * - 169.254.0.0/16 (Link-Local / Cloud Metadata RFC3927)
 * - 172.16.0.0/12 (Private RFC1918)
 * - 192.0.0.0/24 (IETF Protocol Assignments)
 * - 192.0.2.0/24 (TEST-NET-1 RFC5737)
 * - 192.88.99.0/24 (6to4 Relay Anycast)
 * - 192.168.0.0/16 (Private RFC1918)
 * - 198.18.0.0/15 (Benchmarking RFC2544)
 * - 198.51.100.0/24 (TEST-NET-2 RFC5737)
 * - 203.0.113.0/24 (TEST-NET-3 RFC5737)
 * - 224.0.0.0/4 (Multicast RFC5771)
 * - 240.0.0.0/4 (Reserved / Future use RFC1112)
 * - 255.255.255.255/32 (Limited Broadcast)
 */
export function isRestrictedIPv4(ip: string): { restricted: boolean; reason?: string } {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return { restricted: true, reason: 'Malformed IPv4 address' };
  }

  const [a, b, c, d] = parts;
  const num = (a << 24) | (b << 16) | (c << 8) | d;

  // 0.0.0.0/8
  if (a === 0) return { restricted: true, reason: 'Current network (0.0.0.0/8)' };
  // 127.0.0.0/8
  if (a === 127) return { restricted: true, reason: 'Loopback address (127.0.0.0/8)' };
  // 10.0.0.0/8
  if (a === 10) return { restricted: true, reason: 'Private RFC 1918 address (10.0.0.0/8)' };
  // 100.64.0.0/10
  if (a === 100 && b >= 64 && b <= 127) return { restricted: true, reason: 'Carrier-Grade NAT (100.64.0.0/10)' };
  // 169.254.0.0/16 (Includes Cloud Metadata 169.254.169.254)
  if (a === 169 && b === 254) return { restricted: true, reason: 'Link-Local / Cloud Metadata (169.254.0.0/16)' };
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return { restricted: true, reason: 'Private RFC 1918 address (172.16.0.0/12)' };
  // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 0) return { restricted: true, reason: 'IETF Protocol Assignments (192.0.0.0/24)' };
  // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 0 && c === 2) return { restricted: true, reason: 'Documentation TEST-NET-1 (192.0.2.0/24)' };
  // 192.168.0.0/16
  if (a === 192 && b === 168) return { restricted: true, reason: 'Private RFC 1918 address (192.168.0.0/16)' };
  // 198.18.0.0/15
  if (a === 198 && (b === 18 || b === 19)) return { restricted: true, reason: 'Network Benchmark Range (198.18.0.0/15)' };
  // 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && b === 51 && c === 100) return { restricted: true, reason: 'Documentation TEST-NET-2 (198.51.100.0/24)' };
  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 0 && c === 113) return { restricted: true, reason: 'Documentation TEST-NET-3 (203.0.113.0/24)' };
  // 224.0.0.0/4 (Multicast)
  if (a >= 224 && a <= 239) return { restricted: true, reason: 'Multicast address space (224.0.0.0/4)' };
  // 240.0.0.0/4 (Reserved)
  if (a >= 240) return { restricted: true, reason: 'Reserved / Broadcast address space' };

  return { restricted: false };
}

/**
 * Checks if an IPv6 address falls within restricted or private ranges:
 * - ::1/128 (Loopback)
 * - ::/128 (Unspecified)
 * - ::ffff:0:0/96 (IPv4-mapped IPv6)
 * - fe80::/10 (Link-Local unicast)
 * - fc00::/7 (Unique Local Address - ULA RFC4193)
 * - ff00::/8 (Multicast)
 * - 2001:db8::/32 (Documentation RFC3849)
 */
export function isRestrictedIPv6(ip: string): { restricted: boolean; reason?: string } {
  const normalized = ip.toLowerCase().trim();

  // IPv4-mapped IPv6 address (e.g. ::ffff:192.168.1.1)
  if (normalized.startsWith('::ffff:') && normalized.includes('.')) {
    const v4Part = normalized.replace('::ffff:', '');
    const v4Check = isRestrictedIPv4(v4Part);
    if (v4Check.restricted) {
      return { restricted: true, reason: `IPv4-mapped IPv6 pointing to restricted range: ${v4Check.reason}` };
    }
  }

  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') {
    return { restricted: true, reason: 'IPv6 Loopback (::1)' };
  }
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') {
    return { restricted: true, reason: 'IPv6 Unspecified address (::)' };
  }
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return { restricted: true, reason: 'IPv6 Link-Local address (fe80::/10)' };
  }
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return { restricted: true, reason: 'IPv6 Unique Local Address (fc00::/7)' };
  }
  if (normalized.startsWith('ff')) {
    return { restricted: true, reason: 'IPv6 Multicast address (ff00::/8)' };
  }
  if (normalized.startsWith('2001:db8') || normalized.startsWith('2001:0db8')) {
    return { restricted: true, reason: 'IPv6 Documentation address (2001:db8::/32)' };
  }

  return { restricted: false };
}

/**
 * Normalizes input target string: strips protocol schemes, paths, ports, and trailing slashes.
 */
export function sanitizeTargetInput(input: string): string {
  let cleaned = input.trim();
  // Strip url schemes if passed (e.g. http://, https://)
  cleaned = cleaned.replace(/^[a-zA-Z]+:\/\//, '');
  // Strip path or query
  const slashIdx = cleaned.indexOf('/');
  if (slashIdx !== -1) {
    cleaned = cleaned.substring(0, slashIdx);
  }
  const queryIdx = cleaned.indexOf('?');
  if (queryIdx !== -1) {
    cleaned = cleaned.substring(0, queryIdx);
  }
  // Strip port if specified e.g. example.com:8080 (unless IPv6 [::1]:8080)
  if (cleaned.startsWith('[') && cleaned.includes(']')) {
    const bracketEnd = cleaned.indexOf(']');
    cleaned = cleaned.substring(1, bracketEnd);
  } else if (cleaned.includes(':') && net.isIPv4(cleaned.split(':')[0])) {
    cleaned = cleaned.split(':')[0];
  } else if (cleaned.includes(':') && !cleaned.includes('::') && cleaned.split(':').length === 2) {
    // hostname:port
    cleaned = cleaned.split(':')[0];
  }
  return cleaned.toLowerCase();
}

/**
 * Validates a target host against security policy and resolves DNS.
 * Pre-emptively defeats DNS rebinding by returning the verified IPs.
 */
export async function validateScanTarget(
  rawInput: string,
  options: ValidationOptions = {}
): Promise<ValidatedTarget> {
  const normalizedHost = sanitizeTargetInput(rawInput);
  if (!normalizedHost) {
    throw new SecurityPolicyError('Target hostname or IP address cannot be empty', 'INVALID_TARGET');
  }

  // Check character legality to prevent injection
  const validHostRegex = /^[a-z0-9.-]+$/;
  const isV6Format = normalizedHost.includes(':');
  if (!isV6Format && !validHostRegex.test(normalizedHost)) {
    throw new SecurityPolicyError(`Invalid characters detected in target hostname: "${normalizedHost}"`, 'ILLEGAL_CHARACTERS');
  }

  const isIpV4 = net.isIPv4(normalizedHost);
  const isIpV6 = net.isIPv6(normalizedHost);
  const isIp = isIpV4 || isIpV6;
  const ipVersion = isIpV4 ? 4 : isIpV6 ? 6 : null;

  let resolvedIps: string[] = [];
  const notes: string[] = [];

  if (isIp) {
    resolvedIps = [normalizedHost];
  } else {
    // Target is a domain name, resolve DNS
    try {
      const records = await dns.lookup(normalizedHost, { all: true });
      resolvedIps = records.map((r) => r.address);
      if (resolvedIps.length === 0) {
        throw new SecurityPolicyError(`Could not resolve hostname: ${normalizedHost}`, 'DNS_RESOLUTION_FAILED');
      }
    } catch (err: any) {
      if (err instanceof SecurityPolicyError) throw err;
      throw new SecurityPolicyError(`DNS resolution failed for ${normalizedHost}: ${err.message || 'Host not found'}`, 'DNS_RESOLUTION_FAILED');
    }
  }

  let hasRestricted = false;
  let restrictedReasons: string[] = [];

  for (const ip of resolvedIps) {
    const isV4 = net.isIPv4(ip);
    const check = isV4 ? isRestrictedIPv4(ip) : isRestrictedIPv6(ip);
    if (check.restricted) {
      hasRestricted = true;
      restrictedReasons.push(`${ip} (${check.reason})`);
    }
  }

  if (hasRestricted) {
    if (!options.allowPrivate && !options.allowLoopback) {
      throw new SecurityPolicyError(
        `Default-Deny Policy Blocked Target: ${normalizedHost} resolves to restricted address space: ${restrictedReasons.join(', ')}. ` +
        `To scan internal lab infrastructure for authorized cybersecurity assessments, explicitly supply --allow-private (CLI) or enable Lab Mode authorization (API).`,
        'TARGET_POLICY_VIOLATION'
      );
    } else {
      notes.push(`Private/Restricted target explicitly authorized via Lab Testing Policy: ${restrictedReasons.join(', ')}`);
    }
  }

  return {
    rawInput,
    normalizedHost,
    isIp,
    ipVersion,
    resolvedIps,
    primaryIp: resolvedIps[0],
    isPrivateOrRestricted: hasRestricted,
    authorizationNotes: notes,
  };
}
