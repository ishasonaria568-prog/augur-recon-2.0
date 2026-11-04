/**
 * AUGUR RECON 2.0 - Security Policy & Target Validation Automated Tests
 */

import { describe, it, expect } from 'vitest';
import {
  isRestrictedIPv4,
  isRestrictedIPv6,
  sanitizeTargetInput,
  validateScanTarget,
  SecurityPolicyError,
} from '../src/security/target-validator.ts';

describe('Security Architecture - Target Policy & Default-Deny', () => {
  it('correctly blocks RFC1918 IPv4 private addresses by default', () => {
    // 10.0.0.0/8
    expect(isRestrictedIPv4('10.0.0.1').restricted).toBe(true);
    expect(isRestrictedIPv4('10.254.1.5').restricted).toBe(true);

    // 172.16.0.0/12
    expect(isRestrictedIPv4('172.16.0.1').restricted).toBe(true);
    expect(isRestrictedIPv4('172.31.255.255').restricted).toBe(true);
    expect(isRestrictedIPv4('172.32.0.1').restricted).toBe(false);

    // 192.168.0.0/16
    expect(isRestrictedIPv4('192.168.1.1').restricted).toBe(true);
    expect(isRestrictedIPv4('192.168.100.254').restricted).toBe(true);
  });

  it('blocks loopback and local multicast/broadcast addresses', () => {
    expect(isRestrictedIPv4('127.0.0.1').restricted).toBe(true);
    expect(isRestrictedIPv4('127.0.0.53').restricted).toBe(true);
    expect(isRestrictedIPv4('0.0.0.0').restricted).toBe(true);
    expect(isRestrictedIPv4('224.0.0.1').restricted).toBe(true); // Multicast
    expect(isRestrictedIPv4('255.255.255.255').restricted).toBe(true);
  });

  it('blocks Cloud Metadata (169.254.169.254) and Link-Local', () => {
    const check = isRestrictedIPv4('169.254.169.254');
    expect(check.restricted).toBe(true);
    expect(check.reason).toContain('Link-Local / Cloud Metadata');
  });

  it('blocks Carrier-Grade NAT (RFC6598 100.64.0.0/10)', () => {
    expect(isRestrictedIPv4('100.64.0.1').restricted).toBe(true);
    expect(isRestrictedIPv4('100.127.255.255').restricted).toBe(true);
    expect(isRestrictedIPv4('100.128.0.1').restricted).toBe(false);
  });

  it('blocks IPv6 loopback, link-local, and ULA addresses', () => {
    expect(isRestrictedIPv6('::1').restricted).toBe(true);
    expect(isRestrictedIPv6('fe80::1').restricted).toBe(true);
    expect(isRestrictedIPv6('fc00::1').restricted).toBe(true);
    expect(isRestrictedIPv6('fd12:3456:789a::1').restricted).toBe(true);
    expect(isRestrictedIPv6('::ffff:192.168.1.1').restricted).toBe(true);
  });

  it('normalizes target input schemes, ports, and trailing paths', () => {
    expect(sanitizeTargetInput('https://scanme.nmap.org/')).toBe('scanme.nmap.org');
    expect(sanitizeTargetInput('http://example.com:8080/path?query=1')).toBe('example.com');
    expect(sanitizeTargetInput('  1.1.1.1:443  ')).toBe('1.1.1.1');
    expect(sanitizeTargetInput('[::1]:8080')).toBe('::1');
  });

  it('throws SecurityPolicyError when attempting to scan private IP without lab flag', async () => {
    await expect(validateScanTarget('127.0.0.1')).rejects.toThrow(SecurityPolicyError);
    await expect(validateScanTarget('192.168.1.50')).rejects.toThrow(SecurityPolicyError);
    await expect(validateScanTarget('10.10.10.10')).rejects.toThrow(SecurityPolicyError);
  });

  it('permits private IP scan when allowPrivate is explicitly authorized for lab testing', async () => {
    const validated = await validateScanTarget('192.168.1.1', { allowPrivate: true });
    expect(validated.normalizedHost).toBe('192.168.1.1');
    expect(validated.primaryIp).toBe('192.168.1.1');
    expect(validated.isPrivateOrRestricted).toBe(true);
    expect(validated.authorizationNotes.length).toBeGreaterThan(0);
  });
});
