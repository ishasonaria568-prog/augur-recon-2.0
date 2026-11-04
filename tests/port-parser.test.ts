/**
 * AUGUR RECON 2.0 - Port Parser & Preset Tests
 */

import { describe, it, expect } from 'vitest';
import { parsePortSpecification, PORT_PRESETS } from '../src/scanner/port-parser.ts';

describe('Reconnaissance Engine - Port Specification & Presets', () => {
  it('defaults to Top 20 preset when empty or omitted', () => {
    const ports = parsePortSpecification();
    expect(ports).toEqual(PORT_PRESETS.top20.ports);
    expect(ports).toContain(80);
    expect(ports).toContain(443);
    expect(ports).toContain(22);
  });

  it('correctly loads named presets', () => {
    const webPorts = parsePortSpecification('web');
    expect(webPorts).toContain(80);
    expect(webPorts).toContain(443);
    expect(webPorts).toContain(8080);
    expect(webPorts).toContain(8443);

    const dbPorts = parsePortSpecification('database');
    expect(dbPorts).toContain(3306);
    expect(dbPorts).toContain(5432);
    expect(dbPorts).toContain(6379);
  });

  it('parses comma-separated port numbers and ranges', () => {
    const parsed = parsePortSpecification('22,80,8080-8083');
    expect(parsed).toEqual([22, 80, 8080, 8081, 8082, 8083]);
  });

  it('deduplicates and sorts ports numerically', () => {
    const parsed = parsePortSpecification('443,80,443,22,80');
    expect(parsed).toEqual([22, 80, 443]);
  });

  it('throws error on out-of-range or malformed ports', () => {
    expect(() => parsePortSpecification('0')).toThrow();
    expect(() => parsePortSpecification('70000')).toThrow();
    expect(() => parsePortSpecification('invalid-port')).toThrow();
    expect(() => parsePortSpecification('500-100')).toThrow();
  });
});
