/**
 * AUGUR RECON 2.0 - UDP Reconnaissance Module
 * Best-effort UDP probe engine using native dgram sockets with protocol payloads
 * and clear technical disclosures on UDP stateless limitations.
 */

import dgram from 'node:dgram';

export interface UdpProbeResult {
  port: number;
  protocol: 'udp';
  state: 'open' | 'closed' | 'open/filtered';
  reason: string;
  latencyMs: number;
  responsePayloadHex?: string;
}

export const COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 500, 514, 520, 1900, 5353];

/**
 * Builds protocol-specific probe buffers for high-signal UDP responses
 */
function getUdpPayload(port: number): Buffer {
  switch (port) {
    case 53:
      // DNS Query: Standard query for root . IN A
      return Buffer.from([
        0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01
      ]);
    case 123: {
      // NTP Client Request: LI=0, VN=3, Mode=3 (Client), 48 bytes
      const ntpBuf = Buffer.alloc(48);
      ntpBuf[0] = 0x1b;
      return ntpBuf;
    }
    case 161:
      // SNMP v1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0) with 'public' community
      return Buffer.from([
        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0xa0, 0x19, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01,
        0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00
      ]);
    case 1900:
      // SSDP M-SEARCH Discovery
      return Buffer.from(
        'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
      );
    default:
      // Generic null probe
      return Buffer.alloc(4);
  }
}

export function probeUdpPort(host: string, port: number, timeoutMs = 1500): Promise<UdpProbeResult> {
  return new Promise<UdpProbeResult>((resolve) => {
    const startTime = performance.now();
    let settled = false;
    const socket = dgram.createSocket('udp4');

    const finish = (
      state: 'open' | 'closed' | 'open/filtered',
      reason: string,
      payload?: Buffer
    ) => {
      if (settled) return;
      settled = true;
      try {
        socket.close();
      } catch {}
      const latencyMs = Math.round(performance.now() - startTime);
      resolve({
        port,
        protocol: 'udp',
        state,
        reason,
        latencyMs,
        responsePayloadHex: payload ? payload.toString('hex') : undefined,
      });
    };

    const timer = setTimeout(() => {
      finish(
        'open/filtered',
        `No response received within ${timeoutMs}ms (stateless UDP service or packet filtered by firewall)`
      );
    }, timeoutMs);

    socket.on('message', (msg) => {
      clearTimeout(timer);
      finish('open', `UDP datagram response received (${msg.length} bytes)`, msg);
    });

    socket.on('error', (err: any) => {
      clearTimeout(timer);
      if (err.code === 'ECONNREFUSED') {
        finish('closed', 'ICMP Port Unreachable received');
      } else {
        finish('open/filtered', `Socket error: ${err.message || err.code}`);
      }
    });

    try {
      const payload = getUdpPayload(port);
      socket.send(payload, port, host, (err) => {
        if (err) {
          clearTimeout(timer);
          finish('open/filtered', `Failed to transmit UDP datagram: ${err.message}`);
        }
      });
    } catch (err: any) {
      clearTimeout(timer);
      finish('open/filtered', `Send exception: ${err.message}`);
    }
  });
}

export async function scanUdpPorts(
  host: string,
  ports: number[] = COMMON_UDP_PORTS,
  timeoutMs = 1500
): Promise<UdpProbeResult[]> {
  const results: UdpProbeResult[] = [];
  for (const port of ports) {
    const res = await probeUdpPort(host, port, timeoutMs);
    results.push(res);
  }
  return results;
}
