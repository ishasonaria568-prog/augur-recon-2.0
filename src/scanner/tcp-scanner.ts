/**
 * AUGUR RECON 2.0 - TCP Connection Reconnaissance Engine
 * High-performance, concurrent TCP probe engine with microsecond latency recording
 * and precise state classification (open, closed, filtered).
 */

import net from 'node:net';

export interface TcpProbeResult {
  port: number;
  protocol: 'tcp';
  state: 'open' | 'closed' | 'filtered';
  reason: string;
  latencyMs: number;
}

export interface TcpScanOptions {
  host: string;
  ports: number[];
  timeoutMs?: number;
  concurrency?: number;
  onProgress?: (probed: number, total: number, latestResult?: TcpProbeResult) => void;
  signal?: AbortSignal;
}

/**
 * Executes a single TCP connection probe against a destination IP/host and port
 */
export function probeTcpPort(host: string, port: number, timeoutMs = 1500): Promise<TcpProbeResult> {
  return new Promise<TcpProbeResult>((resolve) => {
    const startTime = performance.now();
    let settled = false;

    const socket = new net.Socket();

    const cleanup = () => {
      socket.removeAllListeners();
      socket.destroy();
    };

    const finish = (state: 'open' | 'closed' | 'filtered', reason: string) => {
      if (settled) return;
      settled = true;
      const latencyMs = Math.round(performance.now() - startTime);
      cleanup();
      resolve({
        port,
        protocol: 'tcp',
        state,
        reason,
        latencyMs,
      });
    };

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      finish('open', 'SYN-ACK received / Connection established');
    });

    socket.on('timeout', () => {
      finish('filtered', `Timeout after ${timeoutMs}ms (no TCP reply or dropped)`);
    });

    socket.on('error', (err: any) => {
      const code = err.code || '';
      if (code === 'ECONNREFUSED') {
        finish('closed', 'RST received / Connection refused by host');
      } else if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH' || code === 'ETIMEDOUT') {
        finish('filtered', `Filtered/Unreachable: ${code}`);
      } else {
        finish('filtered', `Socket error: ${err.message || code}`);
      }
    });

    try {
      socket.connect({ host, port });
    } catch (err: any) {
      finish('filtered', `Connect exception: ${err.message}`);
    }
  });
}

/**
 * Concurrent batch TCP scanner with bounded concurrency pool
 */
export async function scanTcpPorts(options: TcpScanOptions): Promise<TcpProbeResult[]> {
  const { host, ports, timeoutMs = 1500, concurrency = 40, onProgress, signal } = options;
  const results: TcpProbeResult[] = [];
  const total = ports.length;
  let probedCount = 0;
  let cursor = 0;

  async function worker() {
    while (cursor < ports.length) {
      if (signal?.aborted) break;
      const index = cursor++;
      const port = ports[index];

      const res = await probeTcpPort(host, port, timeoutMs);
      results.push(res);
      probedCount++;
      if (onProgress) {
        onProgress(probedCount, total, res);
      }
    }
  }

  const poolSize = Math.min(concurrency, ports.length);
  const workers = Array.from({ length: poolSize }, () => worker());
  await Promise.all(workers);

  return results.sort((a, b) => a.port - b.port);
}
