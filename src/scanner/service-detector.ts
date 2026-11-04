/**
 * AUGUR RECON 2.0 - Service & Protocol Identification Engine
 * Protocol-aware banner grabber for SSH, HTTP/HTTPS, FTP, SMTP, and generic TCP daemons.
 */

import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

export interface DiscoveredService {
  port: number;
  protocol: 'tcp' | 'udp';
  serviceName: string;
  product?: string;
  version?: string;
  banner?: string;
  rawResponse?: string;
  details?: Record<string, any>;
}

/**
 * Grabs initial text banner from a listening TCP socket
 */
function grabTcpBanner(host: string, port: number, probePayload?: string, timeoutMs = 2500): Promise<string> {
  return new Promise((resolve) => {
    let settled = false;
    let dataBuffer = '';
    const socket = new net.Socket();

    const cleanup = () => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve(dataBuffer.trim());
    };

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      if (probePayload) {
        socket.write(probePayload);
      }
    });

    socket.on('data', (chunk) => {
      dataBuffer += chunk.toString('utf8');
      if (dataBuffer.length >= 1024 || dataBuffer.includes('\n')) {
        cleanup();
      }
    });

    socket.on('timeout', cleanup);
    socket.on('error', cleanup);
    socket.on('close', cleanup);

    try {
      socket.connect({ host, port });
    } catch {
      cleanup();
    }
  });
}

/**
 * Probes HTTP/HTTPS services for headers, server software, and page title
 */
function probeHttpService(
  host: string,
  port: number,
  isTls: boolean,
  hostnameHeader?: string,
  timeoutMs = 3000
): Promise<{ banner: string; product?: string; version?: string; raw: string; details: any } | null> {
  return new Promise((resolve) => {
    const client = isTls ? https : http;
    const req = client.request(
      {
        host,
        port,
        path: '/',
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AugurRecon/2.0',
          Host: hostnameHeader || (isTls ? `${host}:${port}` : host),
          Accept: '*/*',
        },
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          if (body.length < 4096) body += chunk.toString('utf8');
        });
        res.on('end', () => {
          const serverHeader = res.headers['server'] || '';
          const poweredBy = res.headers['x-powered-by'] || '';
          const statusCode = res.statusCode || 0;

          // Extract HTML title
          const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
          const pageTitle = titleMatch ? titleMatch[1].trim() : undefined;

          let product = 'HTTP Daemon';
          let version = '';

          if (serverHeader) {
            const parts = serverHeader.split('/');
            product = parts[0] || 'HTTP Daemon';
            version = parts[1] ? parts[1].split(' ')[0] : '';
          }

          const banner = `HTTP/${res.httpVersion} ${statusCode} (Server: ${serverHeader || 'Hidden'}, Title: "${pageTitle || 'N/A'}")`;
          resolve({
            banner,
            product,
            version,
            raw: `HTTP/${res.httpVersion} ${statusCode}\n${Object.entries(res.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}`,
            details: {
              statusCode,
              serverHeader,
              poweredBy,
              pageTitle,
              headers: res.headers,
            },
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    req.on('error', () => {
      resolve(null);
    });

    req.end();
  });
}

/**
 * Protocol-aware service fingerprinting for an open port
 */
export async function identifyService(
  host: string,
  port: number,
  hostnameHeader?: string,
  timeoutMs = 2500
): Promise<DiscoveredService> {
  // 1. SSH detection (standard port 22 or common alternate)
  if (port === 22 || port === 2222) {
    const banner = await grabTcpBanner(host, port, undefined, timeoutMs);
    if (banner.startsWith('SSH-')) {
      const match = banner.match(/^SSH-([0-9.]+)-([^\s\r\n]+)/);
      return {
        port,
        protocol: 'tcp',
        serviceName: 'ssh',
        product: match ? match[2] : 'OpenSSH',
        version: match ? match[1] : undefined,
        banner,
        rawResponse: banner,
      };
    }
  }

  // 2. HTTP / HTTPS detection
  const isCommonTls = [443, 8443, 9443, 2053, 2083, 2087, 2096].includes(port);
  const isCommonHttp = [80, 8080, 8000, 8081, 3000, 5000, 8888, 9000].includes(port);

  if (isCommonTls) {
    const httpRes = await probeHttpService(host, port, true, hostnameHeader, timeoutMs);
    if (httpRes) {
      return {
        port,
        protocol: 'tcp',
        serviceName: 'https',
        product: httpRes.product,
        version: httpRes.version,
        banner: httpRes.banner,
        rawResponse: httpRes.raw,
        details: httpRes.details,
      };
    }
  }

  if (isCommonHttp) {
    const httpRes = await probeHttpService(host, port, false, hostnameHeader, timeoutMs);
    if (httpRes) {
      return {
        port,
        protocol: 'tcp',
        serviceName: 'http',
        product: httpRes.product,
        version: httpRes.version,
        banner: httpRes.banner,
        rawResponse: httpRes.raw,
        details: httpRes.details,
      };
    }
  }

  // 3. FTP detection (port 21)
  if (port === 21 || port === 2121) {
    const banner = await grabTcpBanner(host, port, undefined, timeoutMs);
    if (banner.startsWith('220')) {
      return {
        port,
        protocol: 'tcp',
        serviceName: 'ftp',
        product: banner.includes('vsFTPd') ? 'vsFTPd' : banner.includes('Pure-FTPd') ? 'Pure-FTPd' : banner.includes('ProFTPD') ? 'ProFTPD' : 'FTP Server',
        banner,
        rawResponse: banner,
      };
    }
  }

  // 4. SMTP detection (port 25, 587, 465)
  if ([25, 465, 587].includes(port)) {
    const banner = await grabTcpBanner(host, port, undefined, timeoutMs);
    if (banner.startsWith('220')) {
      return {
        port,
        protocol: 'tcp',
        serviceName: 'smtp',
        product: banner.includes('Postfix') ? 'Postfix' : banner.includes('Exim') ? 'Exim' : banner.includes('Sendmail') ? 'Sendmail' : 'SMTP MTA',
        banner,
        rawResponse: banner,
      };
    }
  }

  // 5. Generic TCP Banner Probe (Send newline to evoke service prompt)
  const genericBanner = await grabTcpBanner(host, port, '\r\nHELP\r\n\r\n', timeoutMs);
  if (genericBanner) {
    let serviceName = 'tcp-service';
    if (genericBanner.toLowerCase().includes('mysql')) serviceName = 'mysql';
    else if (genericBanner.toLowerCase().includes('redis')) serviceName = 'redis';
    else if (genericBanner.toLowerCase().includes('rfb')) serviceName = 'vnc';
    else if (genericBanner.toLowerCase().includes('http')) serviceName = 'http';

    return {
      port,
      protocol: 'tcp',
      serviceName,
      banner: genericBanner.substring(0, 200),
      rawResponse: genericBanner,
    };
  }

  // 6. Default Fallback according to standard IANA assignments
  const knownServices: Record<number, string> = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'domain',
    80: 'http',
    110: 'pop3',
    111: 'rpcbind',
    135: 'msrpc',
    139: 'netbios-ssn',
    143: 'imap',
    443: 'https',
    445: 'microsoft-ds',
    993: 'imaps',
    995: 'pop3s',
    1433: 'ms-sql-s',
    1521: 'oracle',
    3306: 'mysql',
    3389: 'ms-wbt-server',
    5432: 'postgresql',
    5900: 'vnc',
    6379: 'redis',
    8080: 'http-proxy',
    8443: 'https-alt',
  };

  return {
    port,
    protocol: 'tcp',
    serviceName: knownServices[port] || 'unknown',
    banner: 'Open port responded to TCP handshake (No banner broadcasted)',
  };
}
