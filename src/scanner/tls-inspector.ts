/**
 * AUGUR RECON 2.0 - TLS Certificate Inspection & Cryptographic Analysis Engine
 * Extracts and parses X.509 certificate chains, validity windows, SANs, ciphers, and validation errors.
 */

import tls from 'node:tls';

export interface TlsInspectionResult {
  port: number;
  subjectCn: string;
  issuerCn: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  sans: string[];
  cipher: string;
  protocolVersion: string;
  isValid: boolean;
  validationError?: string;
  fingerprint256?: string;
  serialNumber?: string;
}

export function inspectTlsCertificate(
  host: string,
  port: number,
  servername?: string,
  timeoutMs = 4000
): Promise<TlsInspectionResult | null> {
  return new Promise((resolve) => {
    let settled = false;

    const cleanup = (res: TlsInspectionResult | null) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {}
      resolve(res);
    };

    const socket = tls.connect(
      {
        host,
        port,
        servername: servername || host,
        rejectUnauthorized: false, // We inspect even invalid / self-signed certs to report security findings
        timeout: timeoutMs,
      },
      () => {
        try {
          const peerCert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();

          if (!peerCert || !peerCert.subject) {
            cleanup(null);
            return;
          }

          const subjectCn = peerCert.subject.CN || (peerCert.subject as any).O || 'Unknown';
          const issuerCn = peerCert.issuer.CN || peerCert.issuer.O || 'Unknown Issuer';
          const validFrom = peerCert.valid_from;
          const validTo = peerCert.valid_to;

          const expirationDate = new Date(validTo);
          const now = new Date();
          const diffMs = expirationDate.getTime() - now.getTime();
          const daysRemaining = Math.floor(diffMs / (1000 * 60 * 60 * 24));

          // Parse Subject Alternative Names
          const sans: string[] = [];
          if (peerCert.subjectaltname) {
            const rawSans = peerCert.subjectaltname.split(', ');
            for (const s of rawSans) {
              sans.push(s.replace(/^DNS:/, '').trim());
            }
          }

          // Evaluate validity and common validation errors
          let isValid = true;
          let validationError: string | undefined = undefined;

          if (daysRemaining < 0) {
            isValid = false;
            validationError = `Certificate expired ${Math.abs(daysRemaining)} days ago (${validTo})`;
          } else if (peerCert.issuer.CN === peerCert.subject.CN && peerCert.issuer.O === peerCert.subject.O) {
            isValid = false;
            validationError = 'Self-signed certificate (untrusted root CA)';
          } else if (servername && !sans.includes(servername) && subjectCn !== servername && !sans.some((s) => s.startsWith('*.') && servername.endsWith(s.slice(2)))) {
            isValid = false;
            validationError = `Hostname mismatch: certificate issued for ${subjectCn} / [${sans.slice(0, 3).join(', ')}] does not match ${servername}`;
          }

          cleanup({
            port,
            subjectCn,
            issuerCn,
            validFrom,
            validTo,
            daysRemaining,
            sans,
            cipher: cipher ? `${cipher.name} (${cipher.standardName || cipher.version})` : 'Unknown',
            protocolVersion: protocol || 'Unknown',
            isValid,
            validationError,
            fingerprint256: peerCert.fingerprint256,
            serialNumber: peerCert.serialNumber,
          });
        } catch {
          cleanup(null);
        }
      }
    );

    socket.on('timeout', () => cleanup(null));
    socket.on('error', () => cleanup(null));
  });
}
