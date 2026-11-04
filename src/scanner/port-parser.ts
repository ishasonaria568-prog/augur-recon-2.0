/**
 * AUGUR RECON 2.0 - Port Specification Parser & Presets
 */

export const PORT_PRESETS: Record<string, { name: string; description: string; ports: number[] }> = {
  top20: {
    name: 'Top 20 Critical Ports',
    description: 'Most commonly exposed attack surface ports (SSH, HTTP, HTTPS, RDP, SMB, etc.)',
    ports: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
  },
  top100: {
    name: 'Top 100 Common Ports',
    description: 'Comprehensive baseline for corporate perimeter and external infrastructure',
    ports: [
      7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
      139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
      646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
      2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
      6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 10000, 27017, 32768, 49152, 49154
    ],
  },
  web: {
    name: 'Web & Reverse Proxy Ports',
    description: 'Standard and alternate HTTP/HTTPS services, management consoles, and dev servers',
    ports: [80, 81, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 4000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443],
  },
  database: {
    name: 'Database & Cache Infrastructure',
    description: 'Relational, NoSQL, and memory caches (PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch)',
    ports: [1433, 1521, 3306, 5432, 5984, 6379, 7000, 7001, 9042, 9200, 9300, 11211, 27017, 27018, 28017],
  },
  infrastructure: {
    name: 'Remote Access & Management',
    description: 'Administrative interfaces, SSH, Telnet, RDP, VNC, SNMP, IPMI, Docker, Kubernetes',
    ports: [22, 23, 161, 389, 623, 636, 2375, 2376, 3389, 5900, 5985, 5986, 6443, 8443, 10250],
  },
};

/**
 * Parses user port specifications like "80,443", "80-100", "top20", "web,3000-3005"
 */
export function parsePortSpecification(input?: string): number[] {
  if (!input || input.trim() === '') {
    return PORT_PRESETS.top20.ports;
  }

  const trimmed = input.trim().toLowerCase();
  if (PORT_PRESETS[trimmed]) {
    return PORT_PRESETS[trimmed].ports;
  }

  const portSet = new Set<number>();
  const tokens = trimmed.split(',');

  for (const token of tokens) {
    const part = token.trim();
    if (!part) continue;

    // Check if part is a preset name
    if (PORT_PRESETS[part]) {
      for (const p of PORT_PRESETS[part].ports) portSet.add(p);
      continue;
    }

    // Range like 80-90
    if (part.includes('-')) {
      const [startStr, endStr] = part.split('-');
      const start = Number.parseInt(startStr, 10);
      const end = Number.parseInt(endStr, 10);
      if (Number.isNaN(start) || Number.isNaN(end) || start < 1 || end > 65535 || start > end) {
        throw new Error(`Invalid port range: "${part}". Must be between 1 and 65535.`);
      }
      // Safety cap for single range to prevent accidental billion port crash
      if (end - start > 10000) {
        throw new Error(`Port range "${part}" exceeds maximum single scan span of 10,000 ports.`);
      }
      for (let p = start; p <= end; p++) {
        portSet.add(p);
      }
    } else {
      const p = Number.parseInt(part, 10);
      if (Number.isNaN(p) || p < 1 || p > 65535) {
        throw new Error(`Invalid port number: "${part}". Must be an integer between 1 and 65535.`);
      }
      portSet.add(p);
    }
  }

  const sorted = Array.from(portSet).sort((a, b) => a - b);
  if (sorted.length === 0) {
    throw new Error('No valid ports parsed from specification.');
  }

  return sorted;
}
