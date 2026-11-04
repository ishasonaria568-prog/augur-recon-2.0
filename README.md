# AUGUR RECON 2.0
### AI-Augmented Attack Surface Intelligence & Network Reconnaissance

**Developer:** Isha Sonaria  
**GitHub:** [https://github.com/ishasonaria568-prog](https://github.com/ishasonaria568-prog)  
**Project Type:** CLI-first, local-first cybersecurity reconnaissance platform  
**License:** Apache-2.0  

---

## 1. Project Overview

**AUGUR RECON 2.0** is a cybersecurity reconnaissance and attack surface intelligence platform engineered for authorized security assessments, external perimeter reviews, and internal penetration testing labs. 

Built completely from the ground up, AUGUR RECON 2.0 unifies network-level discovery (concurrent TCP/UDP scanning, protocol-aware banner grabbing, TLS inspection, DNS zone enumeration) with local-first SQLite persistence, deterministic attack surface drift comparison, multi-format security reports, and optional Gemini AI security analysis.

It is designed to run natively as a high-speed CLI tool on Kali Linux and Debian systems, while simultaneously providing a professional dark cybersecurity Web Dashboard for visualization, temporal diffing, and executive reporting.

---

## 2. Key Features

- **Concurrent TCP Scanner**: Bounded concurrency pool using native Node.js sockets with microsecond latency tracking, timeout controls, and deterministic state classification (`open`, `closed`, `filtered`).
- **Best-Effort UDP Reconnaissance**: Protocol-aware datagram probes for DNS (53), NTP (123), SNMP (161), and SSDP (1900) disclosing stateless UDP limitations.
- **Protocol-Aware Service Identification**: Banner grabbing for SSH (OpenSSH versions), HTTP/HTTPS (Server software, headers, page titles), FTP, SMTP, and generic daemons.
- **Deep TLS Inspection**: Extracts and parses X.509 certificate chains, Subject and Issuer CNs, validity windows, countdown timers, Subject Alternative Names (SANs), cipher suites, and validation warnings (expired, self-signed, hostname mismatch).
- **DNS Zone Intelligence**: Enumerates A, AAAA, MX, NS, TXT (SPF, DKIM, DMARC), CNAME, SOA, and reverse PTR records.
- **Default-Deny Security Architecture**: Blocks loopback, private (RFC1918), link-local, carrier-grade NAT, and cloud metadata (169.254.169.254) by default, requiring explicit `--allow-private` authorization for authorized lab testing.
- **DNS Rebinding Protection**: Pre-flight target resolution verifies IP addresses against security policies and locks socket destinations to the verified IP.
- **SQLite Persistence & History**: WAL-enabled ACID storage for scans, open ports, banners, certificates, DNS records, configuration, and audit trails.
- **Attack Surface Drift & Diff Engine**: Deterministic diffing between any two historical scans identifying newly opened ports, closed ports, service upgrades, and DNS changes.
- **Multi-Format Reporting**: Generates structured reports in JSON, CSV, Markdown, and fully self-contained offline HTML reports.
- **Optional Gemini AI Posture Analysis**: Synthesizes real empirical scan observations into defensive hardening guidelines without hallucinating fake vulnerabilities. Operates 100% offline without an API key.
- **Kali Linux Packaging**: Pre-built `.deb` package with `/usr/bin/augur` binary launcher and systemd unit.

---

## 3. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend & Core** | Node.js 22 LTS, TypeScript, Express.js, Zod 4, better-sqlite3 |
| **Networking** | Native Node.js `net`, `dgram`, `tls`, `dns/promises` |
| **Frontend** | React 19, TypeScript, Vite 8, Tailwind CSS v4, Lucide Icons, Recharts |
| **CLI** | Commander.js, Chalk terminal formatting |
| **AI Integration** | `@google/genai` (Gemini 3.8 Flash) |
| **Packaging** | Debian `.deb` package (`dpkg-deb`), systemd unit |
| **Testing** | Vitest (Security policy, Port parser, Database, Reporting) |

---

## 4. Security Architecture & Policy

Security is enforced prior to opening any socket connection:

1. **Default-Deny Target Rules**:
   - `127.0.0.0/8` & `::1` (Loopback)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC1918 Private)
   - `169.254.0.0/16` (Link-Local & Cloud Metadata `169.254.169.254`)
   - `100.64.0.0/10` (Carrier-Grade NAT)
   - `224.0.0.0/4` & `ff00::/8` (Multicast)
   - `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` (Documentation)

2. **Authorized Lab Testing Mode**:
   To scan private networks (e.g. VulnHub, HackTheBox, local cyber ranges), explicitly pass:
   ```bash
   augur scan 192.168.1.50 --allow-private
   ```
   All authorizations are written to the immutable SQLite audit log.

3. **DNS Rebinding Prevention**:
   Target hostnames are resolved upfront. If any resolved IP violates the security policy, the scan is blocked immediately. Sockets connect directly to the verified IP, neutralizing DNS rebinding attacks.

4. **Rate Limiting & Audit Logging**:
   Sliding-window token bucket limiters prevent socket exhaustion and API flooding. Every scan action is logged to the database with timestamps and actor details.

---

## 5. Installation & Setup

### Option A: Debian / Kali Linux Package (.deb)

Download and install the Debian package directly:

```bash
# Build the Debian package (or download from dist/)
npm run build:deb

# Install package on Kali Linux or Debian
sudo dpkg -i dist/augur-recon_2.0.0_all.deb

# If any dependencies are missing:
sudo apt-get install -f

# Verify installation:
augur --version
augur --help
```

### Option B: Source Installation

```bash
# Clone the repository
git clone https://github.com/ishasonaria568-prog/augur-recon.git
cd augur-recon

# Install dependencies
npm install

# Link CLI binary locally
npm link

# Run unit tests
npm test

# Verify CLI
augur --version
```

---

## 6. CLI Usage & Command Reference

The primary binary is named `augur`.

```
Usage: augur [options] [command]

Commands:
  scan <target>             Execute network reconnaissance against an authorized target
  history                   Display list of previous scan jobs from local SQLite database
  diff <oldId> <newId>      Compare two scans to detect attack surface drift
  report <jobId>            Export or view a security report (json, csv, markdown, html)
  analyze <jobId>           Run Gemini AI security posture analysis on a historical scan
  config list               Display configuration, data paths, and security policies
  serve                     Launch the Web Dashboard and REST API Server
  help [command]            Display help for command
```

### 1. Basic Scan with Top 20 Presets
```bash
augur scan scanme.nmap.org
```

### 2. Custom Ports & High Concurrency
```bash
augur scan example.com -p 80,443,8080-8090 -c 50 -t 1200
```

### 3. Port Presets
```bash
# Top 100 common ports
augur scan example.com -p top100

# Web and reverse proxy ports
augur scan example.com -p web

# Database infrastructure (MySQL, Postgres, Redis, Mongo)
augur scan example.com -p database

# Management & remote access (SSH, RDP, SNMP)
augur scan example.com -p infrastructure
```

### 4. Enable UDP Probing
```bash
augur scan example.com -p web --udp
```

### 5. Authorized Private Lab Testing (RFC1918)
```bash
augur scan 192.168.1.1 --allow-private -p top20
```

### 6. Export Reports Directly from CLI
```bash
# Generate standalone HTML report
augur scan example.com -f html -o report.html

# Generate Markdown report
augur scan example.com -f markdown -o report.md

# Generate structured JSON
augur scan example.com -f json -o report.json
```

### 7. View Scan History
```bash
augur history
```

### 8. Compare Two Scans (Diff Engine)
```bash
augur diff 3f29b401-209a-4712-9c02-e2c8be371493 8a1b5c20-192a-4122-8d01-a1c2be389401
```

### 9. Run AI Security Analysis
```bash
augur analyze <job_id>
```

### 10. Start the Web Dashboard
```bash
augur serve --port 3000 --host 0.0.0.0
```

---

## 7. Web Dashboard

Launch the server:
```bash
npm run dev
# or
augur serve
```
Open `http://localhost:3000` in your browser.

### Dashboard Sections:
1. **Overview**: Executive telemetry, total scans, open ports distribution, and recent runs.
2. **Scan Management**: Interactive scan launcher with port presets, concurrency controls, timeout settings, UDP toggle, and Lab Mode authorization.
3. **Live Recon**: Real-time progress monitor streaming probe milestones and socket discoveries.
4. **Open Ports**: High-density tabular grid with protocol, state, latency, and service tags.
5. **Services & Banners**: Deep inspection of banner replies, HTTP Server headers, and raw probe payloads.
6. **DNS Intelligence**: Categorized zone intelligence for A, AAAA, MX, NS, TXT, CNAME, SOA, and PTR records.
7. **TLS Inspection**: X.509 certificate validity cards, expiration countdowns, SANs list, cipher suites, and security alerts.
8. **Scan History**: Searchable, filterable archive of all completed jobs with one-click diff selection and report export.
9. **Scan Comparison**: Visual diff analyzer showing newly exposed ports (red), closed ports (green), IP changes, and service banner drift.
10. **Reports**: Interactive report viewer with one-click export for JSON, CSV, Markdown, and self-contained HTML.
11. **AI Security Posture Advisor**: Grounded analysis powered by Gemini API translating observed facts into defensive hardening guidelines.
12. **Security & Audit**: Audit trail viewer displaying chronological security policy decisions and authorization records.

---

## 8. Optional Gemini AI Configuration

AUGUR RECON 2.0 integrates Gemini AI strictly as an optional defensive synthesis module.

- All scanning, banner grabbing, TLS inspection, DNS queries, diffing, and reporting function **100% offline** without an AI API key.
- To enable AI analysis:
  ```bash
  export GEMINI_API_KEY="your-api-key"
  ```
- The advisor uses `@google/genai` with model `gemini-3.8-flash`.
- It strictly separates **Empirical Evidence** from **Hardening Recommendations** and **never hallucinates fake CVE numbers**.

---

## 9. Automated Testing

Run the Vitest test suite:

```bash
npm test
```

Test coverage includes:
- Target validation & RFC1918 default-deny rules
- IPv4 & IPv6 normalization
- Port parser & preset verification
- SQLite database transactions and migrations
- JSON, CSV, Markdown, and HTML report generators

---

## 10. Uninstallation

### Debian Package:
```bash
sudo dpkg -r augur-recon
```

### Source Installation:
```bash
npm unlink -g augur-recon
rm -rf ~/.augur .augur
```

---

## 11. Security Disclaimer

**AUGUR RECON 2.0 is developed exclusively for authorized security research, network administration, and legitimate penetration testing.**

Scanning target networks or hosts without explicit, prior written authorization is illegal in most jurisdictions. The developer (Isha Sonaria) assumes no liability for unauthorized usage or damages resulting from the use of this software. Always obtain written permission before initiating reconnaissance.
