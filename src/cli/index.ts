#!/usr/bin/env node
/**
 * AUGUR RECON 2.0 - Command Line Interface
 * Developer: Isha Sonaria (https://github.com/ishasonaria568-prog)
 * Professional CLI for network reconnaissance, DNS enumeration, TLS analysis, and attack surface intelligence.
 */

import { Command } from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import { executeReconScan } from '../scanner/recon-orchestrator.ts';
import { compareScans } from '../scanner/scan-diff.ts';
import { generateReport, getScanReportData } from '../reporting/report-generator.ts';
import { analyzeScanWithGemini } from '../ai/gemini-advisor.ts';
import { getDatabase } from '../db/database.ts';

const program = new Command();

program
  .name('augur')
  .description('AUGUR RECON 2.0 — AI-Augmented Attack Surface Intelligence\nDeveloper: Isha Sonaria (https://github.com/ishasonaria568-prog)')
  .version('2.0.0');

// 1. augur scan TARGET
program
  .command('scan <target>')
  .description('Execute network reconnaissance against an authorized target host or IP')
  .option('-p, --ports <ports>', 'Ports specification (e.g. 80,443, 1-1000, or preset: top20, top100, web, database, infrastructure)', 'top20')
  .option('-c, --concurrency <number>', 'Concurrent socket connections', '35')
  .option('-t, --timeout <ms>', 'Probe timeout in milliseconds', '1500')
  .option('--udp', 'Enable best-effort UDP scan for common services', false)
  .option('--allow-private', 'Explicit authorization for private IP / RFC1918 lab testing', false)
  .option('-f, --format <format>', 'Report format: text, json, csv, markdown, html', 'text')
  .option('-o, --output <path>', 'Write scan report to file')
  .option('-v, --verbose', 'Show detailed connection errors and probes', false)
  .option('-q, --quiet', 'Suppress interactive terminal progress', false)
  .option('--ai', 'Automatically trigger AI security posture analysis after scan', false)
  .action(async (target, options) => {
    try {
      if (!options.quiet) {
        console.log(`\n\x1b[31;1m[AUGUR RECON 2.0]\x1b[0m AI-Augmented Attack Surface Intelligence`);
        console.log(`\x1b[90mTarget: ${target} | Ports: ${options.ports} | Lab Mode: ${options.allowPrivate ? 'ENABLED' : 'DISABLED'}\x1b[0m\n`);
      }

      const scanResult = await executeReconScan({
        target,
        ports: options.ports,
        concurrency: Number.parseInt(options.concurrency, 10),
        timeoutMs: Number.parseInt(options.timeout, 10),
        enableUdp: options.udp,
        allowPrivate: options.allowPrivate,
        actor: 'cli-user',
        onProgress: (evt) => {
          if (!options.quiet) {
            process.stdout.write(`\r\x1b[K\x1b[36m[${evt.phase.toUpperCase()}]\x1b[0m ${evt.message}`);
          }
        },
      });

      if (!options.quiet) {
        console.log('\n');
      }

      let aiResult = null;
      if (options.ai) {
        if (!options.quiet) console.log(`\x1b[33m[*] Requesting AI Security Analysis from Gemini...\x1b[0m`);
        try {
          aiResult = await analyzeScanWithGemini(scanResult.job.id);
          if (!options.quiet) console.log(`\x1b[32m[✓] AI Analysis successfully synthesized.\x1b[0m\n`);
        } catch (err: any) {
          if (!options.quiet) console.log(`\x1b[33m[!] AI Analysis skipped: ${err.message}\x1b[0m\n`);
        }
      }

      if (options.format === 'text') {
        const openPorts = scanResult.ports.filter((p) => p.state === 'open');
        console.log(`\x1b[1m=== RECONNAISSANCE SUMMARY ===\x1b[0m`);
        console.log(`Job ID:       \x1b[36m${scanResult.job.id}\x1b[0m`);
        console.log(`Target:       ${scanResult.job.target_input} (${scanResult.job.resolved_ip})`);
        console.log(`Duration:     ${scanResult.job.duration_ms}ms`);
        console.log(`Open Ports:   \x1b[32;1m${openPorts.length}\x1b[0m / ${scanResult.job.total_ports_probed} probed\n`);

        if (openPorts.length > 0) {
          console.log(`\x1b[1mOPEN PORTS & SERVICES:\x1b[0m`);
          console.log(`PORT\tPROTO\tSERVICE\t\tPRODUCT\t\t\tLATENCY\tBANNER`);
          console.log(`----\t-----\t-------\t\t-------\t\t\t-------\t------`);
          for (const p of openPorts) {
            const svc = scanResult.services.find((s) => s.port === p.port);
            const svcName = (svc?.service_name || 'unknown').padEnd(12);
            const prod = ((svc?.product || '') + ' ' + (svc?.version || '')).trim().slice(0, 18).padEnd(20) || '-'.padEnd(20);
            const banner = (svc?.banner || '').replace(/[\r\n]+/g, ' ').slice(0, 40);
            console.log(`${p.port}\t${p.protocol.toUpperCase()}\t${svcName}\t${prod}\t${p.latency_ms}ms\t${banner}`);
          }
          console.log('');
        }

        if (scanResult.tlsResults.length > 0) {
          console.log(`\x1b[1mTLS CERTIFICATES:\x1b[0m`);
          for (const t of scanResult.tlsResults) {
            console.log(`Port ${t.port}: Subject: ${t.subject_cn} | Issuer: ${t.issuer_cn} | Valid: ${t.valid_to} (${t.days_remaining}d remaining) | ${t.is_valid ? '\x1b[32mVALID\x1b[0m' : '\x1b[31mINVALID: ' + t.validation_error + '\x1b[0m'}`);
          }
          console.log('');
        }

        if (scanResult.dnsResults.length > 0) {
          console.log(`\x1b[1mDNS INTELLIGENCE:\x1b[0m`);
          for (const d of scanResult.dnsResults) {
            console.log(`[${d.record_type.padEnd(5)}] ${d.value}${d.priority ? ` (Priority: ${d.priority})` : ''}`);
          }
          console.log('');
        }

        if (aiResult) {
          console.log(`\x1b[1mAI POSTURE SUMMARY:\x1b[0m\n${aiResult.summary}\n`);
          if (aiResult.recommendations.length > 0) {
            console.log(`\x1b[1mRECOMMENDATIONS:\x1b[0m`);
            for (const r of aiResult.recommendations) {
              console.log(`[${r.priority}] ${r.title}: ${r.action}`);
            }
            console.log('');
          }
        }
      } else {
        const report = generateReport(scanResult.job.id, options.format as any);
        if (options.output) {
          fs.writeFileSync(options.output, report.content, 'utf8');
          console.log(`\x1b[32m[✓] Report written to: ${options.output}\x1b[0m`);
        } else {
          console.log(report.content);
        }
      }

      if (options.output && options.format === 'text') {
        const report = generateReport(scanResult.job.id, 'markdown');
        fs.writeFileSync(options.output, report.content, 'utf8');
        console.log(`\x1b[32m[✓] Summary report written to: ${options.output}\x1b[0m`);
      }
    } catch (err: any) {
      console.error(`\n\x1b[31;1m[ERROR]\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

// 2. augur history
program
  .command('history')
  .description('Display list of previous scan jobs from local SQLite database')
  .option('-l, --limit <n>', 'Maximum jobs to display', '20')
  .action((options) => {
    const db = getDatabase();
    const jobs = db.listScanJobs(Number.parseInt(options.limit, 10));

    if (jobs.length === 0) {
      console.log('No historical scans found in database.');
      return;
    }

    console.log(`\x1b[1mSCAN HISTORY (${jobs.length} jobs)\x1b[0m\n`);
    console.log(`JOB ID\t\t\t\t\tTARGET\t\t\tIP\t\tSTATUS\t\tOPEN\tDURATION\tCREATED`);
    console.log(`------------------------------------\t----------------\t---------------\t--------\t----\t--------\t-------------------`);

    for (const j of jobs) {
      const statusColor = j.status === 'completed' ? '\x1b[32m' : j.status === 'failed' ? '\x1b[31m' : '\x1b[33m';
      const duration = j.duration_ms ? `${j.duration_ms}ms` : '-';
      const created = j.created_at ? j.created_at.replace('T', ' ').slice(0, 19) : '-';
      console.log(
        `${j.id}\t${j.normalized_host.slice(0, 16).padEnd(16)}\t${j.resolved_ip.padEnd(15)}\t${statusColor}${j.status.padEnd(8)}\x1b[0m\t${j.open_ports_count}\t${duration.padEnd(8)}\t${created}`
      );
    }
    console.log('');
  });

// 3. augur diff OLD_ID NEW_ID
program
  .command('diff <oldId> <newId>')
  .description('Compare two scan jobs to identify attack surface drift, newly opened/closed ports, and service changes')
  .action((oldId, newId) => {
    try {
      const diff = compareScans(oldId, newId);
      console.log(`\n\x1b[1m=== ATTACK SURFACE DIFF ===\x1b[0m`);
      console.log(`Comparing Job \x1b[36m${oldId.slice(0, 8)}\x1b[0m (${diff.oldJob.normalized_host}) → \x1b[36${newId.slice(0, 8)}\x1b[0m (${diff.newJob.normalized_host})`);
      console.log(`Time Delta: ${Math.round(diff.timeDeltaMs / 1000)} seconds\n`);

      if (diff.ipChanged) {
        console.log(`\x1b[33m[!] TARGET IP CHANGED:\x1b[0m ${diff.oldIp} → ${diff.newIp}`);
      }

      console.log(`\x1b[1mPORT DRIFT:\x1b[0m`);
      if (diff.portsDiff.newlyOpened.length === 0 && diff.portsDiff.newlyClosed.length === 0) {
        console.log(`No port state changes detected (${diff.portsDiff.unchangedOpen.length} open ports unchanged).`);
      } else {
        for (const p of diff.portsDiff.newlyOpened) {
          console.log(`  \x1b[31;1m+ [NEWLY OPENED]\x1b[0m Port ${p.port}/${p.protocol.toUpperCase()} (${p.reason})`);
        }
        for (const p of diff.portsDiff.newlyClosed) {
          console.log(`  \x1b[32;1m- [CLOSED/GUARDED]\x1b[0m Port ${p.port}/${p.protocol.toUpperCase()}`);
        }
      }
      console.log('');

      if (diff.servicesDiff.modified.length > 0) {
        console.log(`\x1b[1mSERVICE / BANNER UPDATES:\x1b[0m`);
        for (const s of diff.servicesDiff.modified) {
          console.log(`  Port ${s.port}: ${s.oldService} → ${s.newService}`);
          console.log(`    Old banner: ${s.oldBanner.slice(0, 60)}`);
          console.log(`    New banner: ${s.newBanner.slice(0, 60)}`);
        }
        console.log('');
      }

      if (diff.dnsDiff.added.length > 0 || diff.dnsDiff.removed.length > 0) {
        console.log(`\x1b[1mDNS RECORD CHANGES:\x1b[0m`);
        for (const d of diff.dnsDiff.added) {
          console.log(`  \x1b[32m+ [ADDED]\x1b[0m ${d.record_type}: ${d.value}`);
        }
        for (const d of diff.dnsDiff.removed) {
          console.log(`  \x1b[31m- [REMOVED]\x1b[0m ${d.record_type}: ${d.value}`);
        }
        console.log('');
      }
    } catch (err: any) {
      console.error(`\x1b[31m[ERROR]\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

// 4. augur report JOB_ID
program
  .command('report <jobId>')
  .description('Export or view a security report for a historical scan job')
  .option('-f, --format <format>', 'Report format: json, csv, markdown, html', 'markdown')
  .option('-o, --output <path>', 'Output file path')
  .action((jobId, options) => {
    try {
      const rep = generateReport(jobId, options.format);
      if (options.output) {
        fs.writeFileSync(options.output, rep.content, 'utf8');
        console.log(`\x1b[32m[✓] Report saved to: ${options.output}\x1b[0m`);
      } else {
        console.log(rep.content);
      }
    } catch (err: any) {
      console.error(`\x1b[31m[ERROR]\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

// 5. augur analyze JOB_ID
program
  .command('analyze <jobId>')
  .description('Run Gemini AI security posture analysis on a historical scan job')
  .action(async (jobId) => {
    try {
      console.log(`\x1b[33m[*] Synthesizing attack surface observations for scan ${jobId}...\x1b[0m`);
      const analysis = await analyzeScanWithGemini(jobId);
      console.log(`\n\x1b[1m=== AI SECURITY POSTURE ANALYSIS ===\x1b[0m`);
      console.log(`Model: \x1b[36m${analysis.model}\x1b[0m\n`);
      console.log(analysis.summary + '\n');

      if (analysis.keyFindings.length > 0) {
        console.log(`\x1b[1mKEY FINDINGS:\x1b[0m`);
        for (const f of analysis.keyFindings) {
          console.log(`- [${f.category}] ${f.observation}`);
          console.log(`  Context: ${f.riskContext}`);
        }
        console.log('');
      }

      if (analysis.recommendations.length > 0) {
        console.log(`\x1b[1mRECOMMENDATIONS:\x1b[0m`);
        for (const r of analysis.recommendations) {
          console.log(`[${r.priority}] ${r.title}: ${r.action}`);
        }
        console.log('');
      }
    } catch (err: any) {
      console.error(`\x1b[31m[ERROR]\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

// 6. augur config list
program
  .command('config list')
  .description('Display AUGUR RECON configuration, data paths, and security policies')
  .action(() => {
    const db = getDatabase();
    const config = db.getAllConfig();
    const stats = db.getOverviewStats();

    console.log(`\n\x1b[1m=== AUGUR RECON 2.0 CONFIGURATION ===\x1b[0m`);
    console.log(`Developer:              Isha Sonaria (https://github.com/ishasonaria568-prog)`);
    console.log(`Security Policy:        DEFAULT-DENY (Private / RFC1918 / Loopback blocked by default)`);
    console.log(`Data Directory:         ${process.env.AUGUR_DATA_DIR || path.resolve(process.cwd(), '.augur')}`);
    console.log(`Gemini API Key:         ${process.env.GEMINI_API_KEY ? 'CONFIGURED (' + process.env.GEMINI_API_KEY.slice(0, 6) + '...)' : 'NOT SET (Scanning works offline)'}`);
    console.log(`Total Scans in DB:      ${stats.totalScans}`);
    console.log(`Unique Targets:         ${stats.uniqueTargets}`);
    console.log(`Total Open Ports:       ${stats.totalOpenPorts}\n`);
  });

// 7. augur serve
program
  .command('serve')
  .description('Launch the AUGUR RECON Web Dashboard and REST API Server')
  .option('-p, --port <port>', 'Server port', '3000')
  .option('-h, --host <host>', 'Bind host', '0.0.0.0')
  .action(async (options) => {
    process.env.PORT = options.port;
    process.env.HOST = options.host;
    // Dynamically start server
    await import('../../server.ts');
  });

program.parse(process.argv);
