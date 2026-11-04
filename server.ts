/**
 * AUGUR RECON 2.0 - Full-Stack Express Server & API Gateway
 * Serves REST endpoints for reconnaissance, diffs, reports, and AI analysis,
 * and mounts Vite development middleware.
 */

import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { getDatabase } from './src/db/database.ts';
import { executeReconScan, ReconProgressEvent } from './src/scanner/recon-orchestrator.ts';
import { compareScans } from './src/scanner/scan-diff.ts';
import { generateReport, getScanReportData } from './src/reporting/report-generator.ts';
import { analyzeScanWithGemini } from './src/ai/gemini-advisor.ts';
import { scanJobRateLimiter, apiRateLimiter } from './src/security/rate-limiter.ts';
import { logSecurityAudit } from './src/security/audit-logger.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const isDev = process.env.NODE_ENV !== 'production';

app.use(express.json());

// In-memory active scan progress tracking
const activeJobs = new Map<string, ReconProgressEvent>();

// API Rate Limiting Middleware
app.use('/api', (req: Request, res: Response, next: NextFunction) => {
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const check = apiRateLimiter.check(clientIp, 1);
  if (!check.allowed) {
    res.setHeader('Retry-After', Math.ceil(check.retryAfterMs / 1000));
    return res.status(429).json({
      error: 'Rate limit exceeded. Too many requests to AUGUR RECON API.',
      retryAfterMs: check.retryAfterMs,
    });
  }
  next();
});

// Authentication Middleware: supports optional Bearer token configured in env or database
app.use('/api', (req: Request, res: Response, next: NextFunction) => {
  const configuredToken = process.env.AUGUR_API_TOKEN;
  if (!configuredToken) {
    // Open in local developer preview mode
    return next();
  }

  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : (req.headers['x-api-key'] as string);

  if (!token || token !== configuredToken) {
    return res.status(401).json({
      error: 'Unauthorized: Valid AUGUR RECON API Token required.',
    });
  }
  next();
});

// --- REST API Endpoints ---

// 1. Health & System Info
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    version: '2.0.0',
    app: 'AUGUR RECON',
    developer: 'Isha Sonaria',
    timestamp: new Date().toISOString(),
    geminiEnabled: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'),
  });
});

// 2. Overview Stats
app.get('/api/stats', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const stats = db.getOverviewStats();
    const recentScans = db.listScanJobs(5);
    res.json({
      stats,
      recentScans,
      activeScansCount: activeJobs.size,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Scan History List
app.get('/api/scans', (req: Request, res: Response) => {
  try {
    const limit = Math.min(100, Number.parseInt((req.query.limit as string) || '50', 10));
    const offset = Number.parseInt((req.query.offset as string) || '0', 10);
    const search = req.query.search as string | undefined;

    const db = getDatabase();
    const scans = db.listScanJobs(limit, offset, search);
    res.json({ scans, limit, offset });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Start New Reconnaissance Scan
const CreateScanSchema = z.object({
  target: z.string().min(1, 'Target host or IP address is required'),
  ports: z.string().optional(),
  concurrency: z.number().int().min(1).max(200).optional(),
  timeoutMs: z.number().int().min(200).max(10000).optional(),
  enableUdp: z.boolean().optional(),
  allowPrivate: z.boolean().optional(),
  runAiAnalysis: z.boolean().optional(),
});

app.post('/api/scans', async (req: Request, res: Response) => {
  const parseResult = CreateScanSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'Invalid scan request parameters',
      details: parseResult.error.flatten(),
    });
  }

  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const rateCheck = scanJobRateLimiter.check(clientIp, 1);
  if (!rateCheck.allowed) {
    return res.status(429).json({
      error: 'Scan submission rate limit exceeded. Please wait before scheduling another scan.',
      retryAfterMs: rateCheck.retryAfterMs,
    });
  }

  const { target, ports, concurrency, timeoutMs, enableUdp, allowPrivate, runAiAnalysis } = parseResult.data;

  try {
    const scanPromise = executeReconScan({
      target,
      ports,
      concurrency,
      timeoutMs,
      enableUdp,
      allowPrivate,
      actor: `web-user (${clientIp})`,
      onProgress: (evt) => {
        activeJobs.set(evt.jobId, evt);
      },
    });

    const result = await scanPromise;
    activeJobs.delete(result.job.id);

    // Optional Gemini auto-analysis
    if (runAiAnalysis && process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') {
      try {
        await analyzeScanWithGemini(result.job.id);
      } catch (err: any) {
        console.warn(`[AI_ANALYSIS_AUTO_FAILED] ${err.message}`);
      }
    }

    const fullData = getScanReportData(result.job.id);
    return res.status(201).json({
      success: true,
      data: fullData,
    });
  } catch (err: any) {
    return res.status(400).json({
      error: err.message || 'Scan execution failed',
      code: err.code || 'SCAN_ERROR',
    });
  }
});

// 5. Active Scan Progress Query
app.get('/api/scans/active/:jobId', (req: Request, res: Response) => {
  const { jobId } = req.params;
  const progress = activeJobs.get(jobId);
  if (progress) {
    return res.json({ active: true, progress });
  }
  const db = getDatabase();
  const job = db.getScanJob(jobId);
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }
  return res.json({ active: false, status: job.status });
});

// 6. Get Single Scan Details
app.get('/api/scans/:id', (req: Request, res: Response) => {
  try {
    const data = getScanReportData(req.params.id);
    res.json(data);
  } catch (err: any) {
    res.status(404).json({ error: err.message });
  }
});

// 7. Delete Scan Job
app.delete('/api/scans/:id', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const success = db.deleteScanJob(req.params.id);
    if (!success) return res.status(404).json({ error: 'Scan job not found' });

    logSecurityAudit({
      action: 'SCAN_DELETED',
      target: req.params.id,
      actor: 'web-user',
      status: 'success',
    });

    res.json({ success: true, message: 'Scan job removed' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 8. Scan Comparison (Diff)
app.get('/api/scans/diff/:oldId/:newId', (req: Request, res: Response) => {
  try {
    const diff = compareScans(req.params.oldId, req.params.newId);
    res.json(diff);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// 9. Download or View Report in various formats
app.get('/api/scans/:id/report', (req: Request, res: Response) => {
  try {
    const format = ((req.query.format as string) || 'html').toLowerCase() as any;
    const download = req.query.download === 'true';
    const report = generateReport(req.params.id, format);

    res.setHeader('Content-Type', report.mimeType);
    if (download) {
      res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
    }
    res.send(report.content);
  } catch (err: any) {
    res.status(404).json({ error: err.message });
  }
});

// 10. Trigger AI Security Analysis via Gemini
app.post('/api/scans/:id/analyze', async (req: Request, res: Response) => {
  try {
    const analysis = await analyzeScanWithGemini(req.params.id);
    res.json({ success: true, analysis });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// 11. Audit Logs
app.get('/api/audit-logs', (req: Request, res: Response) => {
  try {
    const limit = Math.min(200, Number.parseInt((req.query.limit as string) || '100', 10));
    const db = getDatabase();
    const logs = db.listAuditEvents(limit);
    res.json({ logs });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 12. App Configuration
app.get('/api/config', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const config = db.getAllConfig();
    res.json({
      config,
      policy: {
        defaultDeny: true,
        rfc1918BlockedByDefault: true,
        loopbackBlockedByDefault: true,
        cloudMetadataBlockedByDefault: true,
      },
      hasGeminiApiKey: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'),
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// --- Frontend Middleware Mounting ---
async function startServer() {
  if (isDev) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, HOST, () => {
    console.log(`\x1b[31;1m[AUGUR RECON 2.0]\x1b[0m Server running at http://${HOST}:${PORT}`);
    console.log(`Developer: Isha Sonaria | Attack Surface Intelligence Platform`);
  });
}

startServer();
