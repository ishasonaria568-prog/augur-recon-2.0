/**
 * AUGUR RECON 2.0 - AI Security Posture Advisor
 * Leverages Gemini API to synthesize real attack surface reconnaissance observations
 * into actionable security posture recommendations without hallucinating vulnerabilities.
 */

import { GoogleGenAI, Type } from '@google/genai';
import { getScanReportData } from '../reporting/report-generator.ts';
import { getDatabase } from '../db/database.ts';

export interface AiAnalysisResult {
  model: string;
  summary: string;
  keyFindings: Array<{
    category: string;
    observation: string;
    riskContext: string;
  }>;
  recommendations: Array<{
    priority: 'HIGH' | 'MEDIUM' | 'LOW';
    title: string;
    action: string;
  }>;
}

export async function analyzeScanWithGemini(jobId: string): Promise<AiAnalysisResult> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    throw new Error('GEMINI_API_KEY is not configured in environment variables. AI analysis requires a valid API key.');
  }

  const data = getScanReportData(jobId);
  const openPorts = data.ports.filter((p) => p.state === 'open');

  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  const prompt = `You are a Principal Cybersecurity Architect reviewing real empirical reconnaissance data collected by AUGUR RECON 2.0.

TARGET SPECIFICATION:
- Hostname: ${data.job.normalized_host}
- Resolved IP: ${data.job.resolved_ip}
- Scan Duration: ${data.job.duration_ms}ms
- Total Ports Probed: ${data.job.total_ports_probed}

EMPIRICAL FINDINGS:
1. Open Ports & Services:
${
  openPorts.length === 0
    ? 'No open ports detected.'
    : openPorts
        .map((p) => {
          const svc = data.services.find((s) => s.port === p.port);
          return `- Port ${p.port}/${p.protocol.toUpperCase()}: ${svc?.service_name || 'unknown'} (Product: ${svc?.product || 'none'}, Version: ${svc?.version || 'none'}, Banner: "${svc?.banner || 'none'}")`;
        })
        .join('\n')
}

2. TLS Certificates:
${
  data.tls.length === 0
    ? 'No TLS certificates observed.'
    : data.tls
        .map(
          (t) =>
            `- Port ${t.port}: Subject="${t.subject_cn}", Issuer="${t.issuer_cn}", Valid until=${t.valid_to} (${t.days_remaining} days left), Valid=${t.is_valid ? 'Yes' : 'No (' + t.validation_error + ')'}, Cipher=${t.cipher}`
        )
        .join('\n')
}

3. DNS Records:
${
  data.dns.length === 0
    ? 'No DNS records enumerated.'
    : data.dns.map((d) => `- ${d.record_type}: ${d.value} (TTL: ${d.ttl || 'default'})`).join('\n')
}

CRITICAL INSTRUCTIONS:
- You must base your analysis STRICTLY on the observed evidence provided above.
- NEVER invent or hallucinate CVE numbers or hypothetical exploits not backed by concrete evidence.
- Clearly separate observed facts (e.g. exposed administrative ports, expired TLS certificates, missing SPF records) from hardening recommendations.
- Keep the summary executive and technical.`;

  let response: any = null;
  let attempts = 0;
  const maxAttempts = 3;

  while (attempts < maxAttempts) {
    attempts++;
    try {
      response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          systemInstruction:
            'You are an authoritative cybersecurity analyst producing accurate, grounded attack surface intelligence reports.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: {
                type: Type.STRING,
                description: 'Executive technical summary of the observed attack surface posture.',
              },
              keyFindings: {
                type: Type.ARRAY,
                description: 'Concrete observations regarding exposed attack surfaces.',
                items: {
                  type: Type.OBJECT,
                  properties: {
                    category: { type: Type.STRING },
                    observation: { type: Type.STRING },
                    riskContext: { type: Type.STRING },
                  },
                  required: ['category', 'observation', 'riskContext'],
                },
              },
              recommendations: {
                type: Type.ARRAY,
                description: 'Prioritized network and perimeter hardening recommendations.',
                items: {
                  type: Type.OBJECT,
                  properties: {
                    priority: { type: Type.STRING, enum: ['HIGH', 'MEDIUM', 'LOW'] },
                    title: { type: Type.STRING },
                    action: { type: Type.STRING },
                  },
                  required: ['priority', 'title', 'action'],
                },
              },
            },
            required: ['summary', 'keyFindings', 'recommendations'],
          },
        },
      });
      break; // Success
    } catch (err: any) {
      if (attempts >= maxAttempts) {
        throw new Error(`Gemini AI service unavailable after ${maxAttempts} attempts: ${err.message || 'Transient error'}`);
      }
      // Wait before retry
      await new Promise((resolve) => setTimeout(resolve, 1500 * attempts));
    }
  }

  const parsed = JSON.parse(response.text || '{}');

  const result: AiAnalysisResult = {
    model: 'gemini-3.8-flash',
    summary: parsed.summary || 'Attack surface reconnaissance completed.',
    keyFindings: parsed.keyFindings || [],
    recommendations: parsed.recommendations || [],
  };

  // Persist analysis in SQLite
  const db = getDatabase();
  db.saveAiAnalysis({
    job_id: jobId,
    model: result.model,
    summary: result.summary,
    key_findings_json: JSON.stringify(result.keyFindings),
    recommendations_json: JSON.stringify(result.recommendations),
    created_at: new Date().toISOString(),
  });

  return result;
}
