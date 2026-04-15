import Anthropic from '@anthropic-ai/sdk';
import config from '../../config.js';
import logger, { appendToFile } from '../utils/logger.js';

let client = null;

if (config.anthropic.apiKey) {
  try {
    client = new Anthropic({ apiKey: config.anthropic.apiKey });
    logger.info('Anthropic AI client initialized');
  } catch (err) {
    logger.warn('Failed to initialize Anthropic client', { error: err.message });
  }
}

const SYSTEM_PROMPT = `You are a cybersecurity AI agent analyzing intrusion detection and prevention alerts for a Node.js web application hosted on a GCP e2-micro instance behind Nginx and Cloudflare.

Analyze each threat and provide:
1. Whether it is a real threat or a false positive
2. Attack type classification (DDoS, brute force, reconnaissance, injection, bot, etc.)
3. Confidence score (0-100%)
4. Recommended action: "block", "monitor", "ignore", or "escalate"
5. A concise human-readable explanation for the operations team

Consider the threat history to detect coordinated campaigns or recurring attackers.

IMPORTANT: The "explanation" field will be displayed in a Telegram message using HTML parse mode.
You may use these HTML tags for formatting: <b>bold</b>, <i>italic</i>, <code>inline code</code>, <pre>code block</pre>.
Do NOT use markdown. Do NOT use characters &, < or > unescaped outside of tags.

Respond ONLY with valid JSON:
{
  "isRealThreat": boolean,
  "attackType": "string",
  "confidence": number,
  "action": "block" | "monitor" | "ignore" | "escalate",
  "explanation": "string (Telegram HTML formatted)"
}`;

export async function analyzeThreat(threat, recentHistory) {
  if (!client) return null;

  const lines = [
    `Analyze this IDPS alert:`,
    ``,
    `Rule: ${threat.rule}`,
    `Source IP: ${threat.ip}`,
    `Severity: ${threat.severity}`,
    `Timestamp: ${threat.timestamp}`,
    `Endpoint: ${threat.endpoint}`,
    `Details: ${threat.details}`,
    `Event count: ${threat.count}`,
  ];

  if (threat.protocol) lines.push(`Protocol: ${threat.protocol}`);
  if (threat.httpMethod) lines.push(`HTTP Method: ${threat.httpMethod}`);
  if (threat.statusCode) {
    const label = threat.statusLabel ? ` (${threat.statusLabel})` : '';
    lines.push(`Status Code: ${threat.statusCode}${label}`);
  }
  if (threat.authMethod) lines.push(`Auth Method: ${threat.authMethod}`);
  if (threat.destPort) lines.push(`Dest Port: ${threat.destPort}`);
  if (threat.jail) lines.push(`Fail2ban Jail: ${threat.jail}`);
  if (threat.origin) lines.push(`Origin: ${threat.origin.name} (${threat.origin.type})`);
  if (threat.userAgent) lines.push(`User-Agent: ${threat.userAgent}`);

  lines.push(
    ``,
    `Recent 24h history (${recentHistory.length} events):`,
    JSON.stringify(recentHistory.slice(-50), null, 2),
  );

  const prompt = lines.join('\n');

  try {
    const response = await client.messages.create({
      model: config.autonomousMode ? config.anthropic.decisionModel : config.anthropic.model,
      max_tokens: config.anthropic.maxTokens,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
    });

    const text = response.content[0].text.trim();
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in AI response');

    const analysis = JSON.parse(jsonMatch[0]);

    await appendToFile(config.aiDecisionLogPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      threat: { rule: threat.rule, ip: threat.ip, severity: threat.severity },
      analysis,
    }));

    logger.info('AI analysis complete', {
      ip: threat.ip,
      action: analysis.action,
      confidence: analysis.confidence,
    });

    return analysis;
  } catch (err) {
    logger.error('AI analysis failed', { error: err.message });
    return null;
  }
}

export async function generateWeeklyReport(weekHistory) {
  if (!client) return null;

  try {
    const response = await client.messages.create({
      model: config.anthropic.model,
      max_tokens: config.anthropic.maxTokens,
      system: 'You are a cybersecurity analyst generating a concise weekly threat report. Format using Telegram HTML tags: <b>bold</b>, <i>italic</i>, <code>code</code>, <pre>block</pre>. Do NOT use markdown. Do NOT use unescaped &, < or > outside of tags.',
      messages: [{
        role: 'user',
        content: `Weekly IDPS report from ${weekHistory.length} events over the last 7 days:\n\n${JSON.stringify(weekHistory.slice(-200), null, 2)}\n\nCover: attack trends, top offenders, pattern analysis, and infrastructure recommendations.`,
      }],
    });

    return response.content[0].text;
  } catch (err) {
    logger.error('Weekly report generation failed', { error: err.message });
    return null;
  }
}

export async function generateIpReport(ip, history) {
  if (!client) return 'AI unavailable \u2014 Anthropic API not configured.';

  const ipEvents = history.filter(e => e.ip === ip);
  if (ipEvents.length === 0) return `No recorded activity for IP ${ip}.`;

  try {
    const response = await client.messages.create({
      model: config.anthropic.model,
      max_tokens: config.anthropic.maxTokens,
      system: 'You are a cybersecurity analyst. Provide a deep-dive report on this IP. Format using Telegram HTML tags: <b>bold</b>, <i>italic</i>, <code>code</code>, <pre>block</pre>. Do NOT use markdown. Do NOT use unescaped &, < or > outside of tags.',
      messages: [{
        role: 'user',
        content: `Deep-dive on IP ${ip} (${ipEvents.length} events):\n\n${JSON.stringify(ipEvents.slice(-50), null, 2)}\n\nAnalyze: attack patterns, timing, risk level, recommended actions.`,
      }],
    });
    return response.content[0].text;
  } catch (err) {
    return `AI report failed: ${err.message}`;
  }
}
