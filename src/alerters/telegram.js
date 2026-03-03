import config from '../../config.js';
import logger from '../utils/logger.js';

const API_BASE = `https://api.telegram.org/bot${config.telegram.botToken}`;

const SEVERITY_ICON = {
  LOW: '\u{1F7E1}',
  MEDIUM: '\u{1F7E0}',
  HIGH: '\u{1F534}',
  CRITICAL: '\u{1F6A8}',
};

const queue = [];
let draining = false;

export async function sendAlert(threat) {
  const icon = SEVERITY_ICON[threat.severity] || '\u26AA';
  const text = [
    `${icon} <b>${threat.severity} \u2014 ${threat.rule}</b>`,
    ``,
    `<b>Source IP:</b> <code>${threat.ip || 'N/A'}</code>`,
    `<b>Time:</b> ${threat.timestamp}`,
    `<b>Endpoint:</b> <code>${escapeHtml(threat.endpoint || 'N/A')}</code>`,
    `<b>Details:</b> ${escapeHtml(threat.details)}`,
    `<b>Suggested:</b> ${escapeHtml(threat.suggestedAction)}`,
    ``,
    `<b>Actions:</b>`,
    `<code>/block_ip ${threat.ip}</code>`,
    `<code>/whitelist ${threat.ip}</code>`,
    `<code>/report ${threat.ip}</code>`,
  ].join('\n');

  await sendMessage(text);
}

export async function sendAIAnalysis(threat, analysis) {
  const text = [
    `\u{1F916} <b>AI Analysis \u2014 ${threat.rule}</b>`,
    ``,
    `<b>IP:</b> <code>${threat.ip}</code>`,
    `<b>Real Threat:</b> ${analysis.isRealThreat ? '\u2705 Yes' : '\u274C Likely false positive'}`,
    `<b>Attack Type:</b> ${escapeHtml(analysis.attackType)}`,
    `<b>Confidence:</b> ${analysis.confidence}%`,
    `<b>Recommended Action:</b> <code>${analysis.action}</code>`,
    ``,
    `<b>Explanation:</b>`,
    escapeHtml(analysis.explanation),
  ].join('\n');

  await sendMessage(text);
}

export async function sendActionTaken(ip, analysis) {
  await sendMessage(
    `\u26A1 <b>Autonomous Action Executed</b>\n\n` +
    `IP <code>${ip}</code> has been <b>${escapeHtml(analysis.action)}ed</b>.\n` +
    `Reason: ${escapeHtml(analysis.explanation)}`
  );
}

export async function sendMessage(text) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    logger.debug('Telegram not configured, message dropped');
    return;
  }

  queue.push(text);
  if (!draining) drainQueue();
}

async function drainQueue() {
  draining = true;
  while (queue.length > 0) {
    const text = queue.shift();
    try {
      const res = await fetch(`${API_BASE}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text,
          parse_mode: 'HTML',
          disable_web_page_preview: true,
        }),
      });
      if (!res.ok) {
        const body = await res.text();
        logger.error('Telegram API error', { status: res.status, body: body.slice(0, 200) });
      }
    } catch (err) {
      logger.error('Telegram send failed', { error: err.message });
    }
    // Telegram rate limit: ~30 msgs/sec, but be conservative
    if (queue.length > 0) await new Promise(r => setTimeout(r, 1000));
  }
  draining = false;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
