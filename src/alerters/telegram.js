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
  const lines = [
    `${icon} <b>${threat.severity} \u2014 ${threat.rule}</b>`,
    ``,
    `<b>Source IP:</b> <code>${threat.ip || 'N/A'}</code>`,
    `<b>Time:</b> ${threat.timestamp}`,
  ];

  if (threat.protocol) {
    lines.push(`<b>Protocol:</b> ${escapeHtml(threat.protocol)}`);
  }
  if (threat.httpMethod && threat.statusCode) {
    const label = threat.statusLabel ? ` (${escapeHtml(threat.statusLabel)})` : '';
    lines.push(`<b>Request:</b> ${escapeHtml(threat.httpMethod)} → ${escapeHtml(String(threat.statusCode))}${label}`);
  } else if (threat.httpMethod) {
    lines.push(`<b>Request:</b> ${escapeHtml(threat.httpMethod)}`);
  }
  if (threat.authMethod) {
    lines.push(`<b>Auth Method:</b> ${escapeHtml(threat.authMethod)}`);
  }
  if (threat.destPort) {
    lines.push(`<b>Dest Port:</b> <code>${escapeHtml(String(threat.destPort))}</code>`);
  }
  if (threat.jail) {
    lines.push(`<b>Jail:</b> ${escapeHtml(threat.jail)}`);
  }
  if (threat.origin) {
    lines.push(`<b>Origin:</b> ${escapeHtml(threat.origin.name)} (${escapeHtml(threat.origin.type)})`);
  }

  lines.push(
    `<b>Endpoint:</b> <code>${escapeHtml(threat.endpoint || 'N/A')}</code>`,
    `<b>Details:</b> ${escapeHtml(threat.details)}`,
    `<b>Suggested:</b> ${escapeHtml(threat.suggestedAction)}`,
  );
  const text = lines.join('\n');

  const replyMarkup = threat.ip ? {
    inline_keyboard: [
      [
        { text: '\u{1F6AB} Block IP', callback_data: `block_ip|${threat.ip}` },
        { text: '\u2705 Whitelist', callback_data: `whitelist|${threat.ip}` },
        { text: '\u{1F50D} Report', callback_data: `report|${threat.ip}` },
      ],
    ],
  } : undefined;

  await sendMessage(text, replyMarkup);
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
    analysis.explanation,
  ].join('\n');

  const aiMarkup = threat.ip ? {
    inline_keyboard: [
      [
        { text: '\u{1F6AB} Block IP', callback_data: `block_ip|${threat.ip}` },
        { text: '\u2705 Whitelist', callback_data: `whitelist|${threat.ip}` },
      ],
    ],
  } : undefined;

  await sendMessage(text, aiMarkup);
}

export async function sendActionTaken(ip, analysis) {
  const markup = ip ? {
    inline_keyboard: [
      [
        { text: '\u{1F513} Unblock IP', callback_data: `unblock_ip|${ip}` },
        { text: '\u{1F50D} Report', callback_data: `report|${ip}` },
      ],
    ],
  } : undefined;

  await sendMessage(
    `\u26A1 <b>Autonomous Action Executed</b>\n\n` +
    `IP <code>${ip}</code> has been <b>${escapeHtml(analysis.action)}ed</b>.\n` +
    `Reason: ${escapeHtml(analysis.explanation)}`,
    markup
  );
}

const AGENT_SMITH_GIF = 'https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExMXNweWMwcml0bHhjODZ1bjVnaG1xdGZyNHdmNXQ3aXdlajE0NnBvZiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/nbpvCPsFLItHO/giphy.gif';

export async function sendAgentSmithGif(ip) {
  if (!config.telegram.botToken || !config.telegram.chatId) return;

  try {
    const body = {
      chat_id: config.telegram.chatId,
      animation: AGENT_SMITH_GIF,
      caption: `\u{1F576}\uFE0F <b>Agent Smith has dealt with</b> <code>${ip}</code>`,
      parse_mode: 'HTML',
    };
    const res = await fetch(`${API_BASE}/sendAnimation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errBody = await res.text();
      logger.error('Telegram sendAnimation error', { status: res.status, body: errBody.slice(0, 200) });
    }
  } catch (err) {
    logger.error('Telegram GIF send failed', { error: err.message });
  }
}

export async function sendMessage(text, replyMarkup) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    logger.debug('Telegram not configured, message dropped');
    return;
  }

  queue.push({ text, replyMarkup });
  if (!draining) drainQueue();
}

async function drainQueue() {
  draining = true;
  while (queue.length > 0) {
    const { text, replyMarkup } = queue.shift();
    try {
      const body = {
        chat_id: config.telegram.chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      };
      if (replyMarkup) body.reply_markup = replyMarkup;

      const res = await fetch(`${API_BASE}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const errBody = await res.text();
        logger.error('Telegram API error', { status: res.status, body: errBody.slice(0, 200) });
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
