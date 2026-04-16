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
  if (!config.telegram.botToken || !config.telegram.chatId) {
    logger.debug('Telegram not configured, Agent Smith GIF dropped');
    return;
  }

  const safeIp = escapeHtml(ip);
  queue.push({
    type: 'animation',
    animation: AGENT_SMITH_GIF,
    caption: `\u{1F576}\uFE0F <b>Agent Smith has dealt with</b> <code>${safeIp}</code>`,
  });
  if (!draining) drainQueue();
}

// Fire-and-forget: queues the message and returns immediately without awaiting
// queue drain / Telegram I/O. Returns a resolved Promise so existing
// `await sendMessage(...).catch(...)` call sites remain valid. Callers that
// need to confirm delivery (e.g. the daily digest) must use
// sendMessageAwaitable() instead.
export async function sendMessage(text, replyMarkup) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    logger.debug('Telegram not configured, message dropped');
    return;
  }

  queue.push({ type: 'message', text, replyMarkup });
  if (!draining) drainQueue();
}

// Awaitable variant for callers that must confirm delivery (e.g. daily digest
// marking lastSentDate only on success). Resolves to true if the Telegram API
// accepted the message, false otherwise. Regular callers should use
// sendMessage so they don't block on queue backoff.
export function sendMessageAwaitable(text, replyMarkup) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    logger.debug('Telegram not configured, message dropped');
    return Promise.resolve(false);
  }

  return new Promise(resolve => {
    queue.push({ type: 'message', text, replyMarkup, resolve });
    if (!draining) drainQueue();
  });
}

async function drainQueue() {
  draining = true;
  while (queue.length > 0) {
    const item = queue.shift();
    let success = false;
    try {
      let endpoint, body;
      if (item.type === 'animation') {
        endpoint = 'sendAnimation';
        body = {
          chat_id: config.telegram.chatId,
          animation: item.animation,
          caption: item.caption,
          parse_mode: 'HTML',
        };
      } else if (item.type === 'message') {
        endpoint = 'sendMessage';
        body = {
          chat_id: config.telegram.chatId,
          text: item.text,
          parse_mode: 'HTML',
          disable_web_page_preview: true,
        };
        if (item.replyMarkup) body.reply_markup = item.replyMarkup;
      } else {
        logger.error('Unknown Telegram queue item type', { type: item.type });
        if (item.resolve) item.resolve(false);
        continue;
      }

      const res = await fetch(`${API_BASE}/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      // Telegram returns HTTP 200 even on API errors, signalling failure via
      // `{ ok: false, error_code, description }` in the body. Parse it and
      // treat anything other than `ok: true` as a failure.
      const rawBody = await res.text();
      let parsed = null;
      try {
        parsed = JSON.parse(rawBody);
      } catch {
        // Non-JSON body (rare — e.g. proxy/5xx HTML); fall through to !res.ok path.
      }
      if (!res.ok || !parsed || parsed.ok !== true) {
        logger.error('Telegram API error', {
          status: res.status,
          error_code: parsed?.error_code,
          description: parsed?.description,
          body: parsed ? undefined : rawBody.slice(0, 200),
        });
      } else {
        success = true;
      }
    } catch (err) {
      logger.error('Telegram send failed', { error: err.message });
    }
    if (item.resolve) item.resolve(success);
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
