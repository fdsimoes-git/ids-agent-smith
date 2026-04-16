import config from '../../config.js';
import logger from '../utils/logger.js';
import { sendMessage, sendAgentSmithGif } from '../alerters/telegram.js';
import { blockIp, unblockIp } from '../ai/actions.js';
import { generateIpReport } from '../ai/analyzer.js';
import { sanitizeIp } from '../utils/sanitize.js';
import { generateTelegramReport } from '../honeypot/report.js';

const API_BASE = `https://api.telegram.org/bot${config.telegram.botToken}`;

let offset = 0;
let running = false;

const BOT_COMMANDS = [
  { command: 'block_ip', description: 'Block an IP across all security layers' },
  { command: 'unblock_ip', description: 'Unblock a previously blocked IP' },
  { command: 'whitelist', description: 'Suppress future alerts for an IP' },
  { command: 'report', description: 'Generate AI analysis for an IP' },
  { command: 'blocked', description: 'List all currently blocked IPs' },
  { command: 'status', description: 'Show threat summary and system stats' },
  { command: 'honeypot', description: 'Show honeypot stats summary' },
  { command: 'help', description: 'Show available commands' },
];

export async function startBot(store, memory) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    logger.warn('Telegram bot not configured — commands disabled');
    return;
  }

  await registerCommands();
  running = true;
  poll(store, memory);
  logger.info('Telegram bot command listener started');
}

async function registerCommands() {
  try {
    const res = await fetch(`${API_BASE}/setMyCommands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commands: BOT_COMMANDS }),
    });
    if (!res.ok) {
      const body = await res.text();
      logger.error('Failed to register bot commands', { status: res.status, body: body.slice(0, 200) });
    } else {
      logger.info('Telegram bot command menu registered');
    }
  } catch (err) {
    logger.error('Failed to register bot commands', { error: err.message });
  }
}

async function poll(store, memory) {
  while (running) {
    try {
      const res = await fetch(
        `${API_BASE}/getUpdates?offset=${offset}&timeout=30`,
        { signal: AbortSignal.timeout(35_000) }
      );
      const data = await res.json();

      if (data.ok && data.result.length > 0) {
        for (const update of data.result) {
          offset = update.update_id + 1;
          if (update.callback_query) {
            await handleCallbackQuery(update.callback_query, store, memory);
          } else if (update.message) {
            await handleMessage(update.message, store, memory);
          }
        }
      }
    } catch (err) {
      if (err.name !== 'TimeoutError' && err.name !== 'AbortError' && running) {
        logger.error('Bot poll error', { error: err.message });
        await new Promise(r => setTimeout(r, 5000));
      }
    }
  }
}

async function answerCallbackQuery(callbackQueryId, text) {
  try {
    await fetch(`${API_BASE}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ callback_query_id: callbackQueryId, text }),
    });
  } catch (err) {
    logger.error('Failed to answer callback query', { error: err.message });
  }
}

const ALLOWED_CALLBACK_ACTIONS = new Set(['block_ip', 'unblock_ip', 'whitelist', 'report']);

async function handleCallbackQuery(query, store, memory) {
  if (String(query.message?.chat?.id) !== String(config.telegram.chatId)) {
    await answerCallbackQuery(query.id, 'Not authorized');
    return;
  }

  const data = query.data || '';
  const separatorIndex = data.indexOf('|');
  if (separatorIndex === -1) {
    await answerCallbackQuery(query.id, 'Invalid callback payload');
    return;
  }

  const action = data.slice(0, separatorIndex);
  const ip = data.slice(separatorIndex + 1);

  if (!ALLOWED_CALLBACK_ACTIONS.has(action)) {
    await answerCallbackQuery(query.id, 'Unknown action');
    return;
  }

  const cleanIp = sanitizeIp(ip);

  if (!cleanIp) {
    await answerCallbackQuery(query.id, 'Invalid IP address');
    return;
  }

  const syntheticMsg = {
    chat: query.message.chat,
    text: `/${action} ${cleanIp}`,
  };

  await answerCallbackQuery(query.id, `Running /${action} ${cleanIp}...`);
  await handleMessage(syntheticMsg, store, memory);
}

async function handleMessage(msg, store, memory) {
  // Security: only respond to the configured chat
  if (String(msg.chat.id) !== String(config.telegram.chatId)) return;

  const text = (msg.text || '').trim();
  if (!text.startsWith('/')) return;

  const [cmd, ...args] = text.split(/\s+/);

  try {
    switch (cmd) {
      case '/block_ip': {
        const ip = sanitizeIp(args[0]);
        if (!ip) {
          await sendMessage('\u26A0\uFE0F Usage: /block_ip &lt;IP&gt;');
          return;
        }
        const results = await blockIp(ip);
        const blocked = store.wasBanned(ip);
        await sendMessage(
          blocked
            ? `\u2705 IP <code>${ip}</code> blocked:\n` +
              results.map(r => `\u251C ${escapeHtml(r)}`).join('\n')
            : `\u274C Failed to block <code>${ip}</code> — no blocking layers succeeded.\n` +
              results.map(r => `\u251C ${escapeHtml(r)}`).join('\n')
        );
        if (blocked) await sendAgentSmithGif(ip);
        break;
      }

      case '/unblock_ip': {
        const ip = sanitizeIp(args[0]);
        if (!ip) {
          await sendMessage('\u26A0\uFE0F Usage: /unblock_ip &lt;IP&gt;');
          return;
        }
        const ubResults = await unblockIp(ip);
        await sendMessage(
          `\u{1F513} IP <code>${ip}</code> unblocked:\n` +
          ubResults.map(r => `\u251C ${escapeHtml(r)}`).join('\n')
        );
        break;
      }

      case '/whitelist': {
        const ip = sanitizeIp(args[0]);
        if (!ip) {
          await sendMessage('\u26A0\uFE0F Usage: /whitelist &lt;IP&gt;');
          return;
        }
        store.whitelist(ip);
        await sendMessage(`\u2705 IP <code>${ip}</code> whitelisted \u2014 future alerts suppressed`);
        break;
      }

      case '/report': {
        const ip = sanitizeIp(args[0]);
        if (!ip) {
          await sendMessage('\u26A0\uFE0F Usage: /report &lt;IP&gt;');
          return;
        }
        await sendMessage(`\u{1F50D} Generating AI report for <code>${ip}</code>...`);
        const history = memory.getLastWeek();
        const report = await generateIpReport(ip, history);
        await sendMessage(`\u{1F4CB} <b>IP Report: ${ip}</b>\n\n${report}`);
        break;
      }

      case '/blocked': {
        const banned = store.getBannedIps();
        if (banned.length === 0) {
          await sendMessage('\u2705 No blocked IPs at the moment.');
          break;
        }
        const header = `\u{1F6AB} <b>Blocked IPs (${banned.length})</b>`;
        const entries = banned.map(({ ip, bannedAt, jail }) => {
          const ago = formatUptime(Math.floor((Date.now() - bannedAt) / 1000));
          const scope = formatScope(jail);
          return `<code>${ip}</code> \u2014 <b>${escapeHtml(scope)}</b>, ${ago} ago`;
        });
        // Telegram limits messages to 4096 chars — send in chunks
        let out = header;
        for (const entry of entries) {
          if (out.length + entry.length + 1 > 4000) {
            await sendMessage(out);
            out = `\u{1F6AB} <b>Blocked IPs (cont.)</b>`;
          }
          out += '\n' + entry;
        }
        await sendMessage(out);
        break;
      }

      case '/status': {
        const stats = store.getStats();
        const mem = stats.memory || {};
        const lines = [
          `\u{1F4CA} <b>IDPS Agent Status</b>`,
          ``,
          `<b>Uptime:</b> ${formatUptime(stats.uptime)}`,
          `<b>Events processed:</b> ${stats.totalEvents}`,
          `<b>Tracked keys:</b> ${stats.trackedKeys}`,
          `<b>Banned IPs:</b> ${stats.bannedIps}`,
          `<b>Whitelisted IPs:</b> ${stats.whitelistedIps}`,
          `<b>Memory:</b> heap ${mem.heapUsedMb ?? '?'}/${mem.heapTotalMb ?? '?'} MB, RSS ${mem.rssMb ?? '?'} MB`,
          `<b>Autonomous mode:</b> ${config.autonomousMode ? 'ON' : 'OFF'}`,
        ];

        const threats = Object.entries(stats.threats);
        if (threats.length > 0) {
          lines.push(``, `<b>Active threat counters:</b>`);
          threats.forEach(([rule, data], i) => {
            const pre = i === threats.length - 1 ? '\u2514' : '\u251C';
            lines.push(`${pre} ${rule}: ${data.total}`);
          });
        }

        await sendMessage(lines.join('\n'));
        break;
      }

      case '/honeypot': {
        if (!config.honeypot?.enabled && !config.honeypot?.http?.enabled) {
          await sendMessage('\u26A0\uFE0F Honeypot is not enabled. Set <code>HONEYPOT_ENABLED=true</code> or <code>HONEYPOT_HTTP_ENABLED=true</code> to activate.');
          break;
        }
        const hpReport = generateTelegramReport();
        await sendMessage(`\u{1F36F} <b>Honeypot Report</b>\n\n${hpReport}`);
        break;
      }

      case '/help':
        await sendMessage(
          `\u{1F6E1}\uFE0F <b>IDPS Agent Commands</b>\n\n` +
          `/block_ip &lt;IP&gt; \u2014 Block IP (fail2ban + iptables + nginx)\n` +
          `/unblock_ip &lt;IP&gt; \u2014 Unblock IP from all layers\n` +
          `/whitelist &lt;IP&gt; \u2014 Suppress alerts for IP\n` +
          `/report &lt;IP&gt; \u2014 AI deep-dive on IP activity\n` +
          `/blocked \u2014 List currently blocked IPs\n` +
          `/status \u2014 Current threat summary\n` +
          `/honeypot \u2014 Honeypot stats summary\n` +
          `/help \u2014 Show this message`
        );
        break;

      default:
        // Ignore unknown commands silently
        break;
    }
  } catch (err) {
    logger.error('Bot command error', { cmd, error: err.message });
    await sendMessage(`\u274C Command failed: ${escapeHtml(err.message)}`).catch(() => {});
  }
}

function formatScope(jail) {
  const labels = { sshd: 'ssh', fail2ban: 'ssh', iptables: 'iptables', ip6tables: 'iptables', nginx: 'http' };
  return (jail || 'unknown').split(',').map(l => labels[l.trim()] || l.trim()).join(' + ');
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d ${h}h ${m}m` : `${h}h ${m}m`;
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function stopBot() {
  running = false;
}
