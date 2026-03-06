import config from '../../config.js';
import logger from '../utils/logger.js';
import { sendMessage } from '../alerters/telegram.js';
import { blockIp, unblockIp } from '../ai/actions.js';
import { generateIpReport } from '../ai/analyzer.js';
import { sanitizeIp } from '../utils/sanitize.js';

const API_BASE = `https://api.telegram.org/bot${config.telegram.botToken}`;

let offset = 0;
let running = false;

export function startBot(store, memory) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    logger.warn('Telegram bot not configured — commands disabled');
    return;
  }

  running = true;
  poll(store, memory);
  logger.info('Telegram bot command listener started');
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
          if (update.message) {
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
        await sendMessage(
          `\u2705 IP <code>${ip}</code> blocked:\n` +
          results.map(r => `\u251C ${escapeHtml(r)}`).join('\n')
        );
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
          const scope = jail === 'sshd' ? 'ssh (fail2ban)' : jail;
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
        const lines = [
          `\u{1F4CA} <b>IDS Agent Status</b>`,
          ``,
          `<b>Uptime:</b> ${formatUptime(stats.uptime)}`,
          `<b>Events processed:</b> ${stats.totalEvents}`,
          `<b>Tracked keys:</b> ${stats.trackedKeys}`,
          `<b>Banned IPs:</b> ${stats.bannedIps}`,
          `<b>Whitelisted IPs:</b> ${stats.whitelistedIps}`,
          `<b>Memory:</b> ${(stats.memoryUsage / 1024 / 1024).toFixed(1)} MB`,
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

      case '/help':
        await sendMessage(
          `\u{1F6E1}\uFE0F <b>IDS Agent Commands</b>\n\n` +
          `/block_ip &lt;IP&gt; \u2014 Block IP (fail2ban + iptables + nginx)\n` +
          `/unblock_ip &lt;IP&gt; \u2014 Unblock IP from all layers\n` +
          `/whitelist &lt;IP&gt; \u2014 Suppress alerts for IP\n` +
          `/report &lt;IP&gt; \u2014 AI deep-dive on IP activity\n` +
          `/blocked \u2014 List currently blocked IPs\n` +
          `/status \u2014 Current threat summary\n` +
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
