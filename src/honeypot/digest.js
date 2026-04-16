import config from '../../config.js';
import logger from '../utils/logger.js';
import { sendMessageAwaitable } from '../alerters/telegram.js';
import honeypotStats from './stats.js';

let timer = null;
let lastSentDate = null;
let running = false;

function msUntilNext(hour, minute) {
  const now = new Date();
  const next = new Date(now);
  next.setHours(hour, minute, 0, 0);
  if (next <= now) next.setDate(next.getDate() + 1);
  return next - now;
}

function scheduleNext() {
  if (!running) return;

  const { hour, minute } = config.honeypot.dailyDigest;
  const delay = msUntilNext(hour, minute);

  timer = setTimeout(async () => {
    // generateAndSend awaits Telegram I/O; stopDigest() may flip `running` off
    // mid-flight, so re-check before rescheduling to guarantee the chain stops.
    if (!running) return;
    const now = new Date();
    const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    if (lastSentDate !== today) {
      try {
        const success = await generateAndSend();
        if (success) {
          lastSentDate = today;
        }
      } catch (err) {
        logger.error('Honeypot daily digest failed', { error: err.message });
      }
    }
    if (!running) return;
    scheduleNext();
  }, delay);
}

export function startDigest() {
  if (!config.honeypot.dailyDigest.enabled) return;

  // Guard against multiple calls — clear existing timer before setting new one
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }

  running = true;
  scheduleNext();

  const { hour, minute } = config.honeypot.dailyDigest;
  logger.info(`Honeypot daily digest scheduled at ${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`);
}

export function stopDigest() {
  running = false;
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
}

async function generateAndSend() {
  const summary = honeypotStats.getSummary();

  if (summary.connectionsLast24h === 0) {
    const sent = await sendMessageAwaitable(
      `\u{1F36F} <b>Honeypot Daily Digest</b>\n\n` +
      `No honeypot activity in the last 24 hours.`
    );
    if (sent) logger.info('Honeypot daily digest sent (no activity)');
    return sent;
  }

  const lines = [
    `\u{1F36F} <b>Honeypot Daily Digest</b>`,
    ``,
    `<b>Total hits (24h):</b> ${summary.connectionsLast24h}`,
    `<b>Unique attacker IPs:</b> ${summary.uniqueIps}`,
  ];

  // TODO: Top countries section will be added after geo-IP data is available (see #18)

  // Most targeted ports
  if (summary.topPorts.length > 0) {
    lines.push(``, `<b>Most targeted ports:</b>`);
    for (const { port, count } of summary.topPorts.slice(0, 5)) {
      lines.push(`  :${port} \u2014 ${count} hits`);
    }
  }

  // Most active hour
  if (summary.hourlyLast24h.length > 0) {
    const peak = summary.hourlyLast24h.reduce((a, b) => (b.count > a.count ? b : a));
    lines.push(``, `<b>Most active hour:</b> ${peak.hour} (${peak.count} connections)`);
  }

  // Top 3 credential attempts — extract user/pass patterns from SSH-like payloads (last 24h only)
  const now24h = Date.now() - 86400_000;
  const credCounts = Object.create(null);
  for (const conn of honeypotStats.getAll()) {
    if (new Date(conn.timestamp).getTime() <= now24h) continue;
    if (!conn.payload) continue;
    const creds = extractCredentials(conn.payload);
    for (const cred of creds) {
      credCounts[cred] = (credCounts[cred] || 0) + 1;
    }
  }
  const topCreds = Object.entries(credCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);
  if (topCreds.length > 0) {
    lines.push(``, `<b>Top credential attempts:</b>`);
    for (const [cred, count] of topCreds) {
      lines.push(`  <code>${escapeHtml(cred)}</code> \u2014 ${count}x`);
    }
  }

  const sent = await sendMessageAwaitable(lines.join('\n'));
  if (sent) logger.info('Honeypot daily digest sent');
  return sent;
}

function extractCredentials(payload) {
  const results = [];
  // Match common SSH / login patterns: user:pass, USER root PASS ..., login=...&password=...
  const colonMatch = payload.match(/^(\S{1,32}):(\S{1,32})$/m);
  if (colonMatch) {
    results.push(`${colonMatch[1]}:${colonMatch[2]}`);
  }
  const sshMatch = payload.match(/USER\s+(\S{1,32}).*?PASS\s+(\S{1,32})/i);
  if (sshMatch) {
    results.push(`${sshMatch[1]}:${sshMatch[2]}`);
  }
  const formMatch = payload.match(/(?:user(?:name)?|login)=([^&\s]{1,32}).*?(?:pass(?:word)?)=([^&\s]{1,32})/i);
  if (formMatch) {
    results.push(`${formMatch[1]}:${formMatch[2]}`);
  }
  return results;
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
