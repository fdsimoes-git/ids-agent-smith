import config from '../../config.js';
import logger from '../utils/logger.js';
import { sendMessage } from '../alerters/telegram.js';
import honeypotStats from './stats.js';

let timer = null;

export function startDigest() {
  if (!config.honeypot.dailyDigest.enabled) return;

  timer = setInterval(() => {
    const now = new Date();
    if (now.getHours() === config.honeypot.dailyDigest.hour && now.getMinutes() === 0) {
      generateAndSend().catch(err => {
        logger.error('Honeypot daily digest failed', { error: err.message });
      });
    }
  }, 60_000);

  logger.info(`Honeypot daily digest scheduled at ${String(config.honeypot.dailyDigest.hour).padStart(2, '0')}:00`);
}

export function stopDigest() {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

async function generateAndSend() {
  const summary = honeypotStats.getSummary();

  if (summary.connectionsLast24h === 0) {
    await sendMessage(
      `\u{1F36F} <b>Honeypot Daily Digest</b>\n\n` +
      `No honeypot activity in the last 24 hours.`
    );
    logger.info('Honeypot daily digest sent (no activity)');
    return;
  }

  const lines = [
    `\u{1F36F} <b>Honeypot Daily Digest</b>`,
    ``,
    `<b>Total hits (24h):</b> ${summary.connectionsLast24h}`,
    `<b>Unique attacker IPs:</b> ${summary.uniqueIps}`,
  ];

  // Top 5 countries — only if geo data is present on connections
  const countryCounts = {};
  for (const conn of honeypotStats.getAll()) {
    if (conn.country) {
      countryCounts[conn.country] = (countryCounts[conn.country] || 0) + 1;
    }
  }
  const topCountries = Object.entries(countryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  if (topCountries.length > 0) {
    lines.push(``, `<b>Top countries:</b>`);
    for (const [country, count] of topCountries) {
      lines.push(`  ${escapeHtml(country)} \u2014 ${count} hits`);
    }
  }

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

  // Top 3 credential attempts — extract user/pass patterns from SSH-like payloads
  const credCounts = {};
  for (const conn of honeypotStats.getAll()) {
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

  await sendMessage(lines.join('\n'));
  logger.info('Honeypot daily digest sent');
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
