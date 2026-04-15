import config from '../../config.js';
import { sendMessage } from './telegram.js';
import logger from '../utils/logger.js';

let timer = null;

export function scheduleDailySummary(store, memory) {
  timer = setInterval(() => {
    const now = new Date();
    if (now.getHours() === config.dailySummaryHour && now.getMinutes() === 0) {
      generateAndSend(store, memory).catch(err => {
        logger.error('Daily summary failed', { error: err.message });
      });
    }
  }, 60_000);
}

async function generateAndSend(store, memory) {
  const events = memory.getLast24h();

  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const byRule = {};
  const ipCounts = {};

  for (const e of events) {
    if (e.severity) bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
    if (e.rule) byRule[e.rule] = (byRule[e.rule] || 0) + 1;
    if (e.ip) ipCounts[e.ip] = (ipCounts[e.ip] || 0) + 1;
  }

  const topIps = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const topRules = Object.entries(byRule)
    .sort((a, b) => b[1] - a[1]);

  const date = new Date().toISOString().slice(0, 10);
  const total = events.length;

  const lines = [
    `\u{1F4CA} <b>IDPS Agent \u2014 Daily Summary (${date})</b>`,
    ``,
    `<b>Threats detected:</b> ${total}`,
    `\u251C CRITICAL: ${bySeverity.CRITICAL}`,
    `\u251C HIGH: ${bySeverity.HIGH}`,
    `\u251C MEDIUM: ${bySeverity.MEDIUM}`,
    `\u2514 LOW: ${bySeverity.LOW}`,
  ];

  if (topIps.length > 0) {
    lines.push(``, `<b>Top offending IPs:</b>`);
    topIps.forEach(([ip, count], i) => {
      const pre = i === topIps.length - 1 ? '\u2514' : '\u251C';
      lines.push(`${pre} <code>${ip}</code> \u2014 ${count} events`);
    });
  }

  if (topRules.length > 0) {
    lines.push(``, `<b>Rules triggered:</b>`);
    topRules.forEach(([rule, count], i) => {
      const pre = i === topRules.length - 1 ? '\u2514' : '\u251C';
      lines.push(`${pre} ${rule}: ${count}`);
    });
  }

  await sendMessage(lines.join('\n'));
  store.resetDailyStats();
  logger.info('Daily summary sent');
}

export function stopDailySummary() {
  if (timer) clearInterval(timer);
}
