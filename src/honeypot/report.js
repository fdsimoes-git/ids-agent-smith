import honeypotStats from './stats.js';

export function generateAsciiReport() {
  const summary = honeypotStats.getSummary();
  const lines = [];

  lines.push('=== HONEYPOT REPORT ===');
  lines.push(`Total connections: ${summary.totalConnections}`);
  lines.push(`Last 24h: ${summary.connectionsLast24h}`);
  lines.push(`Unique IPs: ${summary.uniqueIps}`);
  lines.push('');

  // Top attacker IPs
  if (summary.topIps.length > 0) {
    lines.push('TOP ATTACKER IPs:');
    const maxCount = summary.topIps[0]?.count || 1;
    for (const { ip, count, geo } of summary.topIps) {
      const barLen = Math.max(1, Math.round((count / maxCount) * 20));
      const bar = '#'.repeat(barLen);
      const cc = geo?.countryCode;
      const country = (cc && /^[A-Z]{2}$/.test(cc)) ? ` [${cc}]` : '';
      lines.push(`  ${ip.padEnd(18)} ${bar} ${count}${country}`);
    }
    lines.push('');
  }

  // Top countries
  if (summary.topCountries?.length > 0) {
    lines.push('TOP COUNTRIES:');
    const maxCount = summary.topCountries[0]?.count || 1;
    for (const { country, countryCode, count } of summary.topCountries) {
      const barLen = Math.max(1, Math.round((count / maxCount) * 20));
      const bar = '#'.repeat(barLen);
      lines.push(`  ${countryCode} ${(country || '').padEnd(20)} ${bar} ${count}`);
    }
    lines.push('');
  }

  // Most probed ports
  if (summary.topPorts.length > 0) {
    lines.push('MOST PROBED PORTS:');
    const maxCount = summary.topPorts[0]?.count || 1;
    for (const { port, count } of summary.topPorts) {
      const barLen = Math.max(1, Math.round((count / maxCount) * 20));
      const bar = '#'.repeat(barLen);
      lines.push(`  :${String(port).padEnd(7)} ${bar} ${count}`);
    }
    lines.push('');
  }

  // Hourly distribution (last 24h)
  if (summary.hourlyLast24h.length > 0) {
    lines.push('CONNECTIONS BY HOUR (last 24h):');
    const maxH = Math.max(...summary.hourlyLast24h.map(h => h.count), 1);
    for (const { hour, count } of summary.hourlyLast24h) {
      const barLen = Math.max(1, Math.round((count / maxH) * 30));
      const bar = '#'.repeat(barLen);
      lines.push(`  ${hour} ${bar} ${count}`);
    }
    lines.push('');
  }

  // Recent payloads
  if (summary.recentPayloads.length > 0) {
    lines.push('RECENT PAYLOADS:');
    for (const p of summary.recentPayloads.slice(0, 5)) {
      const preview = p.payload.slice(0, 60).replace(/\n/g, '\\n');
      lines.push(`  ${p.ip}:${p.port} @ ${p.timestamp}`);
      lines.push(`    ${preview}`);
    }
  }

  return lines.join('\n');
}

export function generateTelegramReport() {
  const summary = honeypotStats.getSummary();
  const lines = [];

  lines.push(`<b>Total connections:</b> ${summary.totalConnections}`);
  lines.push(`<b>Last 24h:</b> ${summary.connectionsLast24h}`);
  lines.push(`<b>Unique IPs:</b> ${summary.uniqueIps}`);

  if (summary.topIps.length > 0) {
    lines.push('');
    lines.push('<b>Top Attacker IPs:</b>');
    for (const { ip, count, geo } of summary.topIps.slice(0, 5)) {
      const cc = geo?.countryCode;
      const flag = (cc && /^[A-Z]{2}$/.test(cc)) ? ` ${countryFlag(cc)} ${escapeHtml(cc)}` : '';
      lines.push(`  <code>${escapeHtml(ip)}</code>${flag} — ${count} hits`);
    }
  }

  if (summary.topCountries?.length > 0) {
    lines.push('');
    lines.push('<b>Top Countries:</b>');
    for (const { country, countryCode, count } of summary.topCountries.slice(0, 5)) {
      const safeCode = /^[A-Z]{2}$/.test(countryCode) ? countryCode : '';
      lines.push(`  ${countryFlag(safeCode)} ${escapeHtml(country || safeCode)} — ${count} hits`);
    }
  }

  if (summary.topPorts.length > 0) {
    lines.push('');
    lines.push('<b>Most Probed Ports:</b>');
    for (const { port, count } of summary.topPorts.slice(0, 5)) {
      lines.push(`  :${port} — ${count} hits`);
    }
  }

  return lines.join('\n');
}

export function generateHtmlReport() {
  const summary = honeypotStats.getSummary();

  const topIpRows = summary.topIps
    .map(({ ip, count, geo }) => {
      const country = geo?.countryCode ? ` <small>(${esc(geo.countryCode)})</small>` : '';
      return `<tr><td><code>${esc(ip)}</code>${country}</td><td>${count}</td><td><div class="bar" style="width:${pct(count, summary.topIps[0]?.count)}%"></div></td></tr>`;
    })
    .join('\n');

  const topCountryRows = (summary.topCountries || [])
    .map(({ country, countryCode, count }) => `<tr><td>${esc(countryCode)} ${esc(country)}</td><td>${count}</td><td><div class="bar bar-country" style="width:${pct(count, summary.topCountries?.[0]?.count)}%"></div></td></tr>`)
    .join('\n');

  const topPortRows = summary.topPorts
    .map(({ port, count }) => `<tr><td>:${port}</td><td>${count}</td><td><div class="bar bar-port" style="width:${pct(count, summary.topPorts[0]?.count)}%"></div></td></tr>`)
    .join('\n');

  const maxH = Math.max(...summary.hourlyLast24h.map(h => h.count), 1);
  const hourlyBars = summary.hourlyLast24h
    .map(({ hour, count }) => {
      const height = Math.max(2, Math.round((count / maxH) * 120));
      return `<div class="hbar-col"><div class="hbar" style="height:${height}px"></div><span>${hour}</span><small>${count}</small></div>`;
    })
    .join('\n');

  const payloadRows = summary.recentPayloads
    .map(p => `<tr><td><code>${esc(p.ip)}</code></td><td>:${p.port}</td><td>${esc(p.timestamp)}</td><td><pre>${esc(p.payload.slice(0, 120))}</pre></td></tr>`)
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honeypot Report — IDS Agent</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
  h1 { color: #58a6ff; margin-bottom: .5rem; }
  h2 { color: #8b949e; margin: 2rem 0 .5rem; border-bottom: 1px solid #21262d; padding-bottom: .3rem; }
  .summary { display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 1rem 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; min-width: 150px; }
  .card .num { font-size: 2rem; font-weight: bold; color: #58a6ff; }
  .card .label { color: #8b949e; font-size: .85rem; }
  table { width: 100%; border-collapse: collapse; margin: .5rem 0; }
  th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-size: .8rem; text-transform: uppercase; }
  code { background: #1c2128; padding: .15rem .4rem; border-radius: 4px; font-size: .9rem; }
  pre { background: #1c2128; padding: .3rem .5rem; border-radius: 4px; font-size: .8rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 0; }
  .bar { height: 18px; background: linear-gradient(90deg, #f85149, #da3633); border-radius: 3px; min-width: 4px; }
  .bar-port { background: linear-gradient(90deg, #f0883e, #d29922); }
  .bar-country { background: linear-gradient(90deg, #3fb950, #238636); }
  .hbar-wrap { display: flex; gap: 6px; align-items: flex-end; margin: 1rem 0; padding: .5rem; background: #161b22; border-radius: 8px; overflow-x: auto; }
  .hbar-col { display: flex; flex-direction: column; align-items: center; min-width: 32px; }
  .hbar { width: 24px; background: linear-gradient(0deg, #238636, #2ea043); border-radius: 3px 3px 0 0; }
  .hbar-col span { font-size: .65rem; color: #8b949e; margin-top: 4px; }
  .hbar-col small { font-size: .65rem; color: #58a6ff; }
  .ts { color: #8b949e; font-size: .75rem; margin-top: 2rem; }
</style>
</head>
<body>
<h1>Honeypot Report</h1>
<p class="ts">Generated: ${new Date().toISOString()}</p>

<div class="summary">
  <div class="card"><div class="num">${summary.totalConnections}</div><div class="label">Total Connections</div></div>
  <div class="card"><div class="num">${summary.connectionsLast24h}</div><div class="label">Last 24h</div></div>
  <div class="card"><div class="num">${summary.uniqueIps}</div><div class="label">Unique IPs</div></div>
  <div class="card"><div class="num">${summary.topPorts.length}</div><div class="label">Ports Monitored</div></div>
</div>

<h2>Top Attacker IPs</h2>
<table>
  <tr><th>IP</th><th>Hits</th><th>Distribution</th></tr>
  ${topIpRows || '<tr><td colspan="3">No data yet</td></tr>'}
</table>

<h2>Top Countries</h2>
<table>
  <tr><th>Country</th><th>Hits</th><th>Distribution</th></tr>
  ${topCountryRows || '<tr><td colspan="3">No geo data yet</td></tr>'}
</table>

<h2>Most Probed Ports</h2>
<table>
  <tr><th>Port</th><th>Hits</th><th>Distribution</th></tr>
  ${topPortRows || '<tr><td colspan="3">No data yet</td></tr>'}
</table>

<h2>Connections by Hour (Last 24h)</h2>
<div class="hbar-wrap">
  ${hourlyBars || '<p>No data yet</p>'}
</div>

<h2>Recent Payloads</h2>
<table>
  <tr><th>IP</th><th>Port</th><th>Time</th><th>Payload</th></tr>
  ${payloadRows || '<tr><td colspan="4">No payloads captured yet</td></tr>'}
</table>

</body>
</html>`;
}

function esc(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function countryFlag(code) {
  if (!code || !/^[A-Z]{2}$/.test(code)) return '';
  try {
    return String.fromCodePoint(
      ...code.split('').map(c => 0x1F1E6 + c.charCodeAt(0) - 65)
    );
  } catch {
    return '';
  }
}

function pct(value, max) {
  if (!max) return 0;
  return Math.max(2, Math.round((value / max) * 100));
}
