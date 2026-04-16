import honeypotStats from './stats.js';

// Simplified world country outlines (equirectangular projection, [lon,lat] pairs).
// Covers ~50 countries for a recognizable choropleth. Keyed by ISO 3166-1 alpha-2.
const COUNTRY_SHAPES = {
  US:{n:'United States',p:[[-125,48],[-104,49],[-95,49],[-82,45],[-67,44],[-75,39],[-81,25],[-90,29],[-97,26],[-117,32],[-122,37],[-125,48]]},
  CA:{n:'Canada',p:[[-141,60],[-141,70],[-130,72],[-100,73],[-80,83],[-60,82],[-52,47],[-67,44],[-82,42],[-88,48],[-95,49],[-120,49],[-130,55],[-141,60]]},
  MX:{n:'Mexico',p:[[-117,32],[-97,26],[-97,22],[-92,18],[-87,15],[-92,14],[-105,19],[-108,24],[-115,28],[-117,32]]},
  CU:{n:'Cuba',p:[[-85,22],[-82,23],[-78,22],[-75,20],[-77,20],[-80,22],[-85,22]]},
  CO:{n:'Colombia',p:[[-79,2],[-77,8],[-73,12],[-67,2],[-70,-4],[-78,1],[-79,2]]},
  VE:{n:'Venezuela',p:[[-73,1],[-73,12],[-62,11],[-60,8],[-60,1],[-67,2],[-73,1]]},
  BR:{n:'Brazil',p:[[-70,2],[-60,5],[-50,2],[-44,-3],[-35,-5],[-35,-10],[-38,-16],[-40,-22],[-48,-28],[-54,-34],[-58,-34],[-58,-20],[-68,-11],[-74,-8],[-70,2]]},
  PE:{n:'Peru',p:[[-81,-5],[-75,0],[-69,-1],[-69,-15],[-75,-17],[-81,-5]]},
  AR:{n:'Argentina',p:[[-70,-22],[-65,-28],[-63,-40],[-68,-55],[-72,-52],[-72,-42],[-70,-30],[-70,-22]]},
  CL:{n:'Chile',p:[[-70,-18],[-70,-55],[-73,-55],[-72,-17],[-70,-18]]},
  GB:{n:'United Kingdom',p:[[-6,50],[-3,56],[0,59],[2,53],[0,51],[-6,50]]},
  IE:{n:'Ireland',p:[[-10,51],[-6,51],[-6,55],[-10,55],[-10,51]]},
  FR:{n:'France',p:[[-5,48],[-1,49],[2,51],[8,49],[7,44],[3,43],[-1,43],[-5,48]]},
  ES:{n:'Spain',p:[[-9,36],[-9,44],[3,42],[3,38],[-5,36],[-9,36]]},
  PT:{n:'Portugal',p:[[-9,37],[-7,37],[-7,42],[-9,42],[-9,37]]},
  DE:{n:'Germany',p:[[6,47],[6,54],[9,55],[15,54],[15,51],[13,48],[10,47],[6,47]]},
  IT:{n:'Italy',p:[[7,44],[12,47],[16,46],[18,40],[16,38],[13,38],[9,39],[7,44]]},
  NL:{n:'Netherlands',p:[[3,51],[4,53],[7,54],[7,51],[3,51]]},
  BE:{n:'Belgium',p:[[3,50],[6,51],[6,49],[3,50]]},
  CH:{n:'Switzerland',p:[[6,46],[6,48],[10,48],[10,46],[6,46]]},
  AT:{n:'Austria',p:[[10,47],[10,49],[17,49],[17,47],[10,47]]},
  PL:{n:'Poland',p:[[14,50],[14,54],[19,55],[24,54],[24,50],[14,50]]},
  CZ:{n:'Czechia',p:[[12,49],[15,51],[18,51],[18,49],[12,49]]},
  HU:{n:'Hungary',p:[[16,46],[17,48],[20,49],[23,47],[19,46],[16,46]]},
  RO:{n:'Romania',p:[[22,44],[22,48],[28,48],[30,46],[29,44],[22,44]]},
  BG:{n:'Bulgaria',p:[[22,42],[22,44],[28,44],[29,42],[22,42]]},
  GR:{n:'Greece',p:[[20,35],[20,40],[23,42],[26,41],[28,36],[24,35],[20,35]]},
  NO:{n:'Norway',p:[[5,58],[5,62],[8,64],[15,69],[25,71],[31,71],[20,69],[15,65],[11,59],[5,58]]},
  SE:{n:'Sweden',p:[[11,56],[11,59],[15,65],[20,69],[24,66],[18,60],[15,56],[11,56]]},
  FI:{n:'Finland',p:[[21,60],[21,66],[24,66],[30,70],[30,62],[27,60],[21,60]]},
  DK:{n:'Denmark',p:[[8,55],[8,58],[13,58],[13,55],[8,55]]},
  UA:{n:'Ukraine',p:[[22,48],[24,52],[33,52],[40,50],[40,46],[38,46],[32,46],[28,45],[22,48]]},
  RU:{n:'Russia',p:[[28,45],[28,55],[28,70],[40,72],[60,70],[80,73],[100,78],[120,73],[135,55],[150,50],[160,60],[170,65],[180,72],[180,42],[135,50],[120,53],[90,52],[70,55],[55,52],[50,45],[40,42],[28,45]]},
  TR:{n:'Turkey',p:[[26,36],[26,42],[33,42],[37,42],[44,40],[44,37],[36,36],[26,36]]},
  IR:{n:'Iran',p:[[44,25],[44,40],[48,38],[54,37],[61,36],[63,35],[61,25],[44,25]]},
  IQ:{n:'Iraq',p:[[39,30],[39,37],[44,37],[48,31],[48,29],[42,30],[39,30]]},
  SA:{n:'Saudi Arabia',p:[[35,16],[36,22],[39,22],[43,27],[50,26],[55,22],[55,17],[42,12],[35,16]]},
  EG:{n:'Egypt',p:[[25,22],[25,31],[35,31],[36,22],[25,22]]},
  DZ:{n:'Algeria',p:[[-2,19],[-2,37],[3,37],[9,37],[9,19],[-2,19]]},
  MA:{n:'Morocco',p:[[-13,28],[-13,36],[-2,36],[-2,28],[-13,28]]},
  NG:{n:'Nigeria',p:[[3,4],[3,14],[14,14],[14,4],[3,4]]},
  ET:{n:'Ethiopia',p:[[33,4],[33,15],[42,12],[48,8],[42,3],[33,4]]},
  KE:{n:'Kenya',p:[[34,-5],[34,5],[41,4],[42,-2],[34,-5]]},
  ZA:{n:'South Africa',p:[[17,-35],[18,-29],[25,-27],[32,-27],[33,-30],[28,-34],[17,-35]]},
  IN:{n:'India',p:[[68,8],[68,24],[73,34],[78,35],[85,28],[88,22],[80,8],[77,8],[68,8]]},
  PK:{n:'Pakistan',p:[[61,25],[62,37],[67,37],[77,35],[75,30],[71,25],[61,25]]},
  BD:{n:'Bangladesh',p:[[88,21],[88,27],[92,26],[92,21],[88,21]]},
  CN:{n:'China',p:[[74,40],[80,49],[87,49],[97,42],[105,42],[120,40],[122,32],[121,22],[110,18],[108,22],[98,23],[87,28],[79,30],[74,40]]},
  JP:{n:'Japan',p:[[130,31],[131,34],[136,35],[140,36],[140,41],[145,44],[145,40],[141,38],[140,35],[135,33],[130,31]]},
  KR:{n:'South Korea',p:[[126,34],[126,38],[129,38],[129,35],[126,34]]},
  KP:{n:'North Korea',p:[[125,38],[125,42],[128,43],[130,42],[129,38],[125,38]]},
  TW:{n:'Taiwan',p:[[120,22],[120,25],[122,25],[122,22],[120,22]]},
  VN:{n:'Vietnam',p:[[103,8],[103,16],[106,21],[109,23],[109,18],[107,12],[103,8]]},
  TH:{n:'Thailand',p:[[98,6],[99,15],[101,18],[105,16],[101,12],[100,7],[98,6]]},
  ID:{n:'Indonesia',p:[[95,-6],[95,2],[105,2],[115,0],[119,-5],[115,-8],[105,-7],[95,-6]]},
  PH:{n:'Philippines',p:[[117,6],[117,10],[119,12],[121,18],[125,14],[122,8],[117,6]]},
  MY:{n:'Malaysia',p:[[100,1],[101,5],[104,7],[104,2],[100,1]]},
  AU:{n:'Australia',p:[[114,-35],[115,-22],[119,-15],[129,-12],[137,-12],[145,-15],[150,-23],[153,-28],[151,-34],[141,-38],[131,-35],[114,-35]]},
  NZ:{n:'New Zealand',p:[[166,-47],[170,-44],[174,-41],[178,-37],[178,-42],[170,-47],[166,-47]]},
};

function normalizeCountryCode(code) {
  if (typeof code !== 'string') return null;
  const normalized = code.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(normalized) ? normalized : null;
}

function generateWorldMapSvg(countryCounts) {
  const attacks = Object.create(null);
  for (const { countryCode, count } of countryCounts) {
    const normalized = normalizeCountryCode(countryCode);
    if (!normalized || !COUNTRY_SHAPES[normalized]) continue;
    attacks[normalized] = count;
  }
  const maxCount = Math.max(...Object.values(attacks), 0);

  function toX(lon) { return ((lon + 180) * 1000 / 360).toFixed(1); }
  function toY(lat) { return ((90 - lat) * 500 / 180).toFixed(1); }

  function polyToPath(coords) {
    return coords.map(([lon, lat], i) =>
      `${i === 0 ? 'M' : 'L'}${toX(lon)},${toY(lat)}`
    ).join(' ') + ' Z';
  }

  function getColor(count) {
    if (!count || maxCount === 0) return '#1b2631';
    const t = Math.min(1, Math.log(1 + count) / Math.log(1 + maxCount));
    const stops = [
      [0, 255, 255, 178],
      [0.25, 254, 204, 92],
      [0.5, 253, 141, 60],
      [0.75, 240, 59, 32],
      [1, 189, 0, 38],
    ];
    let lo = stops[0], hi = stops[stops.length - 1];
    for (let i = 0; i < stops.length - 1; i++) {
      if (t >= stops[i][0] && t <= stops[i + 1][0]) { lo = stops[i]; hi = stops[i + 1]; break; }
    }
    const f = (t - lo[0]) / ((hi[0] - lo[0]) || 1);
    const r = Math.round(lo[1] + (hi[1] - lo[1]) * f);
    const g = Math.round(lo[2] + (hi[2] - lo[2]) * f);
    const b = Math.round(lo[3] + (hi[3] - lo[3]) * f);
    return `rgb(${r},${g},${b})`;
  }

  let paths = '';
  for (const [code, data] of Object.entries(COUNTRY_SHAPES)) {
    const count = attacks[code] || 0;
    const color = getColor(count);
    const tooltip = count
      ? `${data.n} (${code}): ${count} connection${count !== 1 ? 's' : ''}`
      : data.n;
    const d = polyToPath(data.p);
    paths += `    <path d="${d}" fill="${color}" stroke="#0d1117" stroke-width="0.5"><title>${esc(tooltip)}</title></path>\n`;
  }

  // Color legend — hide when there is no data to map
  let legend = '';
  if (maxCount > 0) {
    const legendColors = ['#ffffb2', '#fecc5c', '#fd8d3c', '#f03b20', '#bd0026'];
    legend = '    <g transform="translate(20,440)">\n';
    legend += '      <text x="0" y="-5" fill="#8b949e" font-size="11" font-family="sans-serif">Connections</text>\n';
    for (let i = 0; i < 5; i++) {
      legend += `      <rect x="${i * 28}" y="0" width="28" height="10" fill="${legendColors[i]}" rx="1" />\n`;
    }
    legend += '      <text x="0" y="20" fill="#8b949e" font-size="9" font-family="sans-serif">Low</text>\n';
    legend += '      <text x="105" y="20" fill="#8b949e" font-size="9" font-family="sans-serif">High</text>\n';
    legend += '    </g>\n';
  }

  return `<svg viewBox="0 0 1000 500" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:960px;height:auto;background:#0a1628;border-radius:8px;display:block;margin:0 auto;">\n${paths}${legend}  </svg>`;
}

/**
 * Mask a password for display: show first 2 chars followed by asterisks.
 */
function maskPassword(password) {
  if (!password || password === '—') return password || '?';
  if (password.length <= 2) return password[0] + '*'.repeat(password.length - 1);
  return password.slice(0, 2) + '*'.repeat(Math.min(password.length - 2, 6));
}

export function generateAsciiReport() {
  const summary = honeypotStats.getSummary();
  const lines = [];

  lines.push('=== HONEYPOT REPORT ===');
  lines.push(`Total connections: ${summary.totalConnections}`);
  lines.push(`Last 24h: ${summary.connectionsLast24h}`);
  lines.push(`Unique IPs (24h): ${summary.uniqueIps}`);
  lines.push('');

  // Top attacker IPs
  if (summary.topIps.length > 0) {
    lines.push('TOP ATTACKER IPs (24h):');
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
    lines.push('MOST PROBED PORTS (24h):');
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

  // SSH stats
  if (summary.ssh.totalSshConnections > 0) {
    lines.push(`SSH CONNECTIONS: ${summary.ssh.totalSshConnections}`);
    if (summary.ssh.topClientVersions.length > 0) {
      lines.push('  Client versions:');
      for (const { version, count } of summary.ssh.topClientVersions.slice(0, 5)) {
        lines.push(`    ${version} (${count})`);
      }
    }
    if (summary.ssh.recentCredentials.length > 0) {
      lines.push('  Recent credential attempts:');
      for (const c of summary.ssh.recentCredentials.slice(0, 5)) {
        lines.push(`    ${c.ip} — ${c.username || '?'}:${maskPassword(c.password)}`);
      }
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
  lines.push(`<b>Unique IPs (24h):</b> ${summary.uniqueIps}`);

  if (summary.topIps.length > 0) {
    lines.push('');
    lines.push('<b>Top Attacker IPs (24h):</b>');
    for (const { ip, count, geo } of summary.topIps.slice(0, 5)) {
      const cc = geo?.countryCode;
      const flag = (cc && /^[A-Z]{2}$/.test(cc)) ? ` ${countryFlag(cc)} ${escapeHtml(cc)}` : '';
      lines.push(`  <code>${escapeHtml(ip)}</code>${flag} — ${count} hits`);
    }
  }

  if (summary.topCountries?.length > 0) {
    lines.push('');
    lines.push('<b>Top Countries (24h):</b>');
    for (const { country, countryCode, count } of summary.topCountries.slice(0, 5)) {
      const safeCode = /^[A-Z]{2}$/.test(countryCode) ? countryCode : '';
      lines.push(`  ${countryFlag(safeCode)} ${escapeHtml(country || safeCode)} — ${count} hits`);
    }
  }

  if (summary.topPorts.length > 0) {
    lines.push('');
    lines.push('<b>Most Probed Ports (24h):</b>');
    for (const { port, count } of summary.topPorts.slice(0, 5)) {
      lines.push(`  :${port} — ${count} hits`);
    }
  }

  if (summary.ssh.totalSshConnections > 0) {
    lines.push('');
    lines.push(`<b>SSH Honeypot:</b> ${summary.ssh.totalSshConnections} connections`);
    if (summary.ssh.topClientVersions.length > 0) {
      for (const { version, count } of summary.ssh.topClientVersions.slice(0, 3)) {
        lines.push(`  <code>${escapeHtml(version)}</code> — ${count}`);
      }
    }
    if (summary.ssh.recentCredentials.length > 0) {
      lines.push(`  Credential attempts: ${summary.ssh.recentCredentials.length}`);
    }
  }

  return lines.join('\n');
}

export function generateHtmlReport() {
  const summary = honeypotStats.getSummary();
  const hasTopCountryData = summary.topCountries && summary.topCountries.length > 0;
  const hasAnyGeoData = (summary.countryCounts || []).some(({ count }) => count > 0);
  const hasRenderableGeoData = (summary.countryCounts || []).some(
    ({ countryCode, count }) => count > 0 && countryCode && COUNTRY_SHAPES[countryCode]
  );

  const worldMapSvg = generateWorldMapSvg(summary.countryCounts || []);
  const geoNote = hasRenderableGeoData
    ? ''
    : hasAnyGeoData
      ? '<p class="geo-note">Geographic data was collected but the detected countries have no matching shapes in the simplified map.</p>'
      : '<p class="geo-note">No geographic data available. Enable geo-IP lookup (issue #18) to populate this map.</p>';

  const topCountryRows = hasTopCountryData
    ? summary.topCountries
        .map(({ country, countryCode, count }) => {
          const displayName = (country && country !== countryCode) ? country : (COUNTRY_SHAPES[countryCode]?.n || country);
          return `<tr><td><code>${esc(countryCode)}</code></td><td>${esc(displayName)}</td><td>${count}</td><td><div class="bar bar-geo" style="width:${pct(count, summary.topCountries[0]?.count)}%"></div></td></tr>`;
        })
        .join('\n')
    : '';

  const topIpRows = summary.topIps
    .map(({ ip, count, geo }) => {
      const country = geo?.countryCode ? ` <small>(${esc(geo.countryCode)})</small>` : '';
      return `<tr><td><code>${esc(ip)}</code>${country}</td><td>${count}</td><td><div class="bar" style="width:${pct(count, summary.topIps[0]?.count)}%"></div></td></tr>`;
    })
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

  const sshClientRows = summary.ssh.topClientVersions
    .map(({ version, count }) => `<tr><td><code>${esc(version)}</code></td><td>${count}</td></tr>`)
    .join('\n');

  const sshCredRows = summary.ssh.recentCredentials
    .map(c => `<tr><td><code>${esc(c.ip)}</code></td><td>${esc(c.timestamp)}</td><td><code>${esc(c.username || '—')}</code></td><td><code>${esc(maskPassword(c.password))}</code></td></tr>`)
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
  .bar-geo { background: linear-gradient(90deg, #fd8d3c, #bd0026); }
  .hbar-wrap { display: flex; gap: 6px; align-items: flex-end; margin: 1rem 0; padding: .5rem; background: #161b22; border-radius: 8px; overflow-x: auto; }
  .hbar-col { display: flex; flex-direction: column; align-items: center; min-width: 32px; }
  .hbar { width: 24px; background: linear-gradient(0deg, #238636, #2ea043); border-radius: 3px 3px 0 0; }
  .hbar-col span { font-size: .65rem; color: #8b949e; margin-top: 4px; }
  .hbar-col small { font-size: .65rem; color: #58a6ff; }
  .ts { color: #8b949e; font-size: .75rem; margin-top: 2rem; }
  .world-map { margin: 1.5rem 0; }
  .world-map svg path:hover { opacity: 0.8; stroke: #58a6ff; stroke-width: 1.5; cursor: default; }
  .geo-note { color: #8b949e; font-style: italic; margin: 1rem 0; padding: .75rem 1rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; }
</style>
</head>
<body>
<h1>Honeypot Report</h1>
<p class="ts">Generated: ${new Date().toISOString()}</p>

<div class="summary">
  <div class="card"><div class="num">${summary.totalConnections}</div><div class="label">Total Connections</div></div>
  <div class="card"><div class="num">${summary.connectionsLast24h}</div><div class="label">Last 24h</div></div>
  <div class="card"><div class="num">${summary.uniqueIps}</div><div class="label">Unique IPs (24h)</div></div>
  <div class="card"><div class="num">${summary.topPorts.length}</div><div class="label">Unique ports probed (24h)</div></div>
  <div class="card"><div class="num">${summary.uniqueCountries ?? 0}</div><div class="label">Countries (24h)</div></div>
</div>

<h2>Global Attack Origins (24h)</h2>
${geoNote}
<div class="world-map">
${worldMapSvg}
</div>
${hasTopCountryData ? `
<h2>Top Attacker Countries (24h)</h2>
<table>
  <tr><th>Code</th><th>Country</th><th>Hits</th><th>Distribution</th></tr>
  ${topCountryRows}
</table>
` : ''}

<h2>Top Attacker IPs (24h)</h2>
<table>
  <tr><th>IP</th><th>Hits</th><th>Distribution</th></tr>
  ${topIpRows || '<tr><td colspan="3">No data yet</td></tr>'}
</table>

<h2>Most Probed Ports (24h)</h2>
<table>
  <tr><th>Port</th><th>Hits</th><th>Distribution</th></tr>
  ${topPortRows || '<tr><td colspan="3">No data yet</td></tr>'}
</table>

<h2>Connections by Hour (Last 24h)</h2>
<div class="hbar-wrap">
  ${hourlyBars || '<p>No data yet</p>'}
</div>

<h2>SSH Honeypot</h2>
<div class="summary">
  <div class="card"><div class="num">${summary.ssh.totalSshConnections}</div><div class="label">SSH Connections</div></div>
  <div class="card"><div class="num">${summary.ssh.topClientVersions.length}</div><div class="label">Unique Clients</div></div>
  <div class="card"><div class="num">${summary.ssh.recentCredentials.length}</div><div class="label">Credential Attempts</div></div>
</div>

<h2>SSH Client Versions</h2>
<table>
  <tr><th>Client Version</th><th>Count</th></tr>
  ${sshClientRows || '<tr><td colspan="2">No SSH connections yet</td></tr>'}
</table>

<h2>SSH Credential Attempts</h2>
<table>
  <tr><th>IP</th><th>Time</th><th>Username</th><th>Password</th></tr>
  ${sshCredRows || '<tr><td colspan="4">No credentials captured yet</td></tr>'}
</table>

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
