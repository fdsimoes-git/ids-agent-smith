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
        lines.push(`    ${c.ip} — ${c.username || '?'}:${c.password}`);
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
      lines.push(`  Credential attempts: ${summary.ssh.totalCredentialAttempts}`);
    }
  }

  return lines.join('\n');
}

function generateTimelineSvg(hourly) {
  const width = 900;
  const height = 240;
  const padL = 40, padR = 16, padT = 16, padB = 34;
  const innerW = width - padL - padR;
  const innerH = height - padT - padB;

  if (!hourly || hourly.length === 0) {
    return `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" class="chart" role="img" aria-label="Timeline"><text x="${width / 2}" y="${height / 2}" fill="#8b949e" font-size="13" text-anchor="middle" font-family="sans-serif">No data in the last 24h</text></svg>`;
  }

  const maxCount = Math.max(...hourly.map(h => h.count), 1);
  const n = hourly.length;
  const stepX = n > 1 ? innerW / (n - 1) : 0;

  const points = hourly.map(({ count }, i) => {
    const x = padL + (n > 1 ? i * stepX : innerW / 2);
    const y = padT + innerH - (count / maxCount) * innerH;
    return [x, y];
  });

  const linePath = points.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L${points[points.length - 1][0].toFixed(1)},${(padT + innerH).toFixed(1)} L${points[0][0].toFixed(1)},${(padT + innerH).toFixed(1)} Z`;

  const gridY = [0, 0.25, 0.5, 0.75, 1];
  const gridLines = gridY.map(t => {
    const y = padT + innerH * (1 - t);
    const val = Math.round(maxCount * t);
    return `<line x1="${padL}" y1="${y}" x2="${width - padR}" y2="${y}" stroke="#21262d" stroke-width="1"/><text x="${padL - 8}" y="${y + 4}" fill="#6e7681" font-size="10" text-anchor="end" font-family="sans-serif">${val}</text>`;
  }).join('');

  const xLabels = hourly.map(({ hour }, i) => {
    if (n > 12 && i % Math.ceil(n / 12) !== 0 && i !== n - 1) return '';
    const x = padL + (n > 1 ? i * stepX : innerW / 2);
    return `<text x="${x.toFixed(1)}" y="${height - padB + 18}" fill="#8b949e" font-size="10" text-anchor="middle" font-family="sans-serif">${esc(hour)}</text>`;
  }).join('');

  const dots = points.map(([x, y], i) =>
    `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" fill="#58a6ff"><title>${esc(hourly[i].hour)} — ${hourly[i].count} hits</title></circle>`
  ).join('');

  return `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" class="chart" role="img" aria-label="Hits over time">
    <defs>
      <linearGradient id="timelineFill" x1="0" x2="0" y1="0" y2="1">
        <stop offset="0%" stop-color="#58a6ff" stop-opacity="0.35"/>
        <stop offset="100%" stop-color="#58a6ff" stop-opacity="0"/>
      </linearGradient>
    </defs>
    ${gridLines}
    <path d="${areaPath}" fill="url(#timelineFill)"/>
    <path d="${linePath}" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    ${dots}
    ${xLabels}
  </svg>`;
}

function generateVectorDonutSvg(vectorBreakdown) {
  const width = 320, height = 260;
  const cx = 130, cy = 130, r = 90, rInner = 58;

  const entries = [
    { key: 'ssh', label: 'SSH', color: '#f85149' },
    { key: 'http', label: 'HTTP', color: '#3fb950' },
    { key: 'tcp', label: 'TCP', color: '#d29922' },
  ].map(e => ({ ...e, count: vectorBreakdown?.[e.key] || 0 }));

  const total = entries.reduce((s, e) => s + e.count, 0);

  if (total === 0) {
    return `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" class="chart" role="img" aria-label="Attack vectors">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#21262d" stroke-width="${r - rInner}"/>
      <text x="${cx}" y="${cy + 4}" fill="#8b949e" font-size="13" text-anchor="middle" font-family="sans-serif">No hits yet</text>
    </svg>`;
  }

  function arcPath(startAngle, endAngle) {
    // If a single slice makes up 100% of the donut, two identical endpoints
    // collapse the arc to zero width; draw two half-arcs instead so the full
    // ring renders.
    if (endAngle - startAngle >= Math.PI * 2 - 1e-6) {
      const mid = startAngle + Math.PI;
      return arcPath(startAngle, mid) + ' ' + arcPath(mid, startAngle + Math.PI * 2);
    }
    const x1 = cx + r * Math.cos(startAngle);
    const y1 = cy + r * Math.sin(startAngle);
    const x2 = cx + r * Math.cos(endAngle);
    const y2 = cy + r * Math.sin(endAngle);
    const x3 = cx + rInner * Math.cos(endAngle);
    const y3 = cy + rInner * Math.sin(endAngle);
    const x4 = cx + rInner * Math.cos(startAngle);
    const y4 = cy + rInner * Math.sin(startAngle);
    const large = endAngle - startAngle > Math.PI ? 1 : 0;
    return `M${x1.toFixed(2)},${y1.toFixed(2)} A${r},${r} 0 ${large} 1 ${x2.toFixed(2)},${y2.toFixed(2)} L${x3.toFixed(2)},${y3.toFixed(2)} A${rInner},${rInner} 0 ${large} 0 ${x4.toFixed(2)},${y4.toFixed(2)} Z`;
  }

  let angle = -Math.PI / 2;
  const slices = [];
  const legend = [];
  for (const e of entries) {
    if (e.count === 0) {
      legend.push(`<div class="legend-row"><span class="legend-dot" style="background:${e.color}"></span>${e.label}<span class="legend-val">0</span></div>`);
      continue;
    }
    const sweep = (e.count / total) * Math.PI * 2;
    const path = arcPath(angle, angle + sweep);
    const pctLabel = ((e.count / total) * 100).toFixed(total >= 100 ? 0 : 1);
    slices.push(`<path d="${path}" fill="${e.color}" stroke="#0d1117" stroke-width="1.5"><title>${e.label}: ${e.count} (${pctLabel}%)</title></path>`);
    legend.push(`<div class="legend-row"><span class="legend-dot" style="background:${e.color}"></span>${e.label}<span class="legend-val">${e.count} (${pctLabel}%)</span></div>`);
    angle += sweep;
  }

  return `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" class="chart donut" role="img" aria-label="Attack vector breakdown">
    ${slices.join('')}
    <text x="${cx}" y="${cy - 4}" fill="#c9d1d9" font-size="22" font-weight="700" text-anchor="middle" font-family="sans-serif">${total}</text>
    <text x="${cx}" y="${cy + 16}" fill="#8b949e" font-size="11" text-anchor="middle" font-family="sans-serif">total hits</text>
  </svg>
  <div class="legend">${legend.join('')}</div>`;
}

// TODO(issue #27): remaining items from the original issue scope:
//   - Filterable credential attempts table (text filter + type filter).
//     Currently only sortable; no filter UI is rendered.
//   - Print-friendly stylesheet (@media print) — no dedicated print CSS yet.
//   - Replace hand-rolled SVG charts with embedded Plotly.js, which the issue
//     calls out as the preferred renderer (must remain self-contained, no CDN).
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
      ? '<p class="note">Geographic data was collected but the detected countries have no matching shapes in the simplified map.</p>'
      : '<p class="note">No geographic data available. Enable geo-IP lookup (issue #18) to populate this map.</p>';

  const topCountryRows = hasTopCountryData
    ? summary.topCountries
        .map(({ country, countryCode, count }) => {
          const displayName = (country && country !== countryCode) ? country : (COUNTRY_SHAPES[countryCode]?.n || country);
          const flag = countryFlag(countryCode);
          const barPct = pct(count, summary.topCountries[0]?.count);
          return `<tr>
    <td class="flag">${flag}</td>
    <td><code>${esc(countryCode)}</code> ${esc(displayName || '')}</td>
    <td class="num">${count}</td>
    <td class="bar-cell"><div class="bar bar-geo" style="width:${barPct}%"></div></td>
  </tr>`;
        })
        .join('\n')
    : '';

  const topIpRows = summary.topIps
    .map((entry, idx) => {
      const { ip, count, geo, ports, payloads } = entry;
      const flag = geo?.countryCode ? countryFlag(geo.countryCode) : '';
      const cc = geo?.countryCode ? `<span class="cc">${esc(geo.countryCode)}</span>` : '';
      const countryName = geo?.country ? esc(geo.country) : '';
      const barPct = pct(count, summary.topIps[0]?.count);
      const city = geo?.city ? ` · ${esc(geo.city)}` : '';
      const portsList = (ports || []).slice(0, 12).map(p => `<span class="port-chip">:${p.port}<span class="port-count">${p.count}</span></span>`).join(' ') || '<em>no port data</em>';
      const payloadPreview = (payloads || []).length
        ? payloads.map(p => `<pre>${esc(p.slice(0, 200))}</pre>`).join('')
        : '<em>no payload captured</em>';
      const detailId = `ip-detail-${idx}`;
      return `<tr class="ip-row">
    <td><button class="toggle" data-target="${detailId}" aria-controls="${detailId}" aria-expanded="false" aria-label="Toggle details for ${esc(ip)}">+</button></td>
    <td class="flag">${flag}</td>
    <td><code>${esc(ip)}</code> ${cc}<div class="ip-meta">${countryName}${city}</div></td>
    <td class="num">${count}</td>
    <td class="bar-cell"><div class="bar" style="width:${barPct}%"></div></td>
  </tr>
  <tr id="ip-detail-${idx}" class="detail-row" hidden>
    <td colspan="5">
      <div class="detail-grid">
        <div><strong>Ports hit:</strong><div class="ports">${portsList}</div></div>
        <div><strong>Recent payloads:</strong><div class="payloads">${payloadPreview}</div></div>
      </div>
    </td>
  </tr>`;
    })
    .join('\n');

  const topPortRows = summary.topPorts
    .map(({ port, count }) => `<tr><td>:${port}</td><td class="num">${count}</td><td class="bar-cell"><div class="bar bar-port" style="width:${pct(count, summary.topPorts[0]?.count)}%"></div></td></tr>`)
    .join('\n');

  const payloadRows = summary.recentPayloads
    .map(p => `<tr><td><code>${esc(p.ip)}</code></td><td>:${p.port}</td><td class="ts-cell">${esc(p.timestamp)}</td><td><pre>${esc(p.payload.slice(0, 160))}</pre></td></tr>`)
    .join('\n');

  const sshClientRows = summary.ssh.topClientVersions
    .map(({ version, count }) => `<tr><td><code>${esc(version)}</code></td><td class="num">${count}</td></tr>`)
    .join('\n');

  const credAttempts = summary.credentialAttempts || [];
  const credRows = credAttempts
    .map(c => {
      const badgeClass = c.type === 'SSH' ? 'badge-ssh' : 'badge-http';
      return `<tr>
    <td><span class="badge ${badgeClass}">${esc(c.type)}</span></td>
    <td><code>${esc(c.ip)}</code></td>
    <td class="ts-cell">${esc(c.timestamp)}</td>
    <td><code>${esc(c.username || '—')}</code></td>
    <td><code>${esc(c.password || '—')}</code></td>
  </tr>`;
    })
    .join('\n');

  const timelineSvg = generateTimelineSvg(summary.hourlyLast24h || []);
  const vectorDonut = generateVectorDonutSvg(summary.vectorBreakdown || { ssh: 0, http: 0, tcp: 0 });

  const activePorts24h = summary.topPorts.length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honeypot Report — IDS Agent</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  :root {
    --bg: #0d1117;
    --bg-elev: #161b22;
    --bg-elev-2: #1c2128;
    --border: #30363d;
    --border-soft: #21262d;
    --text: #c9d1d9;
    --text-dim: #8b949e;
    --text-dimmer: #6e7681;
    --accent: #58a6ff;
    --danger: #f85149;
    --warn: #d29922;
    --ok: #3fb950;
    --shadow: 0 1px 3px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.15);
  }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: radial-gradient(1200px 600px at 0% 0%, #121b2e 0%, var(--bg) 40%) var(--bg);
    color: var(--text);
    line-height: 1.45;
    min-height: 100vh;
  }
  .app { max-width: 1200px; margin: 0 auto; padding: 1.5rem 1.25rem 3rem; }

  .topbar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-soft); }
  .brand { display: flex; align-items: center; gap: .75rem; }
  .brand-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--danger); box-shadow: 0 0 10px var(--danger); animation: pulse 2s infinite ease-in-out; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }
  @media (prefers-reduced-motion: reduce) {
    .brand-dot { animation: none; }
  }
  h1 { font-size: 1.4rem; margin: 0; color: var(--text); letter-spacing: -.01em; }
  h1 small { display: block; font-size: .75rem; color: var(--text-dim); font-weight: 400; letter-spacing: 0; }
  .meta { color: var(--text-dim); font-size: .8rem; text-align: right; }

  h2 { font-size: 1rem; font-weight: 600; color: var(--text); margin: 2rem 0 .75rem; display: flex; align-items: center; gap: .5rem; letter-spacing: .01em; }
  h2::before { content: ""; width: 3px; height: 1rem; background: var(--accent); border-radius: 2px; }

  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: .75rem; }
  .card { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 10px; padding: .9rem 1rem; box-shadow: var(--shadow); transition: border-color .15s ease; }
  .card:hover { border-color: var(--accent); }
  .card .num { font-size: 1.8rem; font-weight: 700; color: var(--accent); line-height: 1.1; letter-spacing: -.02em; }
  .card.accent-danger .num { color: var(--danger); }
  .card.accent-ok .num { color: var(--ok); }
  .card.accent-warn .num { color: var(--warn); }
  .card .label { color: var(--text-dim); font-size: .7rem; text-transform: uppercase; letter-spacing: .06em; margin-top: .2rem; }
  .card .sub { color: var(--text-dimmer); font-size: .7rem; margin-top: .15rem; }

  .panel-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 1rem; margin-top: 1rem; }
  .panel { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; box-shadow: var(--shadow); }
  .panel h3 { margin: 0 0 .75rem; font-size: .85rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: .06em; font-weight: 600; }
  .chart { width: 100%; height: auto; display: block; }
  .donut { max-width: 260px; margin: 0 auto; }

  .legend { display: flex; flex-direction: column; gap: .3rem; margin-top: .5rem; }
  .legend-row { display: flex; align-items: center; gap: .5rem; font-size: .85rem; color: var(--text); }
  .legend-dot { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
  .legend-val { margin-left: auto; color: var(--text-dim); font-variant-numeric: tabular-nums; }

  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid var(--border-soft); vertical-align: top; }
  th { color: var(--text-dim); font-size: .7rem; text-transform: uppercase; letter-spacing: .06em; font-weight: 600; background: var(--bg-elev-2); }
  th.sortable { cursor: pointer; user-select: none; }
  th.sortable::after { content: " ⇅"; color: var(--text-dimmer); font-size: .75rem; }
  th.sort-asc::after { content: " ↑"; color: var(--accent); }
  th.sort-desc::after { content: " ↓"; color: var(--accent); }
  tbody tr:hover { background: rgba(88, 166, 255, .04); }
  td.num, td.ts-cell { font-variant-numeric: tabular-nums; }
  td.num { text-align: right; color: var(--text); font-weight: 600; }
  td.ts-cell { color: var(--text-dim); font-size: .8rem; white-space: nowrap; }
  td.bar-cell { width: 38%; }
  td.flag { width: 2.2rem; font-size: 1.2rem; text-align: center; }
  .table-wrap { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; box-shadow: var(--shadow); }

  code { background: var(--bg-elev-2); padding: .15rem .4rem; border-radius: 4px; font-size: .85rem; font-family: "SF Mono", "Consolas", "Liberation Mono", Menlo, monospace; color: var(--text); }
  pre { background: var(--bg-elev-2); padding: .5rem .7rem; border-radius: 6px; font-size: .75rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: .25rem 0; color: var(--text); border: 1px solid var(--border-soft); }

  .bar { height: 14px; background: linear-gradient(90deg, #f85149, #da3633); border-radius: 3px; min-width: 4px; }
  .bar-port { background: linear-gradient(90deg, #f0883e, #d29922); }
  .bar-geo { background: linear-gradient(90deg, #fd8d3c, #bd0026); }

  .cc { color: var(--text-dim); font-size: .75rem; margin-left: .3rem; padding: .1rem .35rem; background: var(--bg-elev-2); border-radius: 3px; }
  .ip-meta { font-size: .75rem; color: var(--text-dim); margin-top: .15rem; }
  .toggle { background: var(--bg-elev-2); border: 1px solid var(--border); color: var(--text); width: 22px; height: 22px; padding: 0; border-radius: 4px; cursor: pointer; font-size: .9rem; line-height: 1; font-family: inherit; }
  .toggle:hover { border-color: var(--accent); color: var(--accent); }
  .detail-row td { background: rgba(88, 166, 255, .03); padding: .8rem 1rem; }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .detail-grid strong { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; color: var(--text-dim); font-weight: 600; }
  .ports { display: flex; flex-wrap: wrap; gap: .3rem; margin-top: .4rem; }
  .port-chip { display: inline-flex; align-items: center; gap: .3rem; background: var(--bg-elev-2); border: 1px solid var(--border-soft); border-radius: 4px; padding: .1rem .4rem; font-size: .75rem; font-family: "SF Mono", monospace; }
  .port-chip .port-count { color: var(--text-dim); font-size: .7rem; }
  .payloads { margin-top: .4rem; }

  .badge { display: inline-block; padding: .15rem .45rem; border-radius: 3px; font-size: .7rem; font-weight: 600; letter-spacing: .04em; }
  .badge-ssh { background: rgba(248, 81, 73, .15); color: #ff7b72; border: 1px solid rgba(248, 81, 73, .3); }
  .badge-http { background: rgba(63, 185, 80, .15); color: #56d364; border: 1px solid rgba(63, 185, 80, .3); }

  .world-map { margin: 0; }
  .world-map svg { background: #0a1628; border-radius: 8px; display: block; width: 100%; height: auto; }
  .world-map svg path:hover { opacity: 0.8; stroke: var(--accent); stroke-width: 1.5; cursor: default; }

  .note { color: var(--text-dim); font-style: italic; font-size: .85rem; margin: .5rem 0 1rem; padding: .6rem .8rem; background: var(--bg-elev); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 6px; }
  .empty-row td { color: var(--text-dim); text-align: center; padding: 1.5rem; font-style: italic; }

  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border-soft); color: var(--text-dimmer); font-size: .75rem; text-align: center; }

  @media (max-width: 780px) {
    .app { padding: 1rem .75rem 2rem; }
    h1 { font-size: 1.15rem; }
    .panel-grid { grid-template-columns: 1fr; }
    .detail-grid { grid-template-columns: 1fr; }
    td.bar-cell { display: none; }
    th, td { padding: .45rem .5rem; }
    .meta { text-align: left; width: 100%; }
  }
</style>
</head>
<body>
<div class="app">

<header class="topbar">
  <div class="brand">
    <span class="brand-dot"></span>
    <h1>Honeypot Report<small>IDS Agent Smith — live attack telemetry</small></h1>
  </div>
  <div class="meta">
    <div>Generated: <span>${new Date().toISOString()}</span></div>
    <div id="refresh-status">Auto-refresh: off · append <code>?refresh=60</code> to enable</div>
  </div>
</header>

<section>
  <div class="summary-grid">
    <div class="card accent-danger"><div class="num">${summary.totalConnections}</div><div class="label">Total Hits</div><div class="sub">All time</div></div>
    <div class="card"><div class="num">${summary.connectionsLast24h}</div><div class="label">Last 24h</div><div class="sub">Rolling window</div></div>
    <div class="card"><div class="num">${summary.uniqueIps}</div><div class="label">Unique IPs</div><div class="sub">24h</div></div>
    <div class="card accent-warn"><div class="num">${summary.uniqueCountries ?? 0}</div><div class="label">Countries</div><div class="sub">24h</div></div>
    <div class="card accent-ok"><div class="num">${activePorts24h}</div><div class="label">Active Ports</div><div class="sub">24h</div></div>
  </div>
</section>

<section>
  <div class="panel-grid">
    <div class="panel">
      <h3>Attack Timeline — Last 24h (hourly, UTC)</h3>
      ${timelineSvg}
    </div>
    <div class="panel">
      <h3>Attack Vectors</h3>
      ${vectorDonut}
    </div>
  </div>
</section>

<section>
  <h2>Global Attack Origins (24h)</h2>
  ${geoNote}
  <div class="world-map">
  ${worldMapSvg}
  </div>
</section>

${hasTopCountryData ? `
<section>
  <h2>Top Attacker Countries (24h)</h2>
  <div class="table-wrap">
  <table>
    <thead><tr><th></th><th>Country</th><th class="num">Hits</th><th>Share</th></tr></thead>
    <tbody>
    ${topCountryRows}
    </tbody>
  </table>
  </div>
</section>
` : ''}

<section>
  <h2>Top Attacker IPs (24h)</h2>
  <div class="table-wrap">
  <table>
    <thead><tr><th></th><th></th><th>IP</th><th class="num">Hits</th><th>Share</th></tr></thead>
    <tbody>
    ${topIpRows || '<tr class="empty-row"><td colspan="5">No data yet</td></tr>'}
    </tbody>
  </table>
  </div>
</section>

<section>
  <h2>Most Probed Ports (24h)</h2>
  <div class="table-wrap">
  <table>
    <thead><tr><th class="sortable">Port</th><th class="sortable num">Hits</th><th>Share</th></tr></thead>
    <tbody>
    ${topPortRows || '<tr class="empty-row"><td colspan="3">No data yet</td></tr>'}
    </tbody>
  </table>
  </div>
</section>

<section>
  <h2>Credential Attempts</h2>
  <div class="table-wrap">
  <!-- TODO(issue #27): add filter UI (type dropdown + free-text search) above this table. -->
  <table class="sortable-table">
    <thead><tr><th class="sortable">Type</th><th class="sortable">IP</th><th class="sortable">Time</th><th class="sortable">Username</th><th>Password</th></tr></thead>
    <tbody>
    ${credRows || '<tr class="empty-row"><td colspan="5">No credentials captured yet</td></tr>'}
    </tbody>
  </table>
  </div>
</section>

<section>
  <h2>SSH Honeypot</h2>
  <div class="summary-grid">
    <div class="card"><div class="num">${summary.ssh.totalSshConnections}</div><div class="label">SSH Connections</div></div>
    <div class="card"><div class="num">${summary.ssh.uniqueClientVersions}</div><div class="label">Unique Clients</div></div>
    <div class="card accent-danger"><div class="num">${summary.ssh.totalCredentialAttempts}</div><div class="label">SSH Creds Tried</div></div>
  </div>
</section>

<section>
  <h2>SSH Client Versions</h2>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Client Version</th><th class="num">Count</th></tr></thead>
    <tbody>
    ${sshClientRows || '<tr class="empty-row"><td colspan="2">No SSH connections yet</td></tr>'}
    </tbody>
  </table>
  </div>
</section>

<section>
  <h2>Recent Payloads</h2>
  <div class="table-wrap">
  <table>
    <thead><tr><th>IP</th><th>Port</th><th>Time</th><th>Payload</th></tr></thead>
    <tbody>
    ${payloadRows || '<tr class="empty-row"><td colspan="4">No payloads captured yet</td></tr>'}
    </tbody>
  </table>
  </div>
</section>

<div class="footer">IDS Agent Smith · append <code>?refresh=60</code> to the URL to enable auto-refresh</div>

</div>

<script>
(function() {
  // Opt-in auto-refresh via ?refresh=<seconds>. Default is off so saved/offline
  // reports and printed views keep user state (expanded rows, sort, scroll).
  var params = new URLSearchParams(window.location.search);
  var refresh = parseInt(params.get('refresh') || '', 10);
  if (Number.isFinite(refresh) && refresh > 0) {
    var meta = document.createElement('meta');
    meta.httpEquiv = 'refresh';
    meta.content = String(refresh);
    document.head.appendChild(meta);
    var status = document.getElementById('refresh-status');
    if (status) status.textContent = 'Auto-refresh: ' + refresh + 's';
  }

  // Expandable IP detail rows
  document.querySelectorAll('.toggle').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var targetId = btn.getAttribute('data-target');
      var row = document.getElementById(targetId);
      if (!row) return;
      var open = row.hasAttribute('hidden') === false;
      if (open) {
        row.setAttribute('hidden', '');
        btn.textContent = '+';
        btn.setAttribute('aria-expanded', 'false');
      } else {
        row.removeAttribute('hidden');
        btn.textContent = '−';
        btn.setAttribute('aria-expanded', 'true');
      }
    });
  });

  // Sortable tables
  document.querySelectorAll('table').forEach(function(table) {
    var headers = table.querySelectorAll('th.sortable');
    headers.forEach(function(th, colIdx) {
      th.addEventListener('click', function() {
        var tbody = table.tBodies[0];
        if (!tbody) return;
        var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr')).filter(function(r) {
          return !r.classList.contains('detail-row') && !r.classList.contains('empty-row');
        });
        var asc = !th.classList.contains('sort-asc');
        headers.forEach(function(h) { h.classList.remove('sort-asc', 'sort-desc'); });
        th.classList.add(asc ? 'sort-asc' : 'sort-desc');
        var ipv4Re = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/;
        rows.sort(function(a, b) {
          var av = (a.cells[colIdx] && a.cells[colIdx].innerText || '').trim();
          var bv = (b.cells[colIdx] && b.cells[colIdx].innerText || '').trim();
          // Compare IPv4 addresses octet-by-octet so 10.0.0.2 sorts before 192.168.1.1
          if (ipv4Re.test(av) && ipv4Re.test(bv)) {
            var aOct = av.split('.').map(Number);
            var bOct = bv.split('.').map(Number);
            for (var i = 0; i < 4; i++) {
              if (aOct[i] !== bOct[i]) return asc ? aOct[i] - bOct[i] : bOct[i] - aOct[i];
            }
            return 0;
          }
          var an = parseFloat(av.replace(/[^0-9.\\-]/g, ''));
          var bn = parseFloat(bv.replace(/[^0-9.\\-]/g, ''));
          if (!isNaN(an) && !isNaN(bn) && av.match(/^[:\\d\\s.,\\-]+$/)) {
            return asc ? an - bn : bn - an;
          }
          return asc ? av.localeCompare(bv) : bv.localeCompare(av);
        });
        rows.forEach(function(r) { tbody.appendChild(r); });
      });
    });
  });
})();
</script>
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
