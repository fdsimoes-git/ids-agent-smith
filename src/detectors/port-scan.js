import config from '../../config.js';

const { count, windowSec } = config.thresholds.portScan;
const windowMs = windowSec * 1000;

export function checkPortScan(event, store) {
  if (event.source !== 'nginx') return null;
  if (event.status !== 404) return null;

  const key = `scan:${event.ip}`;
  store.push(key, { path: event.path });

  const uniquePaths = store.uniqueValues(key, 'path', windowMs);

  if (uniquePaths.size >= count) {
    return {
      rule: 'port-scan',
      severity: 'HIGH',
      ip: event.ip,
      timestamp: new Date().toISOString(),
      endpoint: `${uniquePaths.size} unique 404 paths`,
      details: `${uniquePaths.size} unique 404 paths probed in ${windowSec}s`,
      suggestedAction: 'Block IP — likely reconnaissance/scanning',
      count: uniquePaths.size,
    };
  }

  return null;
}
