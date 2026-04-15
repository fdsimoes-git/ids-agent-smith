import { readFile, writeFile } from 'node:fs/promises';
import config from '../../config.js';
import logger from './logger.js';

const HEADER = '# Managed by idps-agent — do not edit manually';

// Simple async mutex to prevent concurrent read-modify-write races
let lock = Promise.resolve();
function withLock(fn) {
  const next = lock.then(fn, fn);
  lock = next.catch(() => {});
  return next;
}

export function addToDenyList(ip) {
  return withLock(async () => {
    const entries = await readDenyList();
    if (entries.has(ip)) return false;

    entries.add(ip);
    await writeDenyList(entries);
    logger.info(`nginx deny list: added ${ip}`);
    return true;
  });
}

export function removeFromDenyList(ip) {
  return withLock(async () => {
    const entries = await readDenyList();
    if (!entries.has(ip)) return false;

    entries.delete(ip);
    await writeDenyList(entries);
    logger.info(`nginx deny list: removed ${ip}`);
    return true;
  });
}

export function rebuildDenyList(bannedIps) {
  return withLock(async () => {
    const entries = new Set(bannedIps);
    await writeDenyList(entries);
    if (entries.size > 0) {
      logger.info(`nginx deny list: rebuilt with ${entries.size} IPs`);
    }
  });
}

async function readDenyList() {
  const entries = new Set();
  try {
    const content = await readFile(config.nginxDenyListPath, 'utf8');
    for (const line of content.split('\n')) {
      const match = line.match(/^deny\s+(\S+);/);
      if (match) entries.add(match[1]);
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      logger.warn(`Failed to read nginx deny list: ${err.message}`);
    }
  }
  return entries;
}

async function writeDenyList(entries) {
  const lines = [HEADER];
  for (const ip of [...entries].sort()) {
    lines.push(`deny ${ip};`);
  }
  lines.push('');
  await writeFile(config.nginxDenyListPath, lines.join('\n'), 'utf8');
}
