import { readFile, writeFile } from 'node:fs/promises';
import config from '../../config.js';
import logger from './logger.js';

const HEADER = '# Managed by ids-agent — do not edit manually\n';

export async function addToDenyList(ip) {
  const entries = await readDenyList();
  if (entries.has(ip)) return false;

  entries.add(ip);
  await writeDenyList(entries);
  logger.info(`nginx deny list: added ${ip}`);
  return true;
}

export async function removeFromDenyList(ip) {
  const entries = await readDenyList();
  if (!entries.has(ip)) return false;

  entries.delete(ip);
  await writeDenyList(entries);
  logger.info(`nginx deny list: removed ${ip}`);
  return true;
}

export async function rebuildDenyList(bannedIps) {
  const entries = new Set(bannedIps);
  await writeDenyList(entries);
  if (entries.size > 0) {
    logger.info(`nginx deny list: rebuilt with ${entries.size} IPs`);
  }
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
