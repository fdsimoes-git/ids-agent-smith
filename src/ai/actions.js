import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import config from '../../config.js';
import logger, { appendToFile } from '../utils/logger.js';
import store from '../store.js';
import { sanitizeIp } from '../utils/sanitize.js';
import { addToDenyList, removeFromDenyList, rebuildDenyList } from '../utils/nginx-deny-list.js';

const exec = promisify(execFile);

export async function executeAction(action, ip, analysis) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    action,
    ip,
    analysis,
    autonomous: config.autonomousMode,
    result: null,
  };

  try {
    switch (action) {
      case 'block':
        logEntry.result = await blockIp(ip);
        break;
      case 'monitor':
        logEntry.result = 'monitoring — no automated action';
        break;
      case 'ignore':
        logEntry.result = 'ignored per AI recommendation';
        break;
      case 'escalate':
        logEntry.result = 'escalated — human review required';
        break;
      default:
        logEntry.result = `unknown action: ${action}`;
    }
  } catch (err) {
    logEntry.result = `error: ${err.message}`;
    logger.error(`Action "${action}" failed for ${ip}`, { error: err.message });
  }

  await appendToFile(config.aiDecisionLogPath, JSON.stringify(logEntry));
  return logEntry;
}

export async function blockIp(ip) {
  logger.info(`Blocking IP: ${ip}`);
  const results = [];

  let f2bBanned = false;
  try {
    await exec('sudo', ['fail2ban-client', 'set', 'sshd', 'banip', ip]);
    results.push('fail2ban: banned');
    logger.info(`fail2ban ban applied: ${ip}`);
    f2bBanned = true;
  } catch (err) {
    results.push(`fail2ban: ${err.message}`);
  }

  const cmd = ip.includes(':') ? 'ip6tables' : 'iptables';
  let iptablesBlocked = false;
  try {
    await exec('sudo', [cmd, '-w', '-C', 'INPUT', '-s', ip, '-j', 'DROP']);
    results.push(`${cmd}: DROP rule already exists`);
    logger.info(`${cmd} DROP rule already exists: ${ip}`);
    iptablesBlocked = true;
  } catch {
    try {
      await exec('sudo', [cmd, '-w', '-I', 'INPUT', '-s', ip, '-j', 'DROP']);
      results.push(`${cmd}: DROP rule added`);
      logger.info(`${cmd} DROP rule added: ${ip}`);
      iptablesBlocked = true;
    } catch (err) {
      results.push(`${cmd}: ${err.message}`);
    }
  }

  // Add to nginx deny list to block HTTP/HTTPS access
  let nginxBlocked = false;
  try {
    const added = await addToDenyList(ip);
    if (added) {
      await reloadNginx();
      results.push('nginx: deny rule added + reloaded');
    } else {
      results.push('nginx: deny rule already exists');
    }
    nginxBlocked = true;
  } catch (err) {
    results.push(`nginx deny list: ${err.message}`);
  }

  const layers = [];
  if (f2bBanned) layers.push('fail2ban');
  if (iptablesBlocked) layers.push(cmd);
  if (nginxBlocked) layers.push('nginx');
  if (layers.length > 0) {
    store.markBanned(ip, layers.join(','));
  }

  return results;
}

export async function unblockIp(ip) {
  logger.info(`Unblocking IP: ${ip}`);
  const results = [];

  // Remove from fail2ban
  try {
    await exec('sudo', ['fail2ban-client', 'set', 'sshd', 'unbanip', ip]);
    results.push('fail2ban: unbanned');
  } catch (err) {
    results.push(`fail2ban: ${err.message}`);
  }

  // Remove iptables/ip6tables DROP rule
  const cmd = ip.includes(':') ? 'ip6tables' : 'iptables';
  try {
    await exec('sudo', [cmd, '-w', '-D', 'INPUT', '-s', ip, '-j', 'DROP']);
    results.push(`${cmd}: DROP rule removed`);
  } catch (err) {
    results.push(`${cmd}: ${err.message}`);
  }

  // Remove from nginx deny list + always reload (emergency escape hatch)
  try {
    const removed = await removeFromDenyList(ip);
    results.push(removed ? 'nginx: deny rule removed' : 'nginx: no deny rule found');
  } catch (err) {
    results.push(`nginx deny list: ${err.message}`);
  }
  try {
    await reloadNginx();
    results.push('nginx: reloaded');
  } catch (err) {
    results.push(`nginx reload: ${err.message}`);
  }

  store.markUnbanned(ip);
  return results;
}

export async function syncBannedIps() {
  let count = 0;

  // Sync from fail2ban
  try {
    const { stdout } = await exec('sudo', ['fail2ban-client', 'status', 'sshd']);
    const match = stdout.match(/Banned IP list:\s+(.+)/);
    if (match) {
      for (const raw of match[1].trim().split(/\s+/)) {
        const ip = sanitizeIp(raw);
        if (ip && !store.wasBanned(ip)) { store.markBanned(ip, 'sshd'); count++; }
      }
    }
  } catch (err) {
    logger.warn(`Failed to sync fail2ban bans: ${err.message}`);
  }

  // Sync from iptables / ip6tables
  for (const cmd of ['iptables', 'ip6tables']) {
    try {
      const { stdout } = await exec('sudo', [cmd, '-w', '-S', 'INPUT']);
      for (const line of stdout.split('\n')) {
        const match = line.match(/^-A INPUT -s (\S+?)(?:\/(\d+))? -j DROP$/);
        if (match) {
          const cidr = match[2];
          const isHostRule = !cidr
            || (cmd === 'iptables' && cidr === '32')
            || (cmd === 'ip6tables' && cidr === '128');
          const ip = isHostRule ? sanitizeIp(match[1]) : null;
          if (ip && !store.wasBanned(ip)) { store.markBanned(ip, cmd); count++; }
        }
      }
    } catch (err) {
      logger.warn(`Failed to sync ${cmd} bans: ${err.message}`);
    }
  }

  if (count > 0) logger.info(`Synced ${count} banned IPs from fail2ban + iptables`);

  // Rebuild nginx deny list from all known banned IPs (always rebuild to clear stale entries)
  const allBanned = store.getBannedIps().map(e => e.ip);
  try {
    await rebuildDenyList(allBanned);
    await reloadNginx();
  } catch (err) {
    logger.warn(`Failed to rebuild nginx deny list: ${err.message}`);
  }

  return count;
}

export async function reloadNginx() {
  try {
    await exec('sudo', ['systemctl', 'reload', 'nginx']);
    logger.info('Nginx reloaded successfully');
  } catch (err) {
    logger.error('Nginx reload failed', { error: err.message });
    throw err;
  }
}
