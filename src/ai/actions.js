import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import config from '../../config.js';
import logger, { appendToFile } from '../utils/logger.js';

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

  try {
    await exec('sudo', ['fail2ban-client', 'set', 'sshd', 'banip', ip]);
    results.push('fail2ban: banned');
    logger.info(`fail2ban ban applied: ${ip}`);
  } catch (err) {
    results.push(`fail2ban: ${err.message}`);
  }

  const cmd = ip.includes(':') ? 'ip6tables' : 'iptables';
  try {
    await exec('sudo', [cmd, '-w', '-C', 'INPUT', '-s', ip, '-j', 'DROP']);
    results.push(`${cmd}: DROP rule already exists`);
    logger.info(`${cmd} DROP rule already exists: ${ip}`);
  } catch {
    try {
      await exec('sudo', [cmd, '-w', '-I', 'INPUT', '-s', ip, '-j', 'DROP']);
      results.push(`${cmd}: DROP rule added`);
      logger.info(`${cmd} DROP rule added: ${ip}`);
    } catch (err) {
      results.push(`${cmd}: ${err.message}`);
    }
  }

  return results;
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
