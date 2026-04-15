import { createServer } from 'node:net';
import config from '../../config.js';
import logger from '../utils/logger.js';
import { sanitizeIp } from '../utils/sanitize.js';
import honeypotStats from './stats.js';

const servers = [];

export async function startHoneypot(onThreat) {
  if (!config.honeypot.enabled) return;

  await honeypotStats.load();
  honeypotStats.startAutoSave();

  for (const port of config.honeypot.ports) {
    try {
      const server = createDecoyServer(port, onThreat);
      servers.push(server);
    } catch (err) {
      logger.error(`Honeypot: failed to start on port ${port}`, { error: err.message });
    }
  }

  logger.info(`Honeypot started on ports: ${config.honeypot.ports.join(', ')}`);
}

function createDecoyServer(port, onThreat) {
  const server = createServer(socket => {
    const remoteIp = sanitizeIp(socket.remoteAddress?.replace('::ffff:', ''));
    if (!remoteIp) {
      socket.destroy();
      return;
    }

    const timestamp = new Date().toISOString();
    let payload = '';

    socket.setTimeout(10_000);
    socket.on('timeout', () => socket.destroy());

    socket.on('data', chunk => {
      if (payload.length < config.honeypot.maxPayloadBytes) {
        payload += chunk.toString('utf8', 0, config.honeypot.maxPayloadBytes - payload.length);
      }
    });

    socket.on('end', () => finalize());
    socket.on('close', () => finalize());
    socket.on('error', () => socket.destroy());

    let finalized = false;
    function finalize() {
      if (finalized) return;
      finalized = true;

      // Strip control chars from payload for safe logging
      const safePayload = payload.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, config.honeypot.maxPayloadBytes);

      honeypotStats.record({
        ip: remoteIp,
        port,
        timestamp,
        payload: safePayload,
      });

      logger.info(`Honeypot hit: ${remoteIp} -> port ${port}`, {
        payload: safePayload.slice(0, 100),
      });

      if (onThreat) {
        onThreat({
          rule: 'honeypot',
          severity: 'HIGH',
          ip: remoteIp,
          endpoint: `TCP:${port}`,
          timestamp,
          details: `Connection to honeypot port ${port}` + (safePayload ? ` — payload: ${safePayload.slice(0, 80)}` : ''),
          suggestedAction: 'block',
          source: 'honeypot',
        });
      }
    }
  });

  server.on('error', err => {
    if (err.code === 'EADDRINUSE') {
      logger.error(`Honeypot: port ${port} already in use — skipping`);
    } else if (err.code === 'EACCES') {
      logger.error(`Honeypot: no permission to bind port ${port} — use a port > 1024 or run with CAP_NET_BIND_SERVICE`);
    } else {
      logger.error(`Honeypot server error on port ${port}`, { error: err.message });
    }
  });

  server.listen(port, '0.0.0.0', () => {
    logger.info(`Honeypot listening on port ${port}`);
  });

  return server;
}

export async function stopHoneypot() {
  const closePromises = servers.map(s => new Promise(resolve => {
    s.close(resolve);
  }));
  await Promise.all(closePromises);
  await honeypotStats.stop();
  servers.length = 0;
  logger.info('Honeypot stopped');
}

export { honeypotStats };
