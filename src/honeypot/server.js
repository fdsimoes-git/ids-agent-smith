import { createServer } from 'node:net';
import config from '../../config.js';
import logger from '../utils/logger.js';
import { sanitizeIp } from '../utils/sanitize.js';
import honeypotStats from './stats.js';

const servers = [];

export async function startHoneypot(onThreat) {
  if (!config.honeypot.enabled) return;

  await honeypotStats.load();

  const startedPorts = [];

  for (const port of config.honeypot.ports) {
    try {
      const server = await createDecoyServer(port, onThreat);
      servers.push(server);
      startedPorts.push(port);
    } catch (err) {
      logger.error(`Honeypot: failed to start on port ${port}`, { error: err.message });
    }
  }

  if (startedPorts.length > 0) {
    honeypotStats.startAutoSave();
    logger.info(`Honeypot started on ports: ${startedPorts.join(', ')}`);
  } else {
    logger.warn('Honeypot: no ports could be started');
  }

  return startedPorts;
}

function createDecoyServer(port, onThreat) {
  return new Promise((resolve, reject) => {
    let bound = false;

    const server = createServer(socket => {
      const remoteIp = sanitizeIp(socket.remoteAddress?.replace('::ffff:', ''));
      if (!remoteIp) {
        socket.destroy();
        return;
      }

      const timestamp = new Date().toISOString();
      const payloadBuffers = [];
      let payloadBytes = 0;

      socket.setTimeout(10_000);
      socket.on('timeout', () => socket.destroy());

      socket.on('data', chunk => {
        if (payloadBytes < config.honeypot.maxPayloadBytes) {
          const remaining = config.honeypot.maxPayloadBytes - payloadBytes;
          const slice = remaining < chunk.length ? chunk.subarray(0, remaining) : chunk;
          payloadBuffers.push(slice);
          payloadBytes += slice.length;
        }
      });

      socket.on('end', () => finalize());
      socket.on('close', () => finalize());
      socket.on('error', () => socket.destroy());

      let finalized = false;
      function finalize() {
        if (finalized) return;
        finalized = true;

        const rawPayload = payloadBuffers.length > 0 ? Buffer.concat(payloadBuffers).toString('utf8') : '';
        const safePayload = rawPayload.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');

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
      if (!bound) {
        if (err.code === 'EADDRINUSE') {
          reject(new Error(`port ${port} already in use`));
        } else if (err.code === 'EACCES') {
          reject(new Error(`no permission to bind port ${port} — use a port > 1024 or run with CAP_NET_BIND_SERVICE`));
        } else {
          reject(err);
        }
      } else {
        logger.error(`Honeypot runtime error on port ${port}`, { error: err.message });
        server.close();
      }
    });

    server.listen(port, '0.0.0.0', () => {
      bound = true;
      logger.info(`Honeypot listening on port ${port}`);
      resolve(server);
    });
  });
}

export async function stopHoneypot() {
  const closePromises = servers.map(s => new Promise(resolve => {
    if (s.listening) {
      s.close(resolve);
    } else {
      resolve();
    }
  }));
  await Promise.all(closePromises);
  await honeypotStats.stop();
  servers.length = 0;
  logger.info('Honeypot stopped');
}

export { honeypotStats };
