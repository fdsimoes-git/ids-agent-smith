import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import config from '../../config.js';
import logger from '../utils/logger.js';

class HoneypotStats {
  constructor() {
    this.connections = [];
    this.dirty = false;
    this.saveTimer = null;
    this.isSaving = false;
  }

  async load() {
    try {
      const raw = await readFile(config.honeypot.dataPath, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data.connections)) {
        this.connections = data.connections;
        this.trimOld();
        logger.info(`Honeypot stats loaded: ${this.connections.length} records`);
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        logger.warn('Failed to load honeypot stats', { error: err.message });
      }
    }
  }

  startAutoSave() {
    if (this.saveTimer) clearInterval(this.saveTimer);
    this.saveTimer = setInterval(() => {
      if (this.dirty && !this.isSaving) this.save();
    }, 60_000);
  }

  record(event) {
    this.connections.push({
      ip: event.ip,
      port: event.port,
      timestamp: event.timestamp,
      payload: event.payload || '',
    });
    this.dirty = true;
    this.trimOld();
  }

  trimOld() {
    const cutoff = Date.now() - config.honeypot.retentionDays * 86400_000;
    this.connections = this.connections.filter(c => new Date(c.timestamp).getTime() > cutoff);
  }

  getAll() {
    return this.connections;
  }

  getSummary() {
    const now = Date.now();
    const last24h = now - 86400_000;
    const recent = this.connections.filter(c => new Date(c.timestamp).getTime() > last24h);

    const byIp = {};
    const byPort = {};
    const byHour = {};

    for (const conn of this.connections) {
      byIp[conn.ip] = (byIp[conn.ip] || 0) + 1;
      byPort[conn.port] = (byPort[conn.port] || 0) + 1;
    }

    for (const conn of recent) {
      const hour = new Date(conn.timestamp).getHours();
      const key = String(hour).padStart(2, '0') + ':00';
      byHour[key] = (byHour[key] || 0) + 1;
    }

    const topIps = Object.entries(byIp)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));

    const topPorts = Object.entries(byPort)
      .sort((a, b) => b[1] - a[1])
      .map(([port, count]) => ({ port: Number(port), count }));

    const hourly = Object.entries(byHour)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([hour, count]) => ({ hour, count }));

    const recentPayloads = this.connections
      .filter(c => c.payload)
      .slice(-10)
      .reverse()
      .map(c => ({ ip: c.ip, port: c.port, timestamp: c.timestamp, payload: c.payload }));

    return {
      totalConnections: this.connections.length,
      connectionsLast24h: recent.length,
      uniqueIps: Object.keys(byIp).length,
      topIps,
      topPorts,
      hourlyLast24h: hourly,
      recentPayloads,
    };
  }

  async save() {
    if (this.isSaving) return;
    this.isSaving = true;
    try {
      const dir = dirname(config.honeypot.dataPath);
      await mkdir(dir, { recursive: true }).catch(() => {});
      await writeFile(
        config.honeypot.dataPath,
        JSON.stringify({ connections: this.connections }, null, 2),
        'utf8'
      );
      this.dirty = false;
    } catch (err) {
      logger.error('Failed to save honeypot stats', { error: err.message });
    } finally {
      this.isSaving = false;
    }
  }

  async stop() {
    if (this.saveTimer) clearInterval(this.saveTimer);
    if (this.dirty) await this.save();
  }
}

export default new HoneypotStats();
